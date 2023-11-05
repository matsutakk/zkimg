use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        GateInstructions,
        RangeChip,
    },
    halo2_proofs::{
        halo2curves::{bn256::{Bn256, Fr, G1Affine}, secp256k1::{Fp, Fq, Secp256k1Affine}},
        plonk::*,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    },
    Context, utils::{BigPrimeField, CurveAffineExt}, AssignedValue,
};
use halo2_ecc::{
    secp256k1::{FqChip, FpChip},
    ecc::{EccChip, scalar_multiply, fixed_base, EcPoint},
    bigint::{big_is_equal, ProperCrtUint}, fields::{FieldChip, PrimeField, fp::FpChip as FpChipField}
};
use rand::rngs::OsRng;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};
use zkimg::util::{random_schnorr_signature_input, SchnorrInput};


const K: usize = 10;

pub fn schnorr_verify_no_pubkey_check<F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    chip: &EccChip<F, FpChipField<F, CF>>,
    ctx: &mut Context<F>,
    pubkey: EcPoint<F, <FpChipField<F, CF> as FieldChip<F>>::FieldPoint>,
    r: ProperCrtUint<F>,       // int(sig[0:32]); fail if r ≥ p.
    s: ProperCrtUint<F>,       // int(sig[32:64]); fail if s ≥ n
    msg_hash: ProperCrtUint<F>, // int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n
    var_window_bits: usize,
    fixed_window_bits: usize,
) -> AssignedValue<F>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let base_chip = chip.field_chip;
    let scalar_chip =
    FpChipField::<F, SF>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);

    // check r < p
    let r_valid = base_chip.is_less_than_p(ctx, &r);
    // check 0 < s < n
    let s_valid = scalar_chip.is_soft_nonzero(ctx, &s);
    // check 0 < e < n
    let e_valid = scalar_chip.is_soft_nonzero(ctx, &msg_hash);

    // compute s * G and msgHash * pubkey
    let s_g = fixed_base::scalar_multiply(
        base_chip,
        ctx,
        &GA::generator(),
        s.limbs().to_vec(),
        base_chip.limb_bits,
        fixed_window_bits,
    );
    let e_p = scalar_multiply::<_, _, GA>(
        base_chip,
        ctx,
        pubkey,
        msg_hash.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // check s_G.x != e_P.x, which is a requirement for sub_unequal
    let x_eq = base_chip.is_equal(ctx, &s_g.x, &e_p.x);
    let x_neq = base_chip.gate().not(ctx, x_eq);

    // R = s⋅G - e⋅P
    // R is not infinity point implicitly constrainted by is_strict = true
    let R = chip.sub_unequal(ctx, s_g, e_p, true);

    // check R.y is even
    let r_y = R.y;
    let r_y_is_even: AssignedValue<F> = base_chip.is_even(ctx, &r_y);

    // check R.x == r
    let r_x = scalar_chip.enforce_less_than(ctx, R.x);
    let equal_check = big_is_equal::assign(
        base_chip.gate(),
        ctx, 
        ProperCrtUint::from(r_x),
        r
    );

    let res1 = base_chip.gate().and(ctx, r_valid, s_valid);
    let res2: AssignedValue<F> = base_chip.gate().and(ctx, res1, e_valid);
    let res3 = base_chip.gate().and(ctx, res2, x_neq);
    let res4: AssignedValue<F> = base_chip.gate().and(ctx, res3, r_y_is_even);
    let res5 = base_chip.gate().and(ctx, res4, equal_check);

    res5
}


fn schnorr<F: PrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    input: SchnorrInput
){
    std::env::set_var("LOOKUP_BITS", lookup_bits.to_string());
    let range = RangeChip::<F>::default(lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, limb_bits, num_limbs);
    let fq_chip = FqChip::<F>::new(&range, limb_bits, num_limbs);

    let [m, s] = [input.msg_hash, input.s].map(|x| fq_chip.load_private(ctx, x));
    let r = fp_chip.load_private(ctx, input.r);

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pk = ecc_chip.assign_point(ctx, input.pk);

    let res = schnorr_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );
    assert_eq!(res.value(), &F::one());
}

fn schnorr_circuit(
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = K;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    schnorr(
        builder.main(0),
        k - 1, 
        88, 
        3, 
        random_schnorr_signature_input()
    );

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    circuit
}

fn bench(c: &mut Criterion) {
    let circuit = schnorr_circuit(CircuitBuilderStage::Keygen, None);

    let params = ParamsKZG::<Bn256>::setup(K as u32, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    let break_points = circuit.0.break_points.take();

    let mut group = c.benchmark_group("schnorr");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("schnorr", K),
        &(&params, &pk),
        |bencher, &(params, pk)| {
            bencher.iter(|| {
                let circuit =
                    schnorr_circuit(CircuitBuilderStage::Prover, Some(break_points.clone()));

                let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<'_, Bn256>,
                    Challenge255<G1Affine>,
                    _,
                    Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
                    _,
                >(params, pk, &[circuit], &[&[]], OsRng, &mut transcript)
                .expect("prover should not fail");
            })
        },
    );
    group.finish()
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench
}
criterion_main!(benches);