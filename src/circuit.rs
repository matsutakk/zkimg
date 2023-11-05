#![allow(unused_imports)]
use std::env::{var, set_var};

use halo2_base::{
    gates::{builder::{
        CircuitBuilderStage, RangeCircuitBuilder, GateThreadBuilder, RangeWithInstanceCircuitBuilder, 
    }, GateChip, GateInstructions},
    halo2_proofs::{
        dev::MockProver,
        arithmetic::Field,
        halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
        halo2curves::secp256k1::{Fp, Secp256k1Affine},
        plonk::*,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    },
    utils::{fs::gen_srs, ScalarField, BigPrimeField},
    QuantumCell::{Constant, Existing, Witness},
    Context, AssignedValue,
};

use halo2_ecc::secp256k1::{FpChip, FqChip};

#[derive(Clone, Copy, Debug)]
pub struct SchnorrInput {
    pub r: Fp,
    pub s: Fq,
    pub msg_hash: Fq,
    pub pk: Secp256k1Affine,
}

// pub fn schnorr_verify_no_pubkey_check<F: BigPrimeField, CF: BigPrimeField, SF: BigPrimeField, GA>(
//     ctx: &mut Context<F>,
// ) {
//     let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
//     let fq_chip = FqChip::<F>::new(range, params.limb_bits, params.num_limbs);

//     let [m, s] = [input.msg_hash, input.s].map(|x| fq_chip.load_private(ctx, x));
//     let r = fp_chip.load_private(ctx, input.r);

//     let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
//     let pk = ecc_chip.assign_point(ctx, input.pk);

//     let base_chip = chip.field_chip;
//     let scalar_chip =
//         FpChip::<F, SF>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);

//     // check r < p
//     let r_valid = base_chip.is_less_than_p(ctx, &r);
//     // check 0 < s < n
//     let s_valid = scalar_chip.is_soft_nonzero(ctx, &s);
//     // check 0 < e < n
//     let e_valid = scalar_chip.is_soft_nonzero(ctx, &msgHash);

//     // compute s * G and msgHash * pubkey
//     let s_G = fixed_base::scalar_multiply(
//         base_chip,
//         ctx,
//         &GA::generator(),
//         s.limbs().to_vec(),
//         base_chip.limb_bits,
//         fixed_window_bits,
//     );

//     let e_P = scalar_multiply::<_, _, GA>(
//         base_chip,
//         ctx,
//         pubkey,
//         msgHash.limbs().to_vec(),
//         base_chip.limb_bits,
//         var_window_bits,
//     );

//     // check s_G.x != e_P.x, which is a requirement for sub_unequal
//     let x_eq = base_chip.is_equal(ctx, &s_G.x, &e_P.x);
//     let x_neq = base_chip.gate().not(ctx, x_eq);

//     // R = s⋅G - e⋅P
//     // R is not infinity point implicitly constrainted by is_strict = true
//     let R = chip.sub_unequal(ctx, s_G, e_P, true);

//     // check R.y is even
//     let R_y = R.y;
//     let R_y_is_even: AssignedValue<F> = base_chip.is_even(ctx, &R_y);

//     // check R.x == r
//     let R_x = scalar_chip.enforce_less_than(ctx, R.x);
//     let equal_check = big_is_equal::assign(base_chip.gate(), ctx, R_x.0, r);

//     let res1 = base_chip.gate().and(ctx, r_valid, s_valid);
//     let res2: AssignedValue<F> = base_chip.gate().and(ctx, res1, e_valid);
//     let res3 = base_chip.gate().and(ctx, res2, x_neq);
//     let res4: AssignedValue<F> = base_chip.gate().and(ctx, res3, R_y_is_even);
//     let res5 = base_chip.gate().and(ctx, res4, equal_check);
//     res5
// }

fn crop<F: ScalarField>(
    ctx: &mut Context<F>,
    x: F,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let gate = GateChip::<F>::default();
    let x = ctx.load_witness(x);    
    let x_sq = gate.mul(ctx, x, x);
    let c = F::from(72);
    let out = gate.add(ctx, x_sq, Constant(c));
    // gate.assert_is_const(ctx, &out, &F::from(1));
    println!("x: {:?}", x.value());
    println!("val_assigned: {:?}", out.value());
    assert_eq!(*x.value() * x.value() + c, *out.value());
}

pub fn run() {
    let k = 8;
    let stage = CircuitBuilderStage::Mock;
    let params = gen_srs(k);

    let mut builder: GateThreadBuilder<Fr> = match stage {
        CircuitBuilderStage::Prover => GateThreadBuilder::new(true),
        _ => GateThreadBuilder::new(false),
    };

    let lookup_bits: usize = var("LOOKUP_BITS")
    .map(|str| {
        let lookup_bits = str.parse().unwrap();
        lookup_bits
    })
    .unwrap_or(0);
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let mut assigned_instances = vec![];
    crop(builder.main(0), Fr::from(7), &mut assigned_instances);

    let minimum_rows = var("MINIMUM_ROWS").unwrap_or_else(|_| "9".to_string()).parse().unwrap();
    match stage {
        CircuitBuilderStage::Prover => {}
        _ => {
            builder.config(k as usize, Some(minimum_rows));
        }
    };

    let circuit = match stage {
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(
            builder,
            None.unwrap()
        ),
        CircuitBuilderStage::Keygen => RangeCircuitBuilder::keygen(builder),
        CircuitBuilderStage::Mock => {
            println!("called");
            RangeCircuitBuilder::mock(builder)
        }
    };


    let public_io: Vec<Fr> = assigned_instances.iter().map(|v| *v.value()).collect();

    println!("here3");

    let c = RangeWithInstanceCircuitBuilder::new(circuit, assigned_instances);

    println!("here4");

    match MockProver::run(k, &c, vec![public_io.clone()]) {
        Ok(result) => result.assert_satisfied(),
        Err(msg) => println!("failure: {}", msg),
    }

}