#![allow(unused_imports)]
#![allow(unused_variables)]
use halo2_base::AssignedValue;
use halo2_base::QuantumCell::{Constant, self};
use halo2_base::gates::builder::{GateCircuitBuilder, GateThreadBuilder, CircuitBuilderStage, MultiPhaseThreadBreakPoints, RangeCircuitBuilder};
use halo2_base::gates::flex_gate::{FlexGateConfig, GateChip, GateInstructions, GateStrategy};
use halo2_base::halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverSHPLONK,
    },
    transcript::{Blake2bWrite, Blake2bRead, Challenge255, TranscriptWriterBuffer, TranscriptReadBuffer},
};
use halo2_base::utils::ScalarField;
use halo2_base::{
    Context,
    QuantumCell::{Existing, Witness},
    SKIP_FIRST_PASS,
};
use itertools::Itertools;
use rand::rngs::OsRng;
use rand::Rng;
use zkimg::util::{generate_image, crop_image};
use std::marker::PhantomData;
use std::mem::size_of;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};
use get_size::GetSize;
// use pprof::criterion::{Output, PProfProfiler};
// https://www.jibbow.com/posts/criterion-flamegraphs/


const WIDTH: usize = 1280;
const HEIGHT: usize = 720;
const CROPWIDTH: usize = 720;
const CROPHEIGHT: usize = 480;
const STARTX: usize = 0;
const STARTY: usize = 0;


fn crop<F: ScalarField>(
    ctx: &mut Context<F>, 
    original_image: Vec<F>, 
    cropped_image: Vec<F>,
    crop_startx: usize,
    crop_starty: usize,
    crop_width: usize,
    crop_height: usize,
) {
    let original_witness = ctx.assign_witnesses(original_image);
    // let cropped_witness = ctx.assign_witnesses(cropped_image);

    let chip = GateChip::default();
    
    // let mut constraints = vec![];
    // let mut is_eq = ctx.load(F::one());
    for new_y in 0..crop_height {
        for new_x in 0..crop_width {
            for rgb in 0..3 {
                let old_x = crop_startx + new_x;
                let old_y = crop_starty + new_y;
    
                let old_index = (old_y * WIDTH + old_x) * 3;
                let new_index = (new_y * crop_width + new_x) * 3;

                // let c = chip.is_equal(
                //     ctx,
                //     QuantumCell::Existing(original_witness[old_index+rgb]),
                //     QuantumCell::Constant(cropped_image[new_index+rgb]),
                // );
                
                chip.assert_is_const(
                    ctx,
                    &original_witness[old_index+rgb],
                    &cropped_image[new_index+rgb],
                );
            }
        }
    }
}

fn crop_circuit(
    k: usize,
    img: &Vec<u64>,
    cropped: &Vec<u64>,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    crop(
        builder.main(0), 
        img.iter().map(|&x| Fr::from(x)).collect(),
        cropped.iter().map(|&x| Fr::from(x)).collect(),
        STARTX, 
        STARTY,
        CROPWIDTH,
        CROPHEIGHT
    );

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k as usize,None);
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k as usize,None);
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    circuit
}

fn bench(c: &mut Criterion) {
    let k:u32 = 20;
    let img = generate_image(WIDTH, HEIGHT);
    let cropped = crop_image(&img, WIDTH, STARTX, STARTY, CROPWIDTH, CROPHEIGHT);
    let circuit = crop_circuit(k as usize, &img, &cropped, CircuitBuilderStage::Keygen, None);
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    let break_points = circuit.0.break_points.take();
    println!("{:?}",break_points);
    drop(circuit);

    let mut builder = GateThreadBuilder::new(true);
    crop(
        builder.main(0), 
        img.iter().map(|&x| Fr::from(x)).collect(),
        cropped.iter().map(|&x| Fr::from(x)).collect(),
        STARTX, 
        STARTY,
        CROPWIDTH,
        CROPHEIGHT
    );
    let circuit = RangeCircuitBuilder::prover(builder, break_points.clone());

    let mut transcript: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>> = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
        _,
    >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
    .expect("prover should not fail");

    let proof = transcript.finalize();
    println!("{:?}",proof.len());


    let mut keygen_group = c.benchmark_group("zkimg");
    keygen_group.sample_size(10);
    keygen_group.bench_with_input(
        BenchmarkId::new("crop-keygen", k),
        &(&k, &img, &cropped),
        |bencher, &(k, img, cropped)| {
            bencher.iter(|| {
                let circuit = crop_circuit(*k as usize, &img, &cropped, CircuitBuilderStage::Keygen, None);
                let params = ParamsKZG::<Bn256>::setup(*k, OsRng);
                let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit).expect("vk should not fail");
                let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
            })
        },
    );
    keygen_group.finish();

    let mut group = c.benchmark_group("zkimg");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("crop-proof", k),
        &(&params, &pk, &img, &cropped),
        |bencher, &(params, pk, img, cropped)| {
            bencher.iter(|| {
                let mut builder = GateThreadBuilder::new(true);
                crop(
                    builder.main(0), 
                    img.iter().map(|&x| Fr::from(x)).collect(),
                    cropped.iter().map(|&x| Fr::from(x)).collect(),
                    STARTX, 
                    STARTY,
                    CROPWIDTH,
                    CROPHEIGHT
                );
                let circuit = RangeCircuitBuilder::prover(builder, break_points.clone());

                let mut transcript: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>> = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<'_, Bn256>,
                    Challenge255<G1Affine>,
                    _,
                    Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
                    _,
                >(params, pk, &[circuit], &[&[]], OsRng, &mut transcript)
                .expect("prover should not fail");
                let proof = transcript.finalize();
            })
        },
    );
    group.bench_with_input(
        BenchmarkId::new("crop-verify", k),
        &(&params, &pk, &proof),
        |bencher, &(params, pk, proof)| {
            bencher.iter(|| {
                let mut transcripts: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
                let strategy = SingleStrategy::new(params);
                let res = verify_proof::<
                    KZGCommitmentScheme<Bn256>,
                    VerifierSHPLONK<'_, Bn256>,
                    Challenge255<G1Affine>,
                    Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
                    SingleStrategy<'_, Bn256>,
                >(params, &pk.get_vk(), strategy, &[&[]], &mut transcripts);
                if res.is_err() {
                    println!("{:?}",res);
                }
            })
        },
    );
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench
}
criterion_main!(benches);
