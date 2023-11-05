
use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
};
use halo2_base::utils::fe_to_biguint;
use num_bigint::BigUint;
use rand::{rngs::StdRng, SeedableRng};
use rand::Rng;
use num_integer::Integer;
use halo2_base::halo2_proofs::arithmetic::Field;
type Image = Vec<u64>; 

#[derive(Clone, Copy, Debug)]
pub struct SchnorrInput {
    pub r: Fp,
    pub s: Fq,
    pub msg_hash: Fq,
    pub pk: Secp256k1Affine,
}

pub fn random_schnorr_signature_input() -> SchnorrInput {
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(StdRng::from_seed([0u8; 32]));
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash =
        <Secp256k1Affine as CurveAffine>::ScalarExt::random(StdRng::from_seed([0u8; 32]));

    let mut k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(StdRng::from_seed([0u8; 32]));

    let mut r_point =
        Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let mut x: &Fp = r_point.x();
    let mut y: &Fp = r_point.y();
    // make sure R.y is even
    while fe_to_biguint(y).mod_floor(&BigUint::from(2u64)) != BigUint::from(0u64) {
        k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(StdRng::from_seed([0u8; 32]));
        r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
        x = r_point.x();
        y = r_point.y();
    }

    let r = *x;
    let s = k + sk * msg_hash;

    SchnorrInput{ r, s, msg_hash, pk }
}


// ランダムなRGB画像を生成
pub fn generate_image(width: usize, height: usize) -> Image {
    let mut rng = rand::thread_rng();
    let mut image = vec![0; width * height * 3];
    for i in 0..(width * height * 3) {
        image[i] = rng.gen_range(0..=255);
    }
    image
}

// クロップ関数
pub fn crop_image(image: &Image, width: usize, x: usize, y: usize, crop_width: usize, crop_height: usize) -> Image {
    let mut cropped_image = vec![0; crop_width * crop_height * 3];

    for new_y in 0..crop_height {
        for new_x in 0..crop_width {
            let old_x = x + new_x;
            let old_y = y + new_y;

            let old_index = (old_y * width + old_x) * 3;
            let new_index = (new_y * crop_width + new_x) * 3;

            cropped_image[new_index..new_index + 3].copy_from_slice(&image[old_index..old_index + 3]);
        }
    }

    cropped_image
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_image() {
        let width = 10;
        let height = 10;
        let image = generate_image(width, height);

        // 画像のサイズが正しいか確認（width * height * 3 ）
        assert_eq!(image.len(), width * height * 3);
    }

    #[test]
    fn test_crop_image() {
        let width = 10;
        let height = 10;
        let image = generate_image(width, height);

        let crop_x = 2;
        let crop_y = 2;
        let crop_width = 5;
        let crop_height = 5;
        let cropped_image = crop_image(&image, width, crop_x, crop_y, crop_width, crop_height);

        // クロップされた画像のサイズが正しいか確認（crop_width * crop_height * 3）
        assert_eq!(cropped_image.len(), crop_width * crop_height * 3);

        // クロップされた画像が元の画像と一致しているか確認
        for y in 0..crop_height {
            for x in 0..crop_width {
                for rgb in 0..3 {
                    let old_x = crop_x + x;
                    let old_y = crop_y + y;

                    let old_index = (old_y * width + old_x) * 3;
                    let new_index = (y * crop_width + x) * 3;
    
                    let old_pixel = &image[old_index + rgb];
                    let new_pixel = &cropped_image[new_index + rgb];
    
                    assert_eq!(old_pixel, new_pixel);
                }
            }
        }
    }
}
