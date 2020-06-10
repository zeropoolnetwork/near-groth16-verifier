use bn::{AffineG1, AffineG2, Fq, Fq2, Fr, G1};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

construct_uint! {
    /// 256-bit unsigned integer.
    #[derive(BorshSerialize,BorshDeserialize)]
    pub struct U256(4);
}

impl_uint_serde!(U256, 4);

pub trait Vectorize {
    fn vectorize(&self, data: &mut [u8]) -> Option<()>;
}

impl Vectorize for Fq {
    fn vectorize(&self, data: &mut [u8]) -> Option<()> {
        self.to_big_endian(data).ok()
    }
}

impl Vectorize for Fq2 {
    fn vectorize(&self, data: &mut [u8]) -> Option<()> {
        if data.len() != 64 {
            None
        } else {
            self.imaginary().vectorize(&mut data[0..32])?;
            self.real().vectorize(&mut data[32..64])
        }
    }
}

impl Vectorize for AffineG1 {
    fn vectorize(&self, data: &mut [u8]) -> Option<()> {
        if data.len() != 64 {
            None
        } else {
            self.x().vectorize(&mut data[0..32])?;
            self.y().vectorize(&mut data[32..64])
        }
    }
}

impl Vectorize for AffineG2 {
    fn vectorize(&self, data: &mut [u8]) -> Option<()> {
        if data.len() != 128 {
            None
        } else {
            self.x().vectorize(&mut data[0..64])?;
            self.y().vectorize(&mut data[64..128])
        }
    }
}

impl Vectorize for (AffineG1, AffineG2) {
    fn vectorize(&self, data: &mut [u8]) -> Option<()> {
        if data.len() != 192 {
            None
        } else {
            self.0.vectorize(&mut data[0..64])?;
            self.1.vectorize(&mut data[64..192])
        }
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct G1PointData(pub U256, pub U256);

#[derive(
    Clone, Copy, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct G2PointData(pub (U256, U256), pub (U256, U256));

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct VKData {
    pub alpha_g1: G1PointData,
    pub beta_g2: G2PointData,
    pub gamma_g2: G2PointData,
    pub delta_g2: G2PointData,
    pub ic: Vec<G1PointData>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ProofData {
    pub a: G1PointData,
    pub b: G2PointData,
    pub c: G1PointData,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct InputData(pub Vec<U256>);

#[derive(Clone)]
pub struct VK {
    pub alpha_g1: AffineG1,
    pub beta_g2: AffineG2,
    pub gamma_g2: AffineG2,
    pub delta_g2: AffineG2,
    pub ic: Vec<AffineG1>,
}

#[derive(Clone)]
pub struct Proof {
    pub a: AffineG1,
    pub b: AffineG2,
    pub c: AffineG1,
}

pub struct Input(pub Vec<Fr>);

impl Into<Option<Fq>> for U256 {
    fn into(self) -> Option<Fq> {
        let mut buff = [0u8; 32];
        self.to_big_endian(&mut buff[..]);
        Fq::from_slice(&buff[..]).ok()
    }
}

impl Into<Option<Fr>> for U256 {
    fn into(self) -> Option<Fr> {
        let mut buff = [0u8; 32];
        self.to_big_endian(&mut buff[..]);
        Fr::from_slice(&buff[..]).ok()
    }
}

impl Into<Option<AffineG1>> for G1PointData {
    fn into(self) -> Option<AffineG1> {
        let x = Into::<Option<Fq>>::into(self.0)?;
        let y = Into::<Option<Fq>>::into(self.1)?;
        AffineG1::new(x, y).ok()
    }
}

impl Into<Option<AffineG2>> for G2PointData {
    fn into(self) -> Option<AffineG2> {
        let x_i = Into::<Option<Fq>>::into(self.0 .0)?;
        let x_r = Into::<Option<Fq>>::into(self.0 .1)?;
        let y_i = Into::<Option<Fq>>::into(self.1 .0)?;
        let y_r = Into::<Option<Fq>>::into(self.1 .1)?;

        let x = Fq2::new(x_r, x_i);
        let y = Fq2::new(y_r, y_i);

        AffineG2::new(x, y).ok()
    }
}

impl Into<Option<VK>> for VKData {
    fn into(self) -> Option<VK> {
        Some(VK {
            alpha_g1: Into::<Option<AffineG1>>::into(self.alpha_g1)?,
            beta_g2: Into::<Option<AffineG2>>::into(self.beta_g2)?,
            gamma_g2: Into::<Option<AffineG2>>::into(self.gamma_g2)?,
            delta_g2: Into::<Option<AffineG2>>::into(self.delta_g2)?,
            ic: self
                .ic
                .iter()
                .map(|&c| Into::<Option<AffineG1>>::into(c))
                .collect::<Option<Vec<_>>>()?,
        })
    }
}

impl Into<Option<Proof>> for ProofData {
    fn into(self) -> Option<Proof> {
        Some(Proof {
            a: Into::<Option<AffineG1>>::into(self.a)?,
            b: Into::<Option<AffineG2>>::into(self.b)?,
            c: Into::<Option<AffineG1>>::into(self.c)?,
        })
    }
}

impl Into<Option<Input>> for InputData {
    fn into(self) -> Option<Input> {
        Some(Input(
            self.0
                .iter()
                .map(|&c| Into::<Option<Fr>>::into(c))
                .collect::<Option<Vec<_>>>()?,
        ))
    }
}

pub fn groth16_verifier_prepare_pairing(vk: &VK, proof: &Proof, input: &Input) -> Option<Vec<u8>> {
    let len = input.0.len();
    if vk.ic.len() != len + 1 {
        None
    } else {
        let mut res = vec![0u8; 192*4];
        let mut acc = G1::from(vk.ic[0]);

        for i in 0..len {
            acc = acc + G1::from(vk.ic[i + 1]) * input.0[i];
        }
        let acc = AffineG1::from_jacobian(acc)?;

        let mut neg_a = proof.a.clone();
        neg_a.set_y(-neg_a.y());

        let pairs = [
            (neg_a, proof.b),
            (vk.alpha_g1, vk.beta_g2),
            (acc, vk.gamma_g2),
            (proof.c, vk.delta_g2),
        ];
        for i in 0..4 {
            pairs[i].vectorize(&mut res[192 * i..192 * (i + 1)])?;
        }

        Some(res)
    }
}
