#[macro_use]
extern crate uint;

#[macro_use]
extern crate impl_serde;

pub mod verifier;


use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::Map;
use near_sdk::{env, near_bindgen};

use verifier::{VK, VKData, Proof, ProofData, Input, InputData, groth16_verifier_prepare_pairing, U256};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[near_bindgen]
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct Groth16Verifier {
    pub n_calls:u64,
    pub res_calls: Map<u64,bool>
}

#[near_bindgen]
impl Groth16Verifier {
    pub fn n_calls(&self) -> u64 {
        self.n_calls
    }

    pub fn get_call(&self, n:u64) -> Option<bool> {
        self.res_calls.get(&n)
    }

    pub fn groth16verify(&self, vk: VKData, proof:ProofData, input:InputData) -> Option<bool> {
        let vk = Into::<Option<VK>>::into(vk)?;
        let proof = Into::<Option<Proof>>::into(proof)?;
        let input = Into::<Option<Input>>::into(input)?;
        let data = groth16_verifier_prepare_pairing(&vk, &proof, &input)?;
        Some(env::alt_bn128_pairing_check(&data))
    }

    pub fn groth16verify_log(&mut self, vk: VKData, proof:ProofData, input:InputData) -> Option<()> {
        let vk = Into::<Option<VK>>::into(vk)?;
        let proof = Into::<Option<Proof>>::into(proof)?;
        let input = Into::<Option<Input>>::into(input)?;
        let data = groth16_verifier_prepare_pairing(&vk, &proof, &input)?;

        self.res_calls.insert(&self.n_calls, &env::alt_bn128_pairing_check(&data));
        self.n_calls+=1;
        Some(())
    }

    pub fn hello_num(&self, n: U256) -> Option<U256> {
        let (c, _) = n.overflowing_mul(n);
        Some(c)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};

    fn get_context(input: Vec<u8>, is_view: bool) -> VMContext {
        VMContext {
            current_account_id: "alice_near".to_string(),
            signer_account_id: "bob_near".to_string(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id: "carol_near".to_string(),
            input,
            block_index: 0,
            block_timestamp: 0,
            account_balance: 0,
            account_locked_balance: 0,
            storage_usage: 0,
            attached_deposit: 0,
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view,
            output_data_receivers: vec![],
            epoch_height: 0,
        }
    }

}
