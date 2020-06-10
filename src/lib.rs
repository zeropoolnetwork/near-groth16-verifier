#[macro_use]
extern crate uint;

#[macro_use]
extern crate impl_serde;

pub mod verifier;


use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::Map;
use near_sdk::{env, near_bindgen};

use verifier::{VK, VKData, Proof, ProofData, Input, InputData, groth16_verifier_prepare_pairing, G2PointData, G1PointData};
use bn::{AffineG2, AffineG1};

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

    
    pub fn profiling(&self, g2: G2PointData) -> Option<String> {
        let _g2 = Into::<Option<AffineG2>>::into(g2)?;

        Some(env::used_gas().to_string())
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
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};
    use serde::{Serialize, Deserialize};
    use serde_json;

    #[derive(Clone, Serialize, Deserialize)]
    struct Params{
        vk:VKData,
        proof:ProofData,
        input:InputData
    }

    #[test]
    fn test_verifier() {
        let data = r#"{"vk":{"alpha_g1":["0x109fc3a44c82a7ae6cd9136de2a0c18fd188ac9158b44d6395f8442b2044eec8","0x11279c772e615f5402dcec672894bdd124a58bec5ab1105bad709d077c3052fc"],"beta_g2":[["0x299f5c3e0de86260717c1dc3f129e4d8040103891db8f35540772cb1afb01b4","0x1bfc7727d222a387d8436424e2f03c3181566640e7a7b3e17bf479acf07bf33f"],["0xb472844c000623267ae2c34b903d882c47c031d6c48841af11f6a38714f4353","0x2fd5f1e41fc9ad8de06beb77274794e64e5f8b50c4954c9105eba5e44277882c"]],"gamma_g2":[["0x15249ce5197f7a80446b4ce9a195b9744c49802830560d3eca7f134ca6282afa","0x29273f97c48d458ae31f4d480a5e50a9203d631c3b275d44ae4f4ed2bbb3266e"],["0x1be77c0192c054a7bc2abd0c24ccd29f3c50e4658bec2052317d20cbe6f7c79c","0x26100229669fdc3b14ab1d4e20ce626ae1fb9dcaa1e47942ca6689e28adca3ce"]],"delta_g2":[["0x2b9c787bbebeffc39cb566638cc45411348948300380f319ca1a05c4589d4003","0x271d2eed01cc2012c1efb0a077c448b3e2f77aa1553df295c0ab49d11d5cd5fe"],["0x2cbe9fb495c5a83846f50bd71a641f4ba701727861183506d1c9c676401f9bdc","0x22bbde161cff65c301e5759bafb72434bdf7842ab5eb373c7c5043836ed58b39"]],"ic":[["0x8c3cf74aeeedf0b9ef61469ce5cbd202dfa4d4c9f31cf0866c2dc2845d50759","0x4957ca2e9bf96f5f4703b54e2373fc4ad24cb60f88815027f03041ea3b10602"],["0x9498c6a96b89097973183776f65e5c3b05f3ac5868b0a76f091f0ad6b54a442","0x1226c97d660963fc373212a87e81022acac4783ad00e7ff4334f031c489062c0"],["0x18c2a570e7f8b365ebe97dff01cdcffd3daa7ffa69f2ea07f648b1309611ec46","0x774dbfe166fd7fdb3324601a9f67158446a8844e5f83bf2590b06d6aca92c2d"],["0x1757dee1177c1309e5dc66ac0b1ed7fa486d765264dbc43aebffb4a9c2983eb2","0x21e002cde53d514cad62d47aac2ccfd8ff775c058758b75ca124ee357a11f59c"]]},"proof":{"a":["0x2e85efde8f500e566fe81ae54b48ddeb0611c7c2726621b5f98e74c7835aec41","0x192f7068683a214f76e41eaf6203265899f527b29fb9e225ff23b8e934ab1555"],"b":[["0x20898b6b22abb68dd5d8b20297bd0b6bbb372ebd436815ffc3dcd3b238fc8b5f","0x1921fd7c5adcb752cd24107a656c2e6e4de41f8e507736f3674bc9651a3c03c9"],["0x12e5897fa24be66c517a1959456cb1a1cc6392e6a773369f743c37701883ce7b","0x50f1587cf9fc9b31388cf9d180041a729edc444d2f731efee06d898d46e2134"]],"c":["0x1e748abcca90c9ea1dfef918ba55d89b4696d543be7e712ace82bd0a8f53aed6","0x139046c1ed0de8c7587dbba8ac12719e9582374352b4fd803e8635fe3c918b47"]},"input":["0xdf4af626a55104b72a2c1fcdad4ae335b0acb0ac4287b5bca39f414de0835c2","0x2a57943972237848ed10a1bbd2ada7a5bbfa63bc0725d4eb68c274dedc69f85b","0x257f2c14f616c5223aa50b07f471407ba56799dda3dc664f561ca8d3400b35fc"]}"#;
        let p : Params = serde_json::from_str(data).unwrap();

        let vk = Into::<Option<VK>>::into(p.vk).unwrap();
        let proof = Into::<Option<Proof>>::into(p.proof).unwrap();
        let input = Into::<Option<Input>>::into(p.input).unwrap();
        let pairing_data = groth16_verifier_prepare_pairing(&vk, &proof, &input).unwrap();
        let context = get_context(vec![], true);
        testing_env!(context);
        assert!(env::alt_bn128_pairing_check(&pairing_data), "result should be true")
    }


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
