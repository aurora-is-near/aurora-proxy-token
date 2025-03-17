use near_contract_standards::fungible_token::metadata::FungibleTokenMetadata;
use near_plugins::{
    AccessControlRole, AccessControllable, Pausable, Upgradable, access_control, pause,
};
use near_sdk::borsh::BorshDeserialize;
use near_sdk::serde_json::json;
use near_sdk::store::IterableMap;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, Promise, env, ext_contract, log, near, require,
};

const PROXY_TOKEN_WASM: &[u8] = include_bytes!("../../res/aurora_proxy_token.wasm");
const MIN_DEPLOY_DEPOSIT: NearToken = NearToken::from_near(3);
const REGISTER_TOKEN_GAS: Gas = Gas::from_tgas(5);
const FINISH_DEPLOY_GAS: Gas = Gas::from_tgas(120);
const PROXY_TOKEN_GAS: Gas = Gas::from_tgas(100);
const FT_METADATA_GAS: Gas = Gas::from_tgas(5);

#[derive(AccessControlRole, Clone, Copy)]
#[near(serializers = [json])]
enum Role {
    Dao,
    Deployer,
    PauseManager,
    UnpauseManager,
}

#[derive(PanicOnDefault, Pausable, Upgradable)]
#[access_control(role_type(Role))]
#[upgradable(access_control_roles(
    code_stagers(Role::Deployer),
    code_deployers(Role::Dao),
    duration_initializers(Role::Dao),
    duration_update_stagers(Role::Dao),
    duration_update_appliers(Role::Dao),
))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
#[near(contract_state)]
pub struct AuroraProxyFactory {
    deployed_tokens: IterableMap<AccountId, AccountId>,
}

#[near]
impl AuroraProxyFactory {
    /// Initializes the contract with the given account of DAO contract.
    #[init]
    #[must_use]
    #[allow(clippy::use_self)]
    pub fn new(dao: Option<AccountId>) -> Self {
        let mut contract = Self {
            deployed_tokens: IterableMap::new(b"t".to_vec()),
        };

        require!(
            contract.acl_init_super_admin(env::current_account_id()),
            "Failed to init Super Admin role"
        );

        // Optionally grant `Role::DAO`.
        if let Some(account_id) = dao {
            let res = contract.acl_grant_role(Role::Dao.into(), account_id);
            require!(Some(true) == res, "Failed to grant DAO role");
        }

        contract
    }

    /// Deploys a proxy token contract for the given NEP-141 token.
    #[payable]
    #[pause]
    pub fn deploy_token(&mut self, token_id: AccountId) -> Promise {
        require!(
            !self.deployed_tokens.contains_key(&token_id),
            format!("Token {token_id} already deployed")
        );
        require!(
            env::attached_deposit() >= MIN_DEPLOY_DEPOSIT,
            "Not enough attached deposit to deploy proxy token"
        );

        ext_ft::ext(token_id.clone())
            .with_static_gas(FT_METADATA_GAS)
            .ft_metadata()
            .then(
                Self::ext(env::current_account_id())
                    .with_attached_deposit(env::attached_deposit())
                    .with_static_gas(FINISH_DEPLOY_GAS)
                    .finish_deploy_token(token_id),
            )
    }

    #[payable]
    #[private]
    pub fn finish_deploy_token(
        &mut self,
        #[callback_unwrap] metadata: &FungibleTokenMetadata,
        token_id: AccountId,
    ) -> Promise {
        // TODO: Should we continue if the number of decimals is 18???
        let proxy_token_id = generate_proxy_token_id(&token_id);

        Promise::new(proxy_token_id.clone())
            .create_account()
            .add_full_access_key(env::signer_account_pk())
            .transfer(env::attached_deposit())
            .deploy_contract(PROXY_TOKEN_WASM.to_vec())
            .function_call(
                "init".to_string(),
                json!({
                    "token_id": token_id,
                    "decimals": metadata.decimals
                })
                .to_string()
                .into_bytes(),
                NearToken::from_yoctonear(0),
                PROXY_TOKEN_GAS,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(REGISTER_TOKEN_GAS)
                    .register_deployed_token(token_id, proxy_token_id),
            )
    }

    #[private]
    pub fn register_deployed_token(
        &mut self,
        token_id: AccountId,
        proxy_token_id: AccountId,
    ) -> AccountId {
        let deploy_result = env::promise_result(0);

        if let near_sdk::PromiseResult::Successful(_) = deploy_result {
            log!(
                "Proxy token: {} for token: {} deployed successfully",
                &proxy_token_id,
                &token_id
            );
            self.deployed_tokens
                .insert(token_id, proxy_token_id.clone());
        }

        proxy_token_id
    }

    /// Returns the proxy token contract ID for the given NEP-141 token.
    pub fn get_proxy_token(&self, token_id: &AccountId) -> Option<&AccountId> {
        self.deployed_tokens.get(token_id)
    }
}

fn generate_proxy_token_id(token_id: &AccountId) -> AccountId {
    let prefix = near_sdk::bs58::encode(env::keccak256_array(token_id.as_bytes()))
        .into_string()
        .to_lowercase();
    format!("{prefix}.{}", env::current_account_id())
        .parse()
        .unwrap()
}

#[ext_contract(ext_ft)]
pub trait FungibleToken {
    fn ft_metadata(&mut self) -> FungibleTokenMetadata;
}

#[test]
fn test_generate_proxy_token_id() {
    let token_id = "usdt.tether-token.near".parse().unwrap();

    assert_eq!(
        generate_proxy_token_id(&token_id).as_str(),
        "5rubrrzzsb8usy5xn3ahmnle79xk9wgajspm5swezors.alice.near"
    );

    let token_id = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
        .parse()
        .unwrap();

    assert_eq!(
        generate_proxy_token_id(&token_id).as_str(),
        "6k1r7pg8butk6qr7bb2vrcvf7vd46yw2ojgm9buvmw6u.alice.near"
    );
}
