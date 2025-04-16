use aurora_engine_types::U256;
use aurora_engine_types::parameters::engine::{CallArgs, FunctionCallArgsV2};
use aurora_engine_types::types::Address;
use near_sdk::json_types::U128;
use near_sdk::serde_json::json;
use near_sdk::{AccountId, NearToken};
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{KeyType, SecretKey};
use near_workspaces::{Account, Contract, Worker, compile_project};
use tokio::sync::OnceCell;

const FT_PATH: &str = "../res/fungible-token.wasm";
const AURORA_PATH: &str = "../res/aurora-mainnet-silo-3.9.0.wasm";
const EXIT_TO_NEAR_PRECOMPILE: &str = "e9217bc70b7ed1f598ddd3199e80b093fa71124f";
pub const STORAGE_DEPOSIT: NearToken = NearToken::from_yoctonear(1_250_000_000_000_000_000_000);

static FACTORY_CODE: OnceCell<Vec<u8>> = OnceCell::const_new();

pub struct Env {
    pub user: Account,
    pub token: Contract,
    pub engine: Contract,
    pub factory: Contract,
}

pub async fn env(
    sandbox: &Worker<Sandbox>,
    init_supply: u128,
    decimals: u8,
) -> anyhow::Result<Env> {
    let user = sandbox.dev_create_account().await?;
    let token = deploy_fungible_token(sandbox, init_supply, decimals).await?;
    let engine = deploy_aurora(sandbox).await?;
    let factory = deploy_factory(sandbox).await?;

    Ok(Env {
        user,
        token,
        engine,
        factory,
    })
}

async fn deploy_factory(sandbox: &Worker<Sandbox>) -> anyhow::Result<Contract> {
    let contract_wasm = FACTORY_CODE
        .get_or_init(|| async { compile_project("../factory").await.unwrap() })
        .await;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let contract = sandbox
        .create_tla_and_deploy("factory".parse().unwrap(), sk, contract_wasm)
        .await?
        .result;
    let result = contract
        .call("new")
        .args_json(json!({}))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success(), "{result:#?}");

    Ok(contract)
}

pub async fn deploy_fungible_token(
    sandbox: &Worker<Sandbox>,
    total_supply: u128,
    decimals: u8,
) -> anyhow::Result<Contract> {
    let bytes = tokio::fs::read(FT_PATH).await?;
    let contract = sandbox.dev_deploy_tla(&bytes).await?;

    let result = contract
        .call("new")
        .args_json(json!({
            "owner_id": contract.id(),
            "total_supply": U128(total_supply),
            "metadata": {
                "spec": "ft-1.0.0",
                "name": "Token",
                "symbol": "TKN",
                "decimals": decimals
            }
        }))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success(), "{result:?}");

    Ok(contract)
}

pub async fn deploy_aurora(sandbox: &Worker<Sandbox>) -> anyhow::Result<Contract> {
    let bytes = tokio::fs::read(AURORA_PATH).await?;
    let contract = sandbox.dev_deploy_tla(&bytes).await?;

    let result = contract
        .call("new")
        .args_json(json!({
           "chain_id": 1_313_161_559,
            "owner_id": contract.id(),
            "upgrade_delay_blocks": 0,
            "key_manager": contract.id(),
            "initial_hashchain": null
        }))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success());

    Ok(contract)
}

pub async fn set_base_token(aurora: &Contract, token_id: &AccountId) -> anyhow::Result<()> {
    #[near_sdk::near(serializers = [borsh])]
    enum WithdrawSerialize {
        Borsh,
        Json,
    }

    let result = aurora
        .call("set_eth_connector_contract_account")
        .args_borsh((token_id, WithdrawSerialize::Borsh))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success(), "{result:?}");

    Ok(())
}

pub async fn storage_deposit(token: &Contract, account_id: &AccountId) -> anyhow::Result<()> {
    let result = token
        .call("storage_deposit")
        .args_json(json!({"account_id": account_id }))
        .deposit(STORAGE_DEPOSIT)
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success());
    Ok(())
}

pub async fn storage_deposit_via_proxy(
    user: &Account,
    proxy_account_id: &AccountId,
) -> anyhow::Result<ExecutionFinalResult> {
    let result = user
        .call(proxy_account_id, "storage_deposit")
        .args_json(json!({"account_id": user.id() }))
        .deposit(STORAGE_DEPOSIT)
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success());

    Ok(result)
}

pub async fn balance(token: &Contract, account_id: &AccountId) -> anyhow::Result<U128> {
    token
        .call("ft_balance_of")
        .args_json(json!({"account_id": account_id}))
        .view()
        .await?
        .json::<U128>()
        .map_err(Into::into)
}

pub async fn evm_balance(engine: &Contract, address: Address) -> anyhow::Result<U128> {
    let result = engine
        .call("get_balance")
        .args(address.as_bytes().to_vec())
        .view()
        .await?;

    Ok(U256::from_big_endian(&result.result).as_u128().into())
}

pub async fn make_deposit(
    user: &Account,
    token: &AccountId,
    proxy: &AccountId,
    engine: &AccountId,
    evm_recipient: Address,
    deposit: U128,
) -> anyhow::Result<()> {
    let result = user
        .call(token, "ft_transfer_call")
        .args_json(json!({
            "receiver_id": proxy,
            "amount": deposit,
            "msg": format!("{}:{}", engine, evm_recipient.encode())
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;

    match result.into_result() {
        Ok(_) => Ok(()),
        Err(e) => anyhow::bail!(e),
    }
}

pub async fn make_withdraw(
    user: &Account,
    engine_id: &AccountId,
    proxy_id: &AccountId,
    near_receiver_id: &AccountId,
    amount: U128,
    msg: Option<String>,
) -> anyhow::Result<()> {
    let value = U256::from(amount.0).to_big_endian();
    let result = user
        .call(engine_id, "call")
        .args_borsh(CallArgs::V2(FunctionCallArgsV2 {
            contract: Address::decode(EXIT_TO_NEAR_PRECOMPILE).unwrap(),
            value,
            input: [
                &[0u8],
                proxy_id.as_bytes(),
                b":",
                near_receiver_id.as_bytes(),
                b":",
                msg.unwrap_or_default().as_bytes(),
            ]
            .concat(),
        }))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success(), "{result:?}");

    Ok(())
}

pub async fn transfer(
    token: &Contract,
    account_id: &AccountId,
    amount: U128,
) -> anyhow::Result<()> {
    let result = token
        .call("ft_transfer")
        .args_json(json!({
            "receiver_id": account_id,
            "amount": amount
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success(), "{result:?}");

    Ok(())
}
