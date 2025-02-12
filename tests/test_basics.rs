use aurora_engine_sdk::types::near_account_to_evm_address;
use aurora_engine_types::parameters::engine::{CallArgs, FunctionCallArgsV2};
use aurora_engine_types::types::Address;
use aurora_engine_types::U256;
use near_sdk::json_types::U128;
use near_sdk::{AccountId, NearToken};
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Contract, Worker};
use serde_json::json;

const EXIT_TO_NEAR_PRECOMPILE: &str = "e9217bc70b7ed1f598ddd3199e80b093fa71124f";
const STORAGE_DEPOSIT: NearToken = NearToken::from_yoctonear(1_250_000_000_000_000_000_000);
const INIT_TOTAL_SUPPLY: U128 = U128(1_000_000_000);

#[tokio::test]
async fn test_deposit_withdraw() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let user = sandbox.dev_create_account().await?;
    let token = deploy_fungible_token(&sandbox).await?;
    let engine = deploy_aurora(&sandbox).await?;
    let proxy = deploy_proxy(&sandbox, token.id(), 6).await?;

    set_base_token(&engine, proxy.id()).await?;
    storage_deposit(&token, proxy.id()).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(1000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_recipient = near_account_to_evm_address(user.id().as_bytes());
    make_deposit(
        &user,
        token.id(),
        proxy.id(),
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY.0 - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    make_withdraw(&user, engine.id(), proxy.id(), user.id(), evm_balance).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY.0 - deposit.0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, U128(0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_balance = crate::evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_balance, U128(0));

    Ok(())
}

async fn deploy_proxy(
    sandbox: &Worker<Sandbox>,
    token_id: &AccountId,
    decimals: u8,
) -> anyhow::Result<Contract> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let result = contract
        .call("new")
        .args_json(json!({"token_id": token_id, "decimals": decimals}))
        .transact()
        .await?;
    assert!(result.is_success(), "{result:?}");

    Ok(contract)
}

async fn deploy_fungible_token(sandbox: &Worker<Sandbox>) -> anyhow::Result<Contract> {
    let contract = sandbox
        .dev_deploy(include_bytes!("../res/fungible-token.wasm"))
        .await?;

    let result = contract
        .call("new")
        .args_json(json!({
            "owner_id": contract.id(),
            "total_supply": INIT_TOTAL_SUPPLY,
            "metadata": {
                "spec": "ft-1.0.0",
                "name": "Token",
                "symbol": "TKN",
                "decimals": 6
            }
        }))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success(), "{result:?}");

    Ok(contract)
}

async fn deploy_aurora(sandbox: &Worker<Sandbox>) -> anyhow::Result<Contract> {
    let contract = sandbox
        .dev_deploy(include_bytes!("../res/aurora-mainnet-silo-3.8.0.wasm"))
        .await?;
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

async fn set_base_token(aurora: &Contract, token_id: &AccountId) -> anyhow::Result<()> {
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

async fn storage_deposit(token: &Contract, account_id: &AccountId) -> anyhow::Result<()> {
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

async fn balance(token: &Contract, account_id: &AccountId) -> anyhow::Result<U128> {
    token
        .call("ft_balance_of")
        .args_json(json!({"account_id": account_id}))
        .view()
        .await?
        .json::<U128>()
        .map_err(Into::into)
}

async fn evm_balance(engine: &Contract, address: Address) -> anyhow::Result<U128> {
    let result = engine
        .call("get_balance")
        .args(address.as_bytes().to_vec())
        .view()
        .await?;

    Ok(U256::from_big_endian(&result.result).as_u128().into())
}

async fn make_deposit(
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
    assert!(result.is_success(), "{result:?}");

    Ok(())
}

async fn make_withdraw(
    user: &Account,
    engine_id: &AccountId,
    proxy_id: &AccountId,
    near_receiver_id: &AccountId,
    amount: U128,
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
            ]
            .concat(),
        }))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success(), "{result:?}");

    Ok(())
}

async fn transfer(token: &Contract, account_id: &AccountId, amount: U128) -> anyhow::Result<()> {
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
