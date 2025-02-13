use aurora_engine_sdk::types::near_account_to_evm_address;
use near_sdk::json_types::U128;

use super::helpers::*;

const INIT_TOTAL_SUPPLY: u128 = 1_000_000_000;

#[tokio::test]
async fn test_deposit_withdraw() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let user = sandbox.dev_create_account().await?;
    let token = deploy_fungible_token(&sandbox, INIT_TOTAL_SUPPLY).await?;
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
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    make_withdraw(&user, engine.id(), proxy.id(), user.id(), evm_user_balance).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, U128(0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(0));

    Ok(())
}
