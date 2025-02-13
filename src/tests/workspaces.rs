use aurora_engine_sdk::types::near_account_to_evm_address;
use near_sdk::json_types::U128;

use super::helpers::*;

const INIT_TOTAL_SUPPLY: u128 = 1_000_000_000;

#[tokio::test]
async fn test_deposit_withdraw() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        proxy,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

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

    let evm_bal = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_bal, U128(deposit.0 * 10u128.pow(18 - 6)));

    make_withdraw(&user, engine.id(), proxy.id(), user.id(), evm_bal, None).await?;

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

#[tokio::test]
async fn test_deposit_withdraw_service() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        token,
        engine,
        proxy,
        ..
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;
    let service = sandbox
        .dev_deploy_tla(include_bytes!("../../res/mock-service.wasm"))
        .await
        .unwrap();

    set_base_token(&engine, proxy.id()).await?;
    storage_deposit(&token, proxy.id()).await?;
    storage_deposit(&token, service.id()).await?;

    let deposit = U128(1000);
    transfer(&token, service.id(), deposit).await?;

    let user_balance = balance(&token, service.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_recipient = near_account_to_evm_address(service.id().as_bytes());
    make_deposit(
        service.as_account(),
        token.id(),
        proxy.id(),
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, service.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    make_withdraw(
        service.as_account(),
        engine.id(),
        proxy.id(),
        service.id(),
        evm_user_balance,
        Some(r#"{\"msg\":\"withdraw\",\"memo\":\"withdraw\"}"#.to_string()),
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, U128(0));

    let user_balance = balance(&token, service.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(0));

    Ok(())
}

#[tokio::test]
async fn test_deposit_withdraw_two_acc() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        proxy,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    set_base_token(&engine, proxy.id()).await?;
    storage_deposit(&token, proxy.id()).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(1000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let recipient = near_account_to_evm_address(user.id().as_bytes());
    make_deposit(
        &user,
        token.id(),
        proxy.id(),
        engine.id(),
        recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_user_balance = evm_balance(&engine, recipient).await?;
    assert_eq!(evm_user_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    let user2 = "user2.near".parse()?;
    storage_deposit(&token, &user2).await?;

    let amount = U128(evm_user_balance.0 / 2);
    make_withdraw(&user, engine.id(), proxy.id(), user.id(), amount, None).await?;
    make_withdraw(&user, engine.id(), proxy.id(), &user2, amount, None).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, U128(0));

    let user1_balance = balance(&token, user.id()).await?;
    assert_eq!(user1_balance, U128(deposit.0 / 2));

    let user2_balance = balance(&token, &user2).await?;
    assert_eq!(user2_balance, U128(deposit.0 / 2));

    let evm_user_balance = evm_balance(&engine, recipient).await?;
    assert_eq!(evm_user_balance, U128(0));

    Ok(())
}

#[tokio::test]
async fn test_withdraw_to_account_without_storage_deposit() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        proxy,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

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

    let evm_bal = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_bal, U128(deposit.0 * 10u128.pow(18 - 6)));

    // Withdraw to account without storage deposit
    let user2 = "user2.near".parse()?;
    make_withdraw(&user, engine.id(), proxy.id(), &user2, evm_bal, None).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, deposit); // the funds stay on the proxy

    let user2_balance = balance(&token, &user2).await?;
    assert_eq!(user2_balance, U128(0));

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(0)); // the funds are withdrawn from the EVM

    Ok(())
}

#[tokio::test]
async fn test_attempt_to_deposit_more_tokens() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        proxy,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    set_base_token(&engine, proxy.id()).await?;
    storage_deposit(&token, proxy.id()).await?;
    storage_deposit(&token, user.id()).await?;

    let amount = U128(1000);
    transfer(&token, user.id(), amount).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, amount);

    let deposit = U128(2000);

    let evm_recipient = near_account_to_evm_address(user.id().as_bytes());
    let err = make_deposit(
        &user,
        token.id(),
        proxy.id(),
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await
    .err()
    .unwrap();

    assert!(err
        .to_string()
        .contains("Smart contract panicked: The account doesn't have enough balance"));

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - amount.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, amount);

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, U128(0));

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(0));

    Ok(())
}

#[tokio::test]
async fn test_attempt_to_withdraw_more_tokens() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        proxy,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    set_base_token(&engine, proxy.id()).await?;
    storage_deposit(&token, proxy.id()).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(2000);
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

    let amount = U128(evm_user_balance.0 + 1);
    make_withdraw(&user, engine.id(), proxy.id(), user.id(), amount, None).await?;

    // Nothing changed
    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, proxy.id()).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    Ok(())
}
