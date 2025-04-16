use super::helpers::*;
use crate::factory::Factory;
use aurora_engine_sdk::types::near_account_to_evm_address;
use near_sdk::NearToken;
use near_sdk::json_types::U128;
use near_sdk::serde_json::json;

const INIT_TOTAL_SUPPLY: u128 = 1_000_000_000;

#[tokio::test]
async fn test_deposit_withdraw_less_decimals() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(1000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_recipient = near_account_to_evm_address(user.id().as_bytes());
    make_deposit(
        &user,
        token.id(),
        &proxy_id,
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_bal = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_bal, U128(deposit.0 * 10u128.pow(18 - 6)));

    make_withdraw(&user, engine.id(), &proxy_id, user.id(), evm_bal, None).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, U128(0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(0));

    Ok(())
}

#[tokio::test]
async fn test_deposit_withdraw_more_decimals() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 24).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(1_000_000_000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_recipient = near_account_to_evm_address(user.id().as_bytes());
    make_deposit(
        &user,
        token.id(),
        &proxy_id,
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_bal = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_bal, U128(deposit.0 / 10u128.pow(24 - 18)));

    make_withdraw(&user, engine.id(), &proxy_id, user.id(), evm_bal, None).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, U128(0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(0));

    Ok(())
}

#[tokio::test]
async fn test_deposit_withdraw_eighteen_decimals() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 18).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(1_000_000_000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_recipient = near_account_to_evm_address(user.id().as_bytes());
    make_deposit(
        &user,
        token.id(),
        &proxy_id,
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_bal = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_bal, U128(deposit.0));

    make_withdraw(&user, engine.id(), &proxy_id, user.id(), evm_bal, None).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, &proxy_id).await?;
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
        factory,
        ..
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;
    let service = sandbox
        .dev_deploy_tla(include_bytes!("../../res/mock-service.wasm"))
        .await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;
    storage_deposit(&token, service.id()).await?;

    let deposit = U128(1000);
    transfer(&token, service.id(), deposit).await?;

    let user_balance = balance(&token, service.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_recipient = near_account_to_evm_address(service.id().as_bytes());
    make_deposit(
        service.as_account(),
        token.id(),
        &proxy_id,
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, service.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    make_withdraw(
        service.as_account(),
        engine.id(),
        &proxy_id,
        service.id(),
        evm_user_balance,
        Some(r#"{\"msg\":\"withdraw\",\"memo\":\"withdraw\"}"#.to_string()),
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, &proxy_id).await?;
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
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(1000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let recipient = near_account_to_evm_address(user.id().as_bytes());
    make_deposit(
        &user,
        token.id(),
        &proxy_id,
        engine.id(),
        recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_user_balance = evm_balance(&engine, recipient).await?;
    assert_eq!(evm_user_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    let user2 = "user2.near".parse()?;
    storage_deposit(&token, &user2).await?;

    let amount = U128(evm_user_balance.0 / 2);
    make_withdraw(&user, engine.id(), &proxy_id, user.id(), amount, None).await?;
    make_withdraw(&user, engine.id(), &proxy_id, &user2, amount, None).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, U128(0));

    let alice_balance = balance(&token, user.id()).await?;
    assert_eq!(alice_balance, U128(deposit.0 / 2));

    let bob_balance = balance(&token, &user2).await?;
    assert_eq!(bob_balance, U128(deposit.0 / 2));

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
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(1000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_recipient = near_account_to_evm_address(user.id().as_bytes());
    make_deposit(
        &user,
        token.id(),
        &proxy_id,
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_bal = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_bal, U128(deposit.0 * 10u128.pow(18 - 6)));

    // Withdraw to account without storage deposit
    let user2 = "user2.near".parse()?;
    make_withdraw(&user, engine.id(), &proxy_id, &user2, evm_bal, None).await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit); // the funds stay on the proxy

    let bob_balance = balance(&token, &user2).await?;
    assert_eq!(bob_balance, U128(0));

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
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;
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
        &proxy_id,
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await
    .err()
    .unwrap();

    assert!(
        err.to_string()
            .contains("Smart contract panicked: The account doesn't have enough balance")
    );

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - amount.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, amount);

    let proxy_balance = balance(&token, &proxy_id).await?;
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
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;
    storage_deposit(&token, user.id()).await?;

    let deposit = U128(2000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    let evm_recipient = near_account_to_evm_address(user.id().as_bytes());
    make_deposit(
        &user,
        token.id(),
        &proxy_id,
        engine.id(),
        evm_recipient,
        deposit,
    )
    .await?;

    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    let amount = U128(evm_user_balance.0 + 1);
    make_withdraw(&user, engine.id(), &proxy_id, user.id(), amount, None).await?;

    // Nothing changed
    let token_balance = balance(&token, token.id()).await?;
    assert_eq!(token_balance, U128(INIT_TOTAL_SUPPLY - deposit.0));

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, U128(0));

    let proxy_balance = balance(&token, &proxy_id).await?;
    assert_eq!(proxy_balance, deposit);

    let evm_user_balance = evm_balance(&engine, evm_recipient).await?;
    assert_eq!(evm_user_balance, U128(deposit.0 * 10u128.pow(18 - 6)));

    Ok(())
}

#[tokio::test]
async fn test_get_proxy_token() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env { token, factory, .. } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let deployed_id = factory.deploy_token(token.id()).await?;
    let retrieved_id = factory.get_proxy_token(token.id()).await?;

    assert_eq!(deployed_id, retrieved_id);

    Ok(())
}

#[tokio::test]
async fn test_deploy_wrong_token() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let not_nep141 = sandbox.dev_create_account().await?;
    let Env { factory, .. } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let result = factory
        .call("deploy_token")
        .args_json(json!({"token_id": not_nep141.id()}))
        .deposit(NearToken::from_near(3))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_failure());

    let err_msg = result.into_result().err().unwrap().to_string();
    assert!(
        // The computation was not successful because we couldn't get the metadata from non-NEP-141.
        err_msg.contains("Smart contract panicked: Callback computation 0 was not successful"),
        "{err_msg}",
    );

    Ok(())
}

#[tokio::test]
async fn test_deploy_by_not_controller() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let alice = sandbox.dev_create_account().await?;
    let Env { token, factory, .. } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let result = alice
        .call(factory.id(), "deploy_token")
        .args_json(json!({"token_id": token.id()}))
        .deposit(NearToken::from_near(3))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_failure());

    let err_msg = result.into_result().err().unwrap().to_string();
    assert!(
        err_msg.contains(
            "Insufficient permissions for method deploy_token restricted by access control"
        ),
        "{err_msg}"
    );

    Ok(())
}

#[tokio::test]
async fn test_storage_deposit_via_proxy() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;

    let balance_before = user.view_account().await?.balance;
    let result = storage_deposit_via_proxy(&user, &proxy_id).await?;
    let total_spend = result
        .outcomes()
        .iter()
        .fold(0u128, |total, o| total + o.tokens_burnt.as_yoctonear());

    sandbox.fast_forward(1).await?; // wait for refund tokens for unused gas

    let balance_after = user.view_account().await?.balance;
    assert_eq!(
        balance_before.as_yoctonear(),
        balance_after
            .checked_add(STORAGE_DEPOSIT)
            .as_ref()
            .map(|r| r.as_yoctonear() + total_spend)
            .unwrap()
    );

    let deposit = U128(1000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    Ok(())
}

#[tokio::test]
async fn test_double_storage_deposit_refund() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;
    storage_deposit(&token, &proxy_id).await?;

    let balance_before = user.view_account().await?.balance;

    let result = storage_deposit_via_proxy(&user, &proxy_id).await?;
    let total_spend = result
        .outcomes()
        .iter()
        .fold(0u128, |total, o| total + o.tokens_burnt.as_yoctonear());

    sandbox.fast_forward(1).await?; // wait for refund tokens for unused gas

    let balance_after = user.view_account().await?.balance;
    assert_eq!(
        balance_before.as_yoctonear(),
        balance_after
            .checked_add(STORAGE_DEPOSIT)
            .as_ref()
            .map(|r| r.as_yoctonear() + total_spend)
            .unwrap()
    );

    // Second storage deposit should be failed and refunded
    let balance_before = user.view_account().await?.balance;
    let result = storage_deposit_via_proxy(&user, &proxy_id).await?;
    let total_spend = result
        .outcomes()
        .iter()
        .fold(0u128, |total, o| total + o.tokens_burnt.as_yoctonear());

    sandbox.fast_forward(1).await?; // wait for refund tokens for unused gas

    let balance_after = user.view_account().await?.balance;
    assert_eq!(
        balance_before.as_yoctonear(),
        balance_after.as_yoctonear() + total_spend
    );

    let deposit = U128(1000);
    transfer(&token, user.id(), deposit).await?;

    let user_balance = balance(&token, user.id()).await?;
    assert_eq!(user_balance, deposit);

    Ok(())
}

#[tokio::test]
async fn test_storage_deposit_less() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;

    let balance_before = user.view_account().await?.balance;

    let result = user
        .call(&proxy_id, "storage_deposit")
        .args_json(json!({"account_id": user.id() }))
        .deposit(STORAGE_DEPOSIT.saturating_div(2))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success());
    let total_spend = result
        .outcomes()
        .iter()
        .fold(0u128, |total, o| total + o.tokens_burnt.as_yoctonear());

    sandbox.fast_forward(1).await?; // wait for refund tokens for unused gas

    let balance_after = user.view_account().await?.balance;
    // We don't need to subtract the STORAGE_DEPOSIT because we deposited less than needed,
    // so refund has happened. We subtract the spending for transaction only.
    assert_eq!(
        balance_before.as_yoctonear() - total_spend,
        balance_after.as_yoctonear()
    );

    Ok(())
}

#[tokio::test]
async fn test_storage_deposit_more() -> anyhow::Result<()> {
    let sandbox = near_workspaces::sandbox().await?;
    let Env {
        user,
        token,
        engine,
        factory,
    } = env(&sandbox, INIT_TOTAL_SUPPLY, 6).await?;

    let proxy_id = factory.deploy_token(token.id()).await?;
    set_base_token(&engine, &proxy_id).await?;

    let balance_before = user.view_account().await?.balance;

    let result = user
        .call(&proxy_id, "storage_deposit")
        .args_json(json!({"account_id": user.id() }))
        .deposit(STORAGE_DEPOSIT.saturating_mul(2))
        .max_gas()
        .transact()
        .await?;
    assert!(result.is_success());
    let total_spend = result
        .outcomes()
        .iter()
        .fold(0u128, |total, o| total + o.tokens_burnt.as_yoctonear());

    sandbox.fast_forward(1).await?; // wait for refund tokens for unused gas

    let balance_after = user.view_account().await?.balance;
    // We tried to deposit 2 x STORAGE_DEPOSIT, but subtract only ONE here, because the another
    // should be refunded.
    assert_eq!(
        balance_before
            .saturating_sub(STORAGE_DEPOSIT)
            .as_yoctonear()
            - total_spend,
        balance_after.as_yoctonear()
    );

    Ok(())
}
