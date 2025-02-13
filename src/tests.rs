use crate::{AuroraProxyToken, Error};

#[test]
fn test_modify_amount_deposit() {
    let contract = AuroraProxyToken::new("token.near".parse().unwrap(), 8);
    let deposit = 100u128;
    let amount = contract
        .modify_amount(deposit.into(), contract.deposit_action())
        .unwrap();
    assert_eq!(amount.0, deposit * 10u128.pow(18 - 8));

    let contract = AuroraProxyToken::new("token.near".parse().unwrap(), 24);
    let deposit = 1_000_000_000u128;
    let amount = contract
        .modify_amount(deposit.into(), contract.deposit_action())
        .unwrap();
    assert_eq!(amount.0, deposit / 10u128.pow(24 - 18));
}

#[test]
fn test_modify_amount_withdraw() {
    let contract = AuroraProxyToken::new("token.near".parse().unwrap(), 8);
    let withdraw = 1_000_000_000_001u128;
    let amount = contract
        .modify_amount(withdraw.into(), contract.withdraw_action())
        .unwrap();
    assert_eq!(amount.0, withdraw / 10u128.pow(18 - 8));

    let contract = AuroraProxyToken::new("token.near".parse().unwrap(), 24);
    let withdraw = 1_000_000_000u128;
    let amount = contract
        .modify_amount(withdraw.into(), contract.withdraw_action())
        .unwrap();
    assert_eq!(amount.0, withdraw * 10u128.pow(24 - 18));
}

#[test]
fn test_modify_amount_deposit_too_low() {
    let contract = AuroraProxyToken::new("token.near".parse().unwrap(), 24);
    let deposit = 1000u128;
    let err = contract
        .modify_amount(deposit.into(), contract.deposit_action())
        .err()
        .unwrap();
    assert!(matches!(err, Error::TooLowAmount));
}

#[test]
fn test_modify_amount_withdraw_too_high() {
    let contract = AuroraProxyToken::new("token.near".parse().unwrap(), 24);
    let withdraw = u128::MAX;
    let err = contract
        .modify_amount(withdraw.into(), contract.withdraw_action())
        .err()
        .unwrap();
    assert!(matches!(err, Error::TooHighAmount));
}
