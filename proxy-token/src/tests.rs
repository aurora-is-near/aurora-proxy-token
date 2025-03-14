use crate::{Error, deposit_action, modify_amount, withdraw_action};

#[test]
fn test_modify_amount_deposit() {
    let deposit = 100u128;
    let amount = modify_amount(deposit.into(), deposit_action(8)).unwrap();
    assert_eq!(amount.0, deposit * 10u128.pow(18 - 8));

    let deposit = 1_000_000_000u128;
    let amount = modify_amount(deposit.into(), deposit_action(24)).unwrap();
    assert_eq!(amount.0, deposit / 10u128.pow(24 - 18));
}

#[test]
fn test_modify_amount_withdraw() {
    let withdraw = 1_000_000_000_001u128;
    let amount = modify_amount(withdraw.into(), withdraw_action(8)).unwrap();
    assert_eq!(amount.0, withdraw / 10u128.pow(18 - 8));

    let withdraw = 1_000_000_000u128;
    let amount = modify_amount(withdraw.into(), withdraw_action(24)).unwrap();
    assert_eq!(amount.0, withdraw * 10u128.pow(24 - 18));
}

#[test]
fn test_modify_amount_deposit_too_low() {
    let deposit = 1000u128;
    let err = modify_amount(deposit.into(), deposit_action(24))
        .err()
        .unwrap();
    assert!(matches!(err, Error::TooLowAmount));
}

#[test]
fn test_modify_amount_withdraw_too_high() {
    let withdraw = u128::MAX;
    let err = modify_amount(withdraw.into(), withdraw_action(24))
        .err()
        .unwrap();
    assert!(matches!(err, Error::TooHighAmount));
}
