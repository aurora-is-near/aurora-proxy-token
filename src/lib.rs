use near_sdk::json_types::U128;
use near_sdk::serde_json::{self, json};
use near_sdk::{
    env, log, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseOrValue,
    PromiseResult,
};
use std::str::FromStr;

const META_MASK_DECIMALS: u8 = 18;
const GAS_FOR_FT_ON_TRANSFER: Gas = Gas::from_tgas(20);
const GAS_FOR_FT_TRANSFER: Gas = Gas::from_tgas(10);
const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas::from_tgas(50);
const GAS_FOR_FT_RESOLVE: Gas = Gas::from_tgas(10);

#[derive(Debug, PanicOnDefault)]
#[near(contract_state)]
pub struct AuroraProxyToken {
    token_id: AccountId,
    decimals: u8,
}

#[near]
impl AuroraProxyToken {
    #[init]
    #[allow(clippy::use_self)]
    pub const fn new(token_id: AccountId, decimals: u8) -> Self {
        Self { token_id, decimals }
    }

    #[payable]
    #[allow(unused_variables)]
    pub fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>, // Engine doesn't use memo
        msg: String,
    ) -> PromiseOrValue<U128> {
        require!(
            env::current_account_id() == receiver_id,
            format!("Only on {} can call `ft_transfer_call`", self.token_id)
        );

        let (receiver_id, msg) = parse_message(&msg)
            .map(|(receiver_id, msg)| {
                (
                    receiver_id.unwrap_or_else(|| env::panic_str("Receiver is not specified")),
                    msg,
                )
            })
            .unwrap_or_else(|| env::panic_str(&format!("Wrong message format: {msg}")));

        let amount = self
            .modify_amount(amount, self.withdraw_action())
            .unwrap_or_else(|e| env::panic_str(e.as_ref()));

        let promise = if msg.is_empty() {
            log!(
                "ft_transfer {} on token: {}, to {}",
                amount.0,
                &self.token_id,
                &receiver_id,
            );

            Promise::new(self.token_id.clone()).function_call(
                "ft_transfer".to_string(),
                serde_json::to_vec(&json!({
                    "receiver_id": receiver_id, // intents.near
                    "amount": amount
                }))
                .unwrap(),
                NearToken::from_yoctonear(1),
                GAS_FOR_FT_TRANSFER,
            )
        } else {
            log!(
                "ft_transfer_call {} on token: {}, to {} with message {:?}",
                amount.0,
                &self.token_id,
                receiver_id,
                &msg
            );

            let Message { msg, memo } = serde_json::from_str(msg)
                .unwrap_or_else(|_| env::panic_str(&format!("Wrong message format: {msg}")));

            Promise::new(self.token_id.clone()).function_call(
                "ft_transfer_call".to_string(),
                serde_json::to_vec(&json!({
                    "receiver_id": receiver_id, // intents.near
                    "amount": amount,
                    "memo": memo,
                    "msg": msg,
                }))
                .unwrap(),
                NearToken::from_yoctonear(1),
                GAS_FOR_FT_TRANSFER_CALL,
            )
        };

        PromiseOrValue::Promise(
            promise.then(
                Promise::new(env::current_account_id()).function_call(
                    "ft_resolve_withdraw".to_string(),
                    serde_json::to_vec(&json!({
                        "sender_id": env::current_account_id(),
                        "receiver_id": receiver_id,
                        "amount": amount,
                        "is_call": !msg.is_empty(),
                    }))
                    .unwrap(),
                    NearToken::from_yoctonear(0),
                    GAS_FOR_FT_RESOLVE,
                ),
            ),
        )
    }

    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        // silo.aurora.near:fe71e451caabd1d87bdb75891430eb90a4956839
        require!(
            env::predecessor_account_id() == self.token_id,
            format!("Only {} can call this method", self.token_id)
        );

        log!(
            "ft_on_transfer {} from {} with message {}",
            amount.0,
            sender_id,
            msg
        );

        let (engine_id, evm_receiver) = parse_message(&msg)
            .unwrap_or_else(|| env::panic_str(&format!("Wrong message format: {msg}")));

        let amount = self
            .modify_amount(amount, self.deposit_action())
            .unwrap_or_else(|e| env::panic_str(e.as_ref()));

        PromiseOrValue::Promise(
            Promise::new(engine_id.clone().unwrap())
                .function_call(
                    "ft_on_transfer".to_string(),
                    serde_json::to_vec(&json!({
                        "sender_id": env::current_account_id(),
                        "amount": amount,
                        "msg": evm_receiver,
                    }))
                    .unwrap(),
                    NearToken::from_yoctonear(1),
                    GAS_FOR_FT_ON_TRANSFER,
                )
                .then(
                    Promise::new(env::current_account_id()).function_call(
                        "ft_resolve_deposit".to_string(),
                        serde_json::to_vec(&json!({
                            "sender_id": env::current_account_id(),
                            "receiver_id": engine_id,
                            "amount": amount,
                        }))
                        .unwrap(),
                        NearToken::from_yoctonear(0),
                        GAS_FOR_FT_RESOLVE,
                    ),
                ),
        )
    }

    #[private]
    pub fn ft_resolve_withdraw(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        is_call: bool,
    ) -> U128 {
        log!(
            "ft_resolve_withdraw {} from {} to: {}",
            amount.0,
            sender_id,
            receiver_id,
        );

        let used = match env::promise_result(0) {
            PromiseResult::Successful(value) => {
                if is_call {
                    // `ft_transfer_call` returns successfully transferred amount
                    serde_json::from_slice::<U128>(&value)
                        .unwrap_or_default()
                        .0
                        .min(amount.0)
                } else if value.is_empty() {
                    // `ft_transfer` returns empty result on success
                    amount.0
                } else {
                    0
                }
            }
            PromiseResult::Failed => {
                if is_call {
                    // do not refund on failed `ft_transfer_call` due to
                    // NEP-141 vulnerability: `ft_resolve_transfer` fails to
                    // read result of `ft_on_transfer` due to insufficient gas
                    amount.0
                } else {
                    0
                }
            }
        };

        U128(used)
    }

    #[private]
    pub fn ft_resolve_deposit(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        log!(
            "ft_resolve_deposit {} from {} to: {}",
            amount.0,
            sender_id,
            receiver_id,
        );

        let used = match env::promise_result(0) {
            PromiseResult::Successful(value) => serde_json::from_slice::<U128>(&value)
                .unwrap_or_default()
                .0
                .min(amount.0),
            PromiseResult::Failed => amount.0,
        };

        U128(used)
    }

    fn modify_amount(&self, amount: U128, action: Action) -> Result<U128, Error> {
        match action {
            Action::Decrease(decimals) => {
                let amount = amount.0.saturating_div(10u128.pow(decimals as u32));
                require!(amount > 0, Error::TooLowDeposit.as_ref());

                Ok(U128(amount))
            }
            Action::Increase(decimals) => amount
                .0
                .checked_mul(10u128.pow(decimals as u32))
                .ok_or(Error::TooHighDeposit)
                .map(U128),
        }
    }

    const fn deposit_action(&self) -> Action {
        if self.decimals < META_MASK_DECIMALS {
            Action::Increase(META_MASK_DECIMALS - self.decimals)
        } else {
            Action::Decrease(self.decimals - META_MASK_DECIMALS)
        }
    }

    const fn withdraw_action(&self) -> Action {
        if self.decimals > META_MASK_DECIMALS {
            Action::Increase(self.decimals - META_MASK_DECIMALS)
        } else {
            Action::Decrease(META_MASK_DECIMALS - self.decimals)
        }
    }
}

#[near(serializers = [json])]
struct Message {
    msg: String,
    memo: Option<String>,
}

enum Action {
    Decrease(u8),
    Increase(u8),
}

fn parse_message(msg: &str) -> Option<(Option<AccountId>, &str)> {
    msg.split_once(':')
        .map(|(acc, msg)| (AccountId::from_str(acc).ok(), msg))
}

enum Error {
    TooLowDeposit,
    TooHighDeposit,
}

impl AsRef<str> for Error {
    fn as_ref(&self) -> &str {
        match self {
            Self::TooLowDeposit => "Deposit is too low",
            Self::TooHighDeposit => "Deposit is too high",
        }
    }
}
