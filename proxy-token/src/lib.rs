use near_contract_standards::fungible_token::metadata::FungibleTokenMetadata;
use near_plugins::{AccessControlRole, AccessControllable, Pausable, access_control, pause};
use near_sdk::borsh::BorshDeserialize;
use near_sdk::json_types::U128;
use near_sdk::serde_json;
use near_sdk::{
    AccountId, Gas, NearToken, PanicOnDefault, PromiseOrValue, PromiseResult, env, ext_contract,
    log, near, require,
};
use std::str::FromStr;

#[cfg(test)]
mod tests;

const META_MASK_DECIMALS: u8 = 18;
const GAS_FOR_FT_ON_TRANSFER: Gas = Gas::from_tgas(20);
const GAS_FOR_FT_TRANSFER: Gas = Gas::from_tgas(10);
const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas::from_tgas(50);
const GAS_FOR_FT_RESOLVE: Gas = Gas::from_tgas(10);
const GAS_FOR_FT_METADATA: Gas = Gas::from_tgas(5);
const GAS_FOR_FINISH_INIT: Gas = Gas::from_tgas(100);

#[derive(AccessControlRole, Copy, Clone)]
#[near(serializers = [json])]
enum Role {
    Controller,
    PauseManager,
    UnpauseManager,
}

#[derive(Debug, PanicOnDefault, Pausable)]
#[access_control(role_type(Role))]
#[pausable(
    pause_roles(Role::Controller, Role::PauseManager),
    unpause_roles(Role::Controller, Role::UnpauseManager)
)]
#[near(contract_state)]
pub struct AuroraProxyToken {
    token_id: AccountId,
    decimals: u8,
}

#[near]
impl AuroraProxyToken {
    /// Initializes the contract with the given NEP-141 token ID.
    #[must_use]
    pub fn init(token_id: AccountId) -> near_sdk::Promise {
        ext_ft::ext(token_id.clone())
            .with_static_gas(GAS_FOR_FT_METADATA)
            .ft_metadata()
            .then(
                Self::ext(env::current_account_id())
                    .with_attached_deposit(env::attached_deposit())
                    .with_static_gas(GAS_FOR_FINISH_INIT)
                    .finish_init(&env::predecessor_account_id(), token_id),
            )
    }

    #[init]
    #[private]
    #[must_use]
    #[allow(clippy::use_self)]
    pub fn finish_init(
        #[callback_unwrap] metadata: &FungibleTokenMetadata,
        controller_id: &AccountId,
        token_id: AccountId,
    ) -> Self {
        let mut contract = Self {
            token_id,
            decimals: metadata.decimals,
        };

        let mut acl = contract.acl_get_or_init();

        require!(
            acl.add_super_admin_unchecked(controller_id),
            "Failed to init Super Admin role"
        );

        require!(
            acl.grant_role_unchecked(Role::Controller, controller_id),
            "Failed to grant Controller role"
        );

        let current_account_id = env::current_account_id();
        require!(
            acl.grant_role_unchecked(Role::PauseManager, &current_account_id),
            "Failed to grant PauseManager role"
        );
        require!(
            acl.grant_role_unchecked(Role::UnpauseManager, &current_account_id),
            "Failed to grant UnpauseManager role"
        );

        contract
    }

    /// Returns the NEP-141 token ID.
    #[must_use]
    pub fn get_token_id(&self) -> AccountId {
        self.token_id.clone()
    }

    /// Returns the number of decimals of the NEP-141 token.
    #[must_use]
    pub const fn get_decimals(&self) -> u8 {
        self.decimals
    }

    #[pause]
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

        let (receiver_id, msg) = parse_message(&msg).unwrap_or_else(|e| env::panic_str(e.as_ref()));

        let amount = modify_amount(amount, withdraw_action(self.decimals))
            .unwrap_or_else(|e| env::panic_str(e.as_ref()));

        let promise = if msg.is_empty() {
            log!(
                "ft_transfer {} on token: {}, to {}",
                amount.0,
                &self.token_id,
                &receiver_id,
            );

            ext_ft::ext(self.token_id.clone())
                .with_static_gas(GAS_FOR_FT_TRANSFER)
                .with_attached_deposit(NearToken::from_yoctonear(1))
                .ft_transfer(receiver_id.clone(), amount)
        } else {
            log!(
                "ft_transfer_call {} on token: {}, to {} with message {:?}",
                amount.0,
                &self.token_id,
                receiver_id,
                &msg
            );

            let Message { msg, memo } = serde_json::from_str(&msg)
                .unwrap_or_else(|_| env::panic_str(&format!("Wrong message format: {msg}")));

            ext_ft::ext(self.token_id.clone())
                .with_attached_deposit(NearToken::from_yoctonear(1))
                .with_static_gas(GAS_FOR_FT_TRANSFER_CALL)
                .ft_transfer_call(receiver_id.clone(), amount, memo, msg)
        };

        promise
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_FT_RESOLVE)
                    .ft_resolve_withdraw(
                        &env::current_account_id(),
                        &receiver_id,
                        amount,
                        !msg.is_empty(),
                    ),
            )
            .into()
    }

    #[pause]
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
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

        let (engine_id, evm_receiver) =
            parse_message(&msg).unwrap_or_else(|e| env::panic_str(e.as_ref()));

        let amount = modify_amount(amount, deposit_action(self.decimals))
            .unwrap_or_else(|e| env::panic_str(e.as_ref()));

        ext_ft::ext(engine_id.clone())
            .with_static_gas(GAS_FOR_FT_ON_TRANSFER)
            .ft_on_transfer(sender_id, amount, evm_receiver)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_FT_RESOLVE)
                    .ft_resolve_deposit(&env::current_account_id(), &engine_id, amount),
            )
            .into()
    }

    #[private]
    pub fn ft_resolve_withdraw(
        &mut self,
        sender_id: &AccountId,
        receiver_id: &AccountId,
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
        sender_id: &AccountId,
        receiver_id: &AccountId,
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
}

#[near(serializers = [json])]
struct Message {
    msg: String,
    memo: Option<String>,
}

#[derive(Clone, Copy)]
enum Action {
    Decrease(u8),
    Increase(u8),
}

fn parse_message(msg: &str) -> Result<(AccountId, String), Error> {
    msg.split_once(':')
        .map(|(acc, msg)| {
            (
                AccountId::from_str(acc)
                    .unwrap_or_else(|_| env::panic_str(Error::BadAccountId.as_ref())),
                msg.to_string(),
            )
        })
        .ok_or(Error::WrongMessage)
}

fn modify_amount(amount: U128, action: Action) -> Result<U128, Error> {
    match action {
        Action::Decrease(decimals) => {
            let amount = amount.0.saturating_div(10u128.pow(u32::from(decimals)));

            if amount == 0 {
                return Err(Error::TooLowAmount);
            }

            Ok(U128(amount))
        }
        Action::Increase(decimals) => amount
            .0
            .checked_mul(10u128.pow(u32::from(decimals)))
            .ok_or(Error::TooHighAmount)
            .map(U128),
    }
}

const fn deposit_action(decimals: u8) -> Action {
    if decimals < META_MASK_DECIMALS {
        Action::Increase(META_MASK_DECIMALS - decimals)
    } else {
        Action::Decrease(decimals - META_MASK_DECIMALS)
    }
}

const fn withdraw_action(decimals: u8) -> Action {
    if decimals > META_MASK_DECIMALS {
        Action::Increase(decimals - META_MASK_DECIMALS)
    } else {
        Action::Decrease(META_MASK_DECIMALS - decimals)
    }
}

#[ext_contract(ext_ft)]
pub trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128);
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128>;
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128>;
    fn ft_metadata(&mut self) -> FungibleTokenMetadata;
}

#[derive(Debug)]
enum Error {
    TooLowAmount,
    TooHighAmount,
    BadAccountId,
    WrongMessage,
}

impl AsRef<str> for Error {
    fn as_ref(&self) -> &str {
        match self {
            Self::TooLowAmount => "Amount is too low",
            Self::TooHighAmount => "Amount is too high",
            Self::BadAccountId => "Bad account_id",
            Self::WrongMessage => "Wrong message format",
        }
    }
}
