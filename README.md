# Aurora Proxy Factory

The main purpose of the contract is to provide the ability to deploy proxy token contracts for NEP-141 tokens.
The purpose of the proxy token is to solve the issue of base tokens having a number of decimals that is not equal to 18.
The problem exists because the MetaMask can only work with base tokens that have a number of decimals equal to 18.
In another way, the balance in base tokens was displayed incorrectly in the MetaMask.

## Build factory

Install [`cargo-near`](https://github.com/near/cargo-near)
[`cargo-make`](https://github.com/sagiegurari/cargo-make) and run:

```bash
cargo make build
```

## Test Locally

```bash
cargo make test
```

### API

#### Auror Proxy Factory:

```rust
/// Initializes the contract with the given account of DAO contract.
pub fn new(dao: Option<AccountId>) -> Self;

/// Deploys a proxy token contract for the given NEP-141 token.
#[pause]
#[payable]
#[access_control_any(roles(Role::Controller))]
pub fn deploy_token(&mut self, token_id: AccountId) -> AccountId;

/// Returns the proxy token contract ID for the given NEP-141 token.
pub fn get_proxy_token(&self, token_id: &AccountId) -> Option<&AccountId>
```

#### Auror Proxy Token:

```rust
/// Initializes the contract with the given NEP-141 token ID.
pub fn init(token_id: AccountId) -> Self;

/// Returns the NEP-141 token ID.
pub fn get_token_id(&self) -> AccountId;

/// Returns the number of decimals of the NEP-141 token.
pub const fn get_decimals(&self) -> u8;

/// Proxy `ft_transfer_call` method for the NEP-141 token.
pub fn ft_transfer_call(
    &mut self,
    receiver_id: AccountId,
    amount: U128,
    memo: Option<String>,
    msg: String,
) -> PromiseOrValue<U128>;

/// Proxy `ft_on_transfer` method for the NEP-141 token.
pub fn ft_on_transfer(
    &mut self,
    sender_id: AccountId,
    amount: U128,
    msg: String,
) -> PromiseOrValue<U128>;

/// Proxy `storage_deposit` method for the NEP-141 token.
fn storage_deposit(
    &mut self,
    account_id: AccountId,
    registration_only: Option<bool>,
) -> StorageBalance;
```
