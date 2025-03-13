use near_sdk::serde_json::json;
use near_sdk::{AccountId, NearToken};
use near_workspaces::Contract;

pub trait Factory {
    async fn deploy_token(&self, token_id: &AccountId) -> anyhow::Result<AccountId>;
    async fn get_proxy_token(&self, token_id: &AccountId) -> anyhow::Result<AccountId>;
}

impl Factory for Contract {
    async fn deploy_token(&self, token_id: &AccountId) -> anyhow::Result<AccountId> {
        let result = self
            .call("deploy_token")
            .args_json(json!({"token_id": token_id}))
            .deposit(NearToken::from_near(3))
            .max_gas()
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
        result.json().map_err(Into::into)
    }

    async fn get_proxy_token(&self, token_id: &AccountId) -> anyhow::Result<AccountId> {
        self.call("get_proxy_token")
            .args_json(json!({"token_id": token_id}))
            .view()
            .await?
            .json()
            .map_err(Into::into)
    }
}
