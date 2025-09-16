use crate::client::aggregator::{AggregatorClient, InclusionProofUtils};
use crate::crypto::SigningService;
use crate::error::{Result, SdkError};
use crate::types::commitment::{MintCommitment, TransferCommitment};
use crate::types::token::{Token, TokenState};
use crate::types::transaction::{
    MintTransactionData, NametagMintTransactionData, Transaction, TransferTransactionData,
};
use secp256k1::SecretKey;
use std::time::Duration;

/// High-level state transition client
pub struct StateTransitionClient {
    aggregator: AggregatorClient,
    signing_service: SigningService,
}

impl StateTransitionClient {
    /// Create a new state transition client
    pub fn new(aggregator_url: String) -> Result<Self> {
        let aggregator = AggregatorClient::new(aggregator_url)?;
        let signing_service = SigningService::new();
        Ok(Self {
            aggregator,
            signing_service,
        })
    }

    /// Create from existing aggregator client
    pub fn from_aggregator(aggregator: AggregatorClient) -> Self {
        Self {
            aggregator,
            signing_service: SigningService::new(),
        }
    }

    /// Mint a new token
    pub async fn mint_token(
        &self,
        mint_data: MintTransactionData,
        signing_key: &SecretKey,
    ) -> Result<Token<MintTransactionData>> {
        // Create and sign commitment
        let commitment = MintCommitment::create(mint_data.clone(), signing_key)?;

        // Submit commitment
        let response = self.aggregator.submit_commitment(&commitment).await?;

        if response.status != "accepted" && response.status != "success" {
            return Err(SdkError::StateTransition(format!(
                "Commitment rejected: {:?}",
                response.message
            )));
        }

        // Wait for inclusion proof
        let proof = InclusionProofUtils::wait_inclusion_proof(
            &self.aggregator,
            &commitment.request_id,
        )
        .await?;

        // Create token with transaction
        let transaction = commitment.to_transaction(proof);
        let token = Token::new(mint_data.target_state.clone(), transaction);

        Ok(token)
    }

    /// Transfer a token
    pub async fn transfer_token<T>(
        &self,
        token: &Token<T>,
        target_state: TokenState,
        salt: Option<Vec<u8>>,
        signing_key: &SecretKey,
    ) -> Result<Token<T>>
    where
        T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        // Create and sign transfer commitment
        let commitment = TransferCommitment::create(token, target_state.clone(), salt, signing_key)?;

        // Submit commitment
        let response = self.aggregator.submit_commitment(&commitment).await?;

        if response.status != "accepted" && response.status != "success" {
            return Err(SdkError::StateTransition(format!(
                "Commitment rejected: {:?}",
                response.message
            )));
        }

        // Wait for inclusion proof
        let proof = InclusionProofUtils::wait_inclusion_proof(
            &self.aggregator,
            &commitment.request_id,
        )
        .await?;

        // Create updated token
        let transfer_tx = commitment.to_transaction(proof);
        let mut updated_token = token.clone();
        updated_token.state = target_state;
        updated_token.add_transaction(transfer_tx);

        Ok(updated_token)
    }

    /// Submit a mint commitment
    pub async fn submit_mint_commitment(
        &self,
        commitment: &MintCommitment,
    ) -> Result<String> {
        let response = self.aggregator.submit_commitment(commitment).await?;

        if response.status != "accepted" && response.status != "success" {
            return Err(SdkError::StateTransition(format!(
                "Commitment rejected: {:?}",
                response.message
            )));
        }

        Ok(response.request_id)
    }

    /// Submit a transfer commitment
    pub async fn submit_transfer_commitment(
        &self,
        commitment: &TransferCommitment,
    ) -> Result<String> {
        let response = self.aggregator.submit_commitment(commitment).await?;

        if response.status != "accepted" && response.status != "success" {
            return Err(SdkError::StateTransition(format!(
                "Commitment rejected: {:?}",
                response.message
            )));
        }

        Ok(response.request_id)
    }

    /// Finalize a transaction with inclusion proof
    pub async fn finalize_transaction<T>(
        &self,
        token: &Token<T>,
        new_state: TokenState,
        transaction_data: TransferTransactionData,
        proof: crate::types::transaction::InclusionProof,
    ) -> Result<Token<T>>
    where
        T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let transaction = Transaction::new(transaction_data, proof);

        let mut finalized_token = token.clone();
        finalized_token.state = new_state;
        finalized_token.add_transaction(transaction);

        Ok(finalized_token)
    }

    /// Create a nametag token
    pub async fn create_nametag(
        &self,
        nametag: String,
        target_state: TokenState,
        signing_key: &SecretKey,
    ) -> Result<Token<NametagMintTransactionData>> {
        let nametag_data = NametagMintTransactionData::new(nametag, target_state.clone());

        // For nametag, we need to wrap it as mint data
        use crate::types::token::TokenType;
        let mint_data = MintTransactionData::new(
            TokenType::new(b"NAMETAG".to_vec()),
            target_state,
            Some(serde_json::to_vec(&nametag_data)?),
            None,
        );

        let commitment = MintCommitment::create(mint_data.clone(), signing_key)?;

        let response = self.aggregator.submit_commitment(&commitment).await?;

        if response.status != "accepted" && response.status != "success" {
            return Err(SdkError::StateTransition(format!(
                "Commitment rejected: {:?}",
                response.message
            )));
        }

        let proof = InclusionProofUtils::wait_inclusion_proof(
            &self.aggregator,
            &commitment.request_id,
        )
        .await?;

        let transaction = Transaction::new(nametag_data.clone(), proof);
        let token = Token::new(nametag_data.target_state.clone(), transaction);

        Ok(token)
    }

    /// Wait for a commitment to be included
    pub async fn wait_for_inclusion(
        &self,
        request_id: &crate::types::primitives::RequestId,
        timeout: Duration,
    ) -> Result<crate::types::transaction::InclusionProof> {
        self.aggregator
            .wait_for_inclusion_proof(request_id, timeout)
            .await
    }

    /// Get current block height
    pub async fn get_block_height(&self) -> Result<u64> {
        self.aggregator.get_block_height().await
    }

    /// Health check
    pub async fn health_check(&self) -> Result<bool> {
        self.aggregator.health_check().await
    }

    /// Get the aggregator client
    pub fn aggregator(&self) -> &AggregatorClient {
        &self.aggregator
    }

    /// Get the signing service
    pub fn signing_service(&self) -> &SigningService {
        &self.signing_service
    }
}

/// Token builder for fluent API
pub struct TokenBuilder<'a> {
    client: &'a StateTransitionClient,
    mint_data: Option<MintTransactionData>,
    signing_key: Option<SecretKey>,
}

impl<'a> TokenBuilder<'a> {
    /// Create a new token builder
    pub fn new(client: &'a StateTransitionClient) -> Self {
        Self {
            client,
            mint_data: None,
            signing_key: None,
        }
    }

    /// Set the mint data
    pub fn with_mint_data(mut self, mint_data: MintTransactionData) -> Self {
        self.mint_data = Some(mint_data);
        self
    }

    /// Set the signing key
    pub fn with_signing_key(mut self, key: SecretKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Build and submit the token
    pub async fn build(self) -> Result<Token<MintTransactionData>> {
        let mint_data = self
            .mint_data
            .ok_or_else(|| SdkError::InvalidParameter("Missing mint data".to_string()))?;

        let signing_key = self
            .signing_key
            .ok_or_else(|| SdkError::InvalidParameter("Missing signing key".to_string()))?;

        self.client.mint_token(mint_data, &signing_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::types::predicate::UnmaskedPredicate;
    use crate::types::token::TokenType;

    #[tokio::test]
    async fn test_client_creation() {
        let client = StateTransitionClient::new("http://localhost:3000".to_string());
        assert!(client.is_ok());
    }

    #[test]
    fn test_token_builder() {
        let client = StateTransitionClient::new("http://localhost:3000".to_string()).unwrap();
        let key_pair = KeyPair::generate().unwrap();

        let predicate = UnmaskedPredicate::new(key_pair.public_key().clone());
        let state = TokenState::from_predicate(&predicate, None).unwrap();
        let mint_data = MintTransactionData::new(
            TokenType::new(vec![1, 2, 3]),
            state,
            None,
            None,
        );

        let _builder = TokenBuilder::new(&client)
            .with_mint_data(mint_data)
            .with_signing_key(key_pair.secret_key().clone());

        // Builder is ready (actual submission would require running aggregator)
        assert!(true);
    }
}