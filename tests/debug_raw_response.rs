use unicity_sdk::types::commitment::MintCommitment;
use unicity_sdk::types::predicate::UnmaskedPredicate;
use unicity_sdk::types::token::{TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::crypto::KeyPair;

#[tokio::test]
#[ignore]
async fn test_raw_json_rpc_response() {
    println!("🔍 DEBUG: Checking raw JSON-RPC responses\n");

    // Create a simple mint commitment
    let token_id = TokenId::unique();
    let token_type = TokenType::new(b"RAW_DEBUG".to_vec());

    let key = KeyPair::generate().unwrap();
    let predicate = UnmaskedPredicate::new(key.public_key().clone());
    let state = TokenState::from_predicate(&predicate, Some(b"debug".to_vec())).unwrap();

    let mint_data = MintTransactionData::new(
        token_id,
        token_type,
        state,
        Some(b"metadata".to_vec()),
        Some(vec![1, 2, 3, 4, 5]),
        None,
    );

    let commitment = MintCommitment::create(mint_data).unwrap();

    println!("Request ID: {}", hex::encode(commitment.request_id.as_data_hash().imprint()));
    println!("Transaction Hash: {}", hex::encode(commitment.transaction_hash.imprint()));

    // Manually create JSON-RPC request to see exact response
    use serde_json::json;
    use reqwest::Client;

    let client = Client::new();
    let aggregator_url = "https://goggregator-test.unicity.network";

    // Create the submit_commitment request
    let auth_dto = json!({
        "algorithm": "secp256k1",
        "publicKey": hex::encode(commitment.authenticator.public_key.as_bytes()),
        "signature": hex::encode(commitment.authenticator.signature.as_bytes()),
        "stateHash": hex::encode(commitment.authenticator.state_hash.imprint()),
    });

    let params = json!({
        "requestId": hex::encode(commitment.request_id.as_data_hash().imprint()),
        "transactionHash": hex::encode(commitment.transaction_hash.imprint()),
        "authenticator": auth_dto,
        "receipt": false,
    });

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "submit_commitment",
        "params": params,
    });

    println!("\n📤 Sending submit_commitment request...");
    println!("Request params:");
    println!("{}", serde_json::to_string_pretty(&params).unwrap());

    let response = client
        .post(aggregator_url)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .unwrap();

    let status_code = response.status();
    let body = response.text().await.unwrap();

    println!("\n📥 Raw Response:");
    println!("HTTP Status: {}", status_code);
    println!("Body: {}", body);

    // Parse and pretty print
    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&body) {
        println!("\n📋 Parsed JSON-RPC Response:");
        println!("{}", serde_json::to_string_pretty(&json_value).unwrap());

        // Check what's in the result
        if let Some(result) = json_value.get("result") {
            println!("\n✅ Result field:");
            println!("{}", serde_json::to_string_pretty(result).unwrap());

            // This is where SUCCESS comes from
            if let Some(status) = result.get("status") {
                println!("\n>>> Status value: {}", status);
            }
        }

        if let Some(error) = json_value.get("error") {
            println!("\n❌ Error field:");
            println!("{}", serde_json::to_string_pretty(error).unwrap());
        }
    }

    // Now try get_inclusion_proof
    println!("\n{}", "=".repeat(60));
    println!("📤 Now trying get_inclusion_proof...\n");

    let get_proof_request = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "get_inclusion_proof",
        "params": {
            "requestId": hex::encode(commitment.request_id.as_data_hash().imprint()),
        }
    });

    println!("Request:");
    println!("{}", serde_json::to_string_pretty(&get_proof_request).unwrap());

    let proof_response = client
        .post(aggregator_url)
        .header("Content-Type", "application/json")
        .json(&get_proof_request)
        .send()
        .await
        .unwrap();

    let proof_body = proof_response.text().await.unwrap();

    println!("\n📥 Raw get_inclusion_proof Response:");
    println!("{}", proof_body);

    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&proof_body) {
        println!("\n📋 Parsed Response:");
        println!("{}", serde_json::to_string_pretty(&json_value).unwrap());
    }
}