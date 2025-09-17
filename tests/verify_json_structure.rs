use unicity_sdk::client::aggregator::AuthenticatorDto;
use unicity_sdk::crypto::KeyPair;
use unicity_sdk::types::commitment::MintCommitment;
use unicity_sdk::types::predicate::UnmaskedPredicate;
use unicity_sdk::types::token::{TokenState, TokenType};
use unicity_sdk::types::transaction::MintTransactionData;

#[test]
fn test_json_serialization_matches_java() {
    // Create a mint commitment using proper signing
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let signing_key = key_pair.secret_key();
    let public_key = key_pair.public_key().clone();

    let predicate = UnmaskedPredicate::new(public_key.clone());
    let target_state = TokenState::from_predicate(&predicate, None).expect("Failed to create state");

    let mint_data = MintTransactionData::new(
        TokenType::new(vec![1, 2, 3, 4]),
        target_state,
        Some(vec![5, 6, 7, 8]),
        None,
    );

    let commitment = MintCommitment::create(mint_data, signing_key)
        .expect("Failed to create commitment");

    // Convert authenticator to DTO
    let auth_dto = AuthenticatorDto::from(&commitment.authenticator);

    // Create the submit request JSON structure
    let submit_request = serde_json::json!({
        "requestId": hex::encode(commitment.request_id.as_data_hash().imprint()),
        "transactionHash": hex::encode(commitment.transaction_hash.imprint()),
        "authenticator": auth_dto,
        "receipt": false,
    });

    let json = serde_json::to_string_pretty(&submit_request).expect("Failed to serialize");

    println!("Submit request JSON:");
    println!("{}", json);

    // Verify all required fields are present
    assert!(json.contains("\"requestId\""));
    assert!(json.contains("\"transactionHash\""));
    assert!(json.contains("\"authenticator\""));
    assert!(json.contains("\"algorithm\""));
    assert!(json.contains("\"publicKey\""));
    assert!(json.contains("\"signature\""));
    assert!(json.contains("\"stateHash\""));
    assert!(json.contains("\"receipt\""));

    // Verify field formats
    let req_obj = submit_request.as_object().unwrap();
    let auth_obj = req_obj["authenticator"].as_object().unwrap();

    assert_eq!(auth_obj["algorithm"].as_str().unwrap(), "secp256k1");
    assert_eq!(req_obj["requestId"].as_str().unwrap().len(), 68);  // 34 bytes hex
    assert_eq!(req_obj["transactionHash"].as_str().unwrap().len(), 68);  // 34 bytes hex
    assert_eq!(auth_obj["publicKey"].as_str().unwrap().len(), 66);  // 33 bytes hex
    assert_eq!(auth_obj["signature"].as_str().unwrap().len(), 130);  // 65 bytes hex
    assert_eq!(auth_obj["stateHash"].as_str().unwrap().len(), 68);  // 34 bytes hex
    assert_eq!(req_obj["receipt"].as_bool().unwrap(), false);

    println!("✅ All fields present and correctly formatted!");
}

#[tokio::test]
#[ignore]
async fn test_raw_submit_commitment() {
    use reqwest::Client;
    use serde_json::json;
    use unicity_sdk::crypto::KeyPair;
    use unicity_sdk::types::commitment::MintCommitment;
    use unicity_sdk::types::predicate::UnmaskedPredicate;
    use unicity_sdk::types::token::{TokenState, TokenType};
    use unicity_sdk::types::transaction::MintTransactionData;

    let aggregator_url = "https://goggregator-test.unicity.network";

    // Create a test commitment
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let signing_key = key_pair.secret_key();
    let public_key = key_pair.public_key().clone();

    let predicate = UnmaskedPredicate::new(public_key.clone());
    let target_state = TokenState::from_predicate(&predicate, None).expect("Failed to create state");

    let mint_data = MintTransactionData::new(
        TokenType::new(vec![1, 2, 3, 4]),
        target_state,
        Some(vec![5, 6, 7, 8]),
        None,
    );

    let commitment = MintCommitment::create(mint_data, signing_key)
        .expect("Failed to create commitment");

    // Convert to DTO
    let auth_dto = AuthenticatorDto::from(&commitment.authenticator);

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
        "params": params
    });

    println!("Sending submit_commitment to {}", aggregator_url);
    println!("Request params: {}", serde_json::to_string_pretty(&params).unwrap());

    let client = Client::new();
    let response = client
        .post(aggregator_url)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response");

    println!("\nResponse status: {}", status);
    println!("Response body: {}", body);

    // Parse to understand structure
    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&body) {
        println!("\nParsed response structure:");
        println!("{}", serde_json::to_string_pretty(&json_value).unwrap());

        // Check if it's an error response
        if let Some(error) = json_value.get("error") {
            println!("\n❌ JSON-RPC Error:");
            println!("{}", serde_json::to_string_pretty(error).unwrap());
        } else if let Some(result) = json_value.get("result") {
            println!("\n✅ JSON-RPC Result:");
            println!("{}", serde_json::to_string_pretty(result).unwrap());
        }
    }
}

#[tokio::test]
async fn test_raw_json_rpc_call() {
    use reqwest::Client;
    use serde_json::json;

    let aggregator_url = "https://goggregator-test.unicity.network";

    // Test get_block_height with raw JSON-RPC
    let client = Client::new();

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "get_block_height",
        "params": {}
    });

    println!("Sending raw JSON-RPC request to {}", aggregator_url);
    println!("Request: {}", serde_json::to_string_pretty(&request).unwrap());

    let response = client
        .post(aggregator_url)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response");

    println!("Response status: {}", status);
    println!("Response body: {}", body);

    // Parse to understand structure
    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&body) {
        println!("\nParsed response structure:");
        println!("{}", serde_json::to_string_pretty(&json_value).unwrap());
    }
}