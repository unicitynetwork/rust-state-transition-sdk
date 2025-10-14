use unicity_sdk::client::aggregator::AggregatorClient;
use unicity_sdk::types::bft::{RootTrustBase, UnicityCertificate};
use unicity_sdk::types::commitment::MintCommitment;
use unicity_sdk::types::predicate::UnmaskedPredicate;
use unicity_sdk::types::token::{TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::crypto::KeyPair;
use std::time::Duration;

#[tokio::test]
#[ignore] // Run with: cargo test --test debug_certificate -- --ignored --nocapture
async fn test_debug_certificate_parsing() {
    println!("🔍 Debugging certificate parsing...");

    let aggregator_url = "https://goggregator-test.unicity.network";
    let client = AggregatorClient::new(aggregator_url.to_string())
        .expect("Failed to create aggregator client");

    // Load trust base
    let trust_base_json = include_str!("resources/trust-base.json");
    let trust_base = RootTrustBase::from_json(trust_base_json)
        .expect("Failed to load trust base");

    // Create a test token and mint it
    let key = KeyPair::generate().unwrap();
    let predicate = UnmaskedPredicate::new(key.public_key().clone());
    let state = TokenState::from_predicate(&predicate, None).unwrap();

    let token_id = TokenId::unique();
    let token_type = TokenType::new(b"DEBUG_TEST".to_vec());

    // Create recipient address from state hash
    let state_hash = state.hash().unwrap();
    let recipient = unicity_sdk::types::address::GenericAddress::direct(state_hash);

    let mint_data = MintTransactionData::new(
        token_id.clone(),
        token_type.clone(),
        None,  // token_data
        None,  // coin_data
        recipient,  // recipient address
        vec![0x01, 0x02, 0x03],  // salt (not Option)
        None,  // recipient_data_hash
        None,  // reason
    );

    let mint_commitment = MintCommitment::create(mint_data.clone())
        .expect("Failed to create mint commitment");

    // Submit and wait for inclusion proof
    println!("Submitting commitment...");
    let response = client.submit_commitment(&mint_commitment).await
        .expect("Failed to submit commitment");

    println!("Response status: {}", response.status);

    // Wait for inclusion proof with certificate
    println!("Waiting for inclusion proof with certificate...");
    let proof = client.wait_for_inclusion_proof(
        &mint_commitment.request_id,
        Duration::from_secs(10)
    ).await.expect("Failed to get inclusion proof");

    println!("Got inclusion proof!");

    if let Some(cert_data) = &proof.unicity_certificate {
        println!("Certificate data length: {} bytes", cert_data.len());

        // Try to parse as CBOR and show structure
        println!("\n📦 Raw certificate hex (first 100 bytes):");
        println!("{}", hex::encode(&cert_data[..cert_data.len().min(100)]));

        // Try to parse the certificate
        match UnicityCertificate::from_cbor(cert_data) {
            Ok(cert) => {
                println!("\n✅ Certificate parsed successfully!");
                println!("  Version: {}", cert.version);
                println!("  Input Record Round: {}", cert.input_record.round_number);
                println!("  Signatures count: {}", cert.unicity_seal.signatures.len());

                // Try to verify with trust base
                match cert.verify(&trust_base) {
                    Ok(valid) => println!("  Verification result: {}", valid),
                    Err(e) => println!("  Verification error: {:?}", e),
                }
            }
            Err(e) => {
                println!("\n❌ Failed to parse certificate: {:?}", e);

                // Try to debug the CBOR structure
                use ciborium::Value;
                match ciborium::from_reader::<Value, _>(cert_data.as_slice()) {
                    Ok(value) => {
                        println!("\n📋 CBOR structure:");
                        debug_cbor_value(&value, 0);
                    }
                    Err(e) => println!("Failed to parse as CBOR: {:?}", e),
                }
            }
        }
    } else {
        println!("No certificate in inclusion proof");
    }
}

fn debug_cbor_value(value: &ciborium::Value, indent: usize) {
    use ciborium::Value;
    let prefix = "  ".repeat(indent);

    match value {
        Value::Integer(i) => println!("{}Integer: {:?}", prefix, i),
        Value::Bytes(b) => println!("{}Bytes[{}]: {}", prefix, b.len(),
            if b.len() <= 8 { hex::encode(b) } else { format!("{}...", hex::encode(&b[..8])) }),
        Value::Text(s) => println!("{}Text: \"{}\"", prefix, s),
        Value::Array(arr) => {
            println!("{}Array[{}]:", prefix, arr.len());
            for (i, item) in arr.iter().enumerate() {
                println!("{}  [{}]:", prefix, i);
                debug_cbor_value(item, indent + 2);
            }
        }
        Value::Map(map) => {
            println!("{}Map[{}]:", prefix, map.len());
            for (k, v) in map {
                print!("{}  Key: ", prefix);
                debug_cbor_value(k, 0);
                print!("{}  Val: ", prefix);
                debug_cbor_value(v, 0);
            }
        }
        Value::Tag(tag, boxed_val) => {
            println!("{}Tag {}: ", prefix, tag);
            debug_cbor_value(boxed_val, indent + 1);
        }
        Value::Null => println!("{}Null", prefix),
        Value::Bool(b) => println!("{}Bool: {}", prefix, b),
        Value::Float(f) => println!("{}Float: {}", prefix, f),
        _ => println!("{}Unknown", prefix),
    }
}