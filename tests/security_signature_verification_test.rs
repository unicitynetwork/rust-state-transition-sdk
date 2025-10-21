/// Security tests for signature verification
/// This ensures that forged/invalid signatures are properly rejected.

use unicity_sdk::crypto::{KeyPair, SigningService};
use unicity_sdk::types::predicate::{MaskedPredicate, UnmaskedPredicate, Predicate};
use unicity_sdk::types::primitives::DataHash;
use unicity_sdk::types::transaction::Authenticator;

#[test]
fn test_security_unmasked_predicate_rejects_invalid_signature() {
    // Verify that an invalid signature is rejected
    let key_pair = KeyPair::generate().unwrap();
    let public_key = key_pair.public_key().clone();
    let predicate = UnmaskedPredicate::new(public_key.clone());

    // Create a transaction hash
    let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

    // Create an INVALID signature (random bytes)
    let invalid_signature = vec![0xFF; 65];

    // Create authenticator with invalid signature
    let authenticator = Authenticator::new(
        "secp256k1".to_string(),
        public_key.as_bytes().to_vec(),
        invalid_signature,
        tx_hash.clone(),
    );

    // Verify - should REJECT the invalid signature
    let result = predicate.verify(&authenticator, &tx_hash, None);

    // Before the fix, this might have passed (only checking public key)
    // After the fix, this MUST fail (signature verification fails or returns error for malformed signature)
    // Either Ok(false) or Err is acceptable - both mean rejection
    match result {
        Ok(verified) => assert!(!verified, "Invalid signature was accepted!"),
        Err(_) => {}, // Also acceptable - malformed signature causes error
    }
}

#[test]
fn test_security_unmasked_predicate_rejects_wrong_signer() {
    // Verify that a transaction signed by the wrong private key is rejected

    // Alice's key pair - the legitimate owner
    let alice_key = KeyPair::generate().unwrap();
    let alice_public_key = alice_key.public_key().clone();
    let predicate = UnmaskedPredicate::new(alice_public_key.clone());

    // Bob's key pair - the attacker
    let bob_key = KeyPair::generate().unwrap();
    let bob_public_key = bob_key.public_key().clone();

    // Create a transaction hash
    let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

    // Bob signs the transaction (trying to impersonate Alice)
    let signing_service = SigningService::new();
    let bob_signature = signing_service.sign(tx_hash.data(), bob_key.secret_key()).unwrap();

    // Bob creates an authenticator claiming to be Alice
    let forged_authenticator = Authenticator::new(
        "secp256k1".to_string(),
        alice_public_key.as_bytes().to_vec(),  // Claims to be Alice
        bob_signature.as_bytes().to_vec(),      // But signed by Bob
        tx_hash.clone(),
    );

    // Verify - should REJECT the forged signature
    let result = predicate.verify(&forged_authenticator, &tx_hash, None);

    // This MUST fail - the signature doesn't match the claimed public key
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Forged signature from wrong signer was accepted!");
}

#[test]
fn test_security_unmasked_predicate_rejects_tampered_transaction_data() {
    // Verify that tampering with transaction data invalidates the signature

    let key_pair = KeyPair::generate().unwrap();
    let public_key = key_pair.public_key().clone();
    let predicate = UnmaskedPredicate::new(public_key.clone());

    // Create original transaction hash and sign it
    let original_tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);
    let signing_service = SigningService::new();
    let signature = signing_service.sign(original_tx_hash.data(), key_pair.secret_key()).unwrap();

    // Create authenticator with the original signature
    let authenticator = Authenticator::new(
        "secp256k1".to_string(),
        public_key.as_bytes().to_vec(),
        signature.as_bytes().to_vec(),
        original_tx_hash.clone(),
    );

    // Attacker tampers with the transaction data
    let tampered_tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 99]);  // Changed last byte

    // Verify with tampered data - should REJECT
    let result = predicate.verify(&authenticator, &tampered_tx_hash, None);

    // This MUST fail - the signature is for the original data, not the tampered data
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Signature accepted for tampered transaction data!");
}

#[test]
fn test_security_masked_predicate_rejects_invalid_signature() {
    // Verify that masked predicates also reject invalid signatures

    let key_pair = KeyPair::generate().unwrap();
    let public_key = key_pair.public_key().clone();
    let nonce = b"secret_nonce_12345";
    let predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, nonce);

    // Create a transaction hash
    let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

    // Create an INVALID signature (random bytes)
    let invalid_signature = vec![0xAA; 65];

    // Create authenticator with invalid signature but correct public key
    let authenticator = Authenticator::new(
        "secp256k1".to_string(),
        public_key.as_bytes().to_vec(),
        invalid_signature,
        tx_hash.clone(),
    );

    // Verify - should REJECT the invalid signature even though nonce is correct
    let result = predicate.verify(&authenticator, &tx_hash, Some(nonce));

    match result {
        Ok(verified) => assert!(!verified, "Invalid signature was accepted by masked predicate!"),
        Err(_) => {}, // Also acceptable - malformed signature causes error
    }
}

#[test]
fn test_security_masked_predicate_rejects_wrong_signer_even_with_correct_nonce() {
    // Even if attacker knows the nonce, they can't forge signatures

    // Alice's key pair - the legitimate owner
    let alice_key = KeyPair::generate().unwrap();
    let alice_public_key = alice_key.public_key().clone();
    let nonce = b"secret_nonce_12345";
    let predicate = MaskedPredicate::from_public_key_and_nonce(&alice_public_key, nonce);

    // Bob's key pair - the attacker who somehow learned the nonce
    let bob_key = KeyPair::generate().unwrap();

    // Create a transaction hash
    let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

    // Bob signs the transaction
    let signing_service = SigningService::new();
    let bob_signature = signing_service.sign(tx_hash.data(), bob_key.secret_key()).unwrap();

    // Bob tries to use Alice's public key with his signature
    let forged_authenticator = Authenticator::new(
        "secp256k1".to_string(),
        alice_public_key.as_bytes().to_vec(),  // Claims to be Alice
        bob_signature.as_bytes().to_vec(),      // But signed by Bob
        tx_hash.clone(),
    );

    // Verify - should REJECT even though nonce is correct
    let result = predicate.verify(&forged_authenticator, &tx_hash, Some(nonce));

    // This MUST fail - knowing the nonce doesn't help if you can't produce valid signature
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Forged signature accepted with correct nonce!");
}

#[test]
fn test_security_valid_signature_passes() {
    // Verify that valid signatures still work correctly

    let key_pair = KeyPair::generate().unwrap();
    let public_key = key_pair.public_key().clone();
    let predicate = UnmaskedPredicate::new(public_key.clone());

    // Create a transaction hash and properly sign it
    let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);
    let signing_service = SigningService::new();
    let signature = signing_service.sign(tx_hash.data(), key_pair.secret_key()).unwrap();

    // Create properly signed authenticator
    let authenticator = Authenticator::new(
        "secp256k1".to_string(),
        public_key.as_bytes().to_vec(),
        signature.as_bytes().to_vec(),
        tx_hash.clone(),
    );

    // Verify - should ACCEPT the valid signature
    let result = predicate.verify(&authenticator, &tx_hash, None);

    assert!(result.is_ok());
    assert!(result.unwrap(), "Valid signature should be accepted!");
}

#[test]
fn test_security_masked_predicate_valid_signature_passes() {
    // Verify that masked predicates accept valid signatures with correct nonce

    let key_pair = KeyPair::generate().unwrap();
    let public_key = key_pair.public_key().clone();
    let nonce = b"secret_nonce_12345";
    let predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, nonce);

    // Create a transaction hash and properly sign it
    let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);
    let signing_service = SigningService::new();
    let signature = signing_service.sign(tx_hash.data(), key_pair.secret_key()).unwrap();

    // Create properly signed authenticator
    let authenticator = Authenticator::new(
        "secp256k1".to_string(),
        public_key.as_bytes().to_vec(),
        signature.as_bytes().to_vec(),
        tx_hash.clone(),
    );

    // Verify - should ACCEPT with valid signature and correct nonce
    let result = predicate.verify(&authenticator, &tx_hash, Some(nonce));

    assert!(result.is_ok());
    assert!(result.unwrap(), "Valid signature with correct nonce should be accepted!");
}
