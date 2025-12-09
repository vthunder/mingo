use sbo_core::crypto::SigningKey;
use sbo_core::presets;

#[test]
fn test_generate_genesis_batch() {
    let signing_key = SigningKey::generate();
    let batch = presets::genesis(&signing_key);

    // Parse as batch - should contain 2 messages
    let messages = sbo_core::wire::parse_batch(&batch).unwrap();
    assert_eq!(messages.len(), 2);

    // First should be sys identity
    let sys = &messages[0];
    assert_eq!(sys.path.to_string(), "/sys/names/");
    assert_eq!(sys.id.as_str(), "sys");
    assert!(sbo_core::message::verify_message(sys).is_ok());

    // Second should be root policy
    let policy = &messages[1];
    assert_eq!(policy.path.to_string(), "/sys/policies/");
    assert_eq!(policy.id.as_str(), "root");
    assert!(sbo_core::message::verify_message(policy).is_ok());
}
