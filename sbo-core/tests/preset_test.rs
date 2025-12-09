use sbo_core::crypto::SigningKey;
use sbo_core::presets;

#[test]
fn test_generate_genesis_messages() {
    let signing_key = SigningKey::generate();
    let messages = presets::genesis(&signing_key);

    assert_eq!(messages.len(), 2);

    // First should be sys identity
    let sys = sbo_core::wire::parse(&messages[0]).unwrap();
    assert_eq!(sys.path.to_string(), "/sys/names/");
    assert_eq!(sys.id.as_str(), "sys");
    assert!(sbo_core::message::verify_message(&sys).is_ok());

    // Second should be root policy
    let policy = sbo_core::wire::parse(&messages[1]).unwrap();
    assert_eq!(policy.path.to_string(), "/sys/policies/");
    assert_eq!(policy.id.as_str(), "root");
    assert!(sbo_core::message::verify_message(&policy).is_ok());
}
