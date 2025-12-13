#![cfg(feature = "serde")]

use sbo_types::id::Id;
use sbo_types::path::Path;
use sbo_types::action::Action;

#[test]
fn test_id_serde_roundtrip() {
    let id = Id::new("alice").unwrap();
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, r#""alice""#);

    let deserialized: Id = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, id);
}

#[test]
fn test_id_serde_validation() {
    // Invalid ID should fail during deserialization
    let result: Result<Id, _> = serde_json::from_str(r#""has space""#);
    assert!(result.is_err());
}

#[test]
fn test_path_serde_roundtrip() {
    let path = Path::parse("/alice/nfts/").unwrap();
    let json = serde_json::to_string(&path).unwrap();
    assert_eq!(json, r#""/alice/nfts/""#);

    let deserialized: Path = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, path);
}

#[test]
fn test_path_root_serde() {
    let path = Path::root();
    let json = serde_json::to_string(&path).unwrap();
    assert_eq!(json, r#""/""#);

    let deserialized: Path = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, path);
}

#[test]
fn test_path_serde_validation() {
    // Invalid path should fail during deserialization
    let result: Result<Path, _> = serde_json::from_str(r#""no-trailing-slash""#);
    assert!(result.is_err());
}

#[test]
fn test_action_serde_roundtrip() {
    let action = Action::Create;
    let json = serde_json::to_string(&action).unwrap();
    assert_eq!(json, r#""create""#);

    let deserialized: Action = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, action);
}

#[test]
fn test_all_actions_serde() {
    let actions = vec![
        (Action::Create, r#""create""#),
        (Action::Post, r#""post""#),
        (Action::Update, r#""update""#),
        (Action::Delete, r#""delete""#),
        (Action::Transfer, r#""transfer""#),
        (Action::Import, r#""import""#),
    ];

    for (action, expected_json) in actions {
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, expected_json);

        let deserialized: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, action);
    }
}
