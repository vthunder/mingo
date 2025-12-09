#[test]
fn test_parse_single_header() {
    let line = b"Content-Type: application/json";
    let (name, value) = sbo_core::wire::parse_header_line(line).unwrap();
    assert_eq!(name, "Content-Type");
    assert_eq!(value, "application/json");
}

#[test]
fn test_parse_header_rejects_crlf() {
    let line = b"Content-Type: application/json\r";
    let result = sbo_core::wire::parse_header_line(line);
    assert!(result.is_err());
}

#[test]
fn test_split_message() {
    let msg = b"SBO-Version: 0.5\nAction: post\n\n{\"hello\":\"world\"}";
    let (headers, payload) = sbo_core::wire::split_message(msg).unwrap();
    assert_eq!(headers.len(), 2);
    assert_eq!(payload, b"{\"hello\":\"world\"}");
}

#[test]
fn test_split_message_no_blank_line() {
    let msg = b"SBO-Version: 0.5\nAction: post";
    let result = sbo_core::wire::split_message(msg);
    assert!(result.is_err());
}

#[test]
fn test_parse_minimal_message() {
    let msg = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: hello\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 17\n\
Content-Hash: sha256:4b7a3c8f2e1d5a9b0c6e3f7a2d4b8c1e5f9a3d7b0c4e8f2a6d9b3c7e1f5a9d3b\n\
Signing-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{\"hello\":\"world\"}";

    let result = sbo_core::wire::parse(msg);
    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let message = result.unwrap();
    assert_eq!(message.path.to_string(), "/test/");
    assert_eq!(message.id.as_str(), "hello");
}

#[test]
fn test_roundtrip_message() {
    let msg = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: hello\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 17\n\
Content-Hash: sha256:4d7953c30e8f2c3a7b6d0f1e5a9c8b2d4f6e3a1b0c9d8e7f6a5b4c3d2e1f0a9b\n\
Signing-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{\"hello\":\"world\"}";

    let msg_parsed = sbo_core::wire::parse(msg).unwrap();
    let serialized = sbo_core::wire::serialize(&msg_parsed);
    let reparsed = sbo_core::wire::parse(&serialized).unwrap();

    assert_eq!(msg_parsed.path.to_string(), reparsed.path.to_string());
    assert_eq!(msg_parsed.id.as_str(), reparsed.id.as_str());
}
