use sbo_core::wire::HeaderMap;

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
