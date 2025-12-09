//! Wire format serializer

use crate::message::{Message, ObjectType};

/// Canonical header order per Wire Format spec
const HEADER_ORDER: &[&str] = &[
    "SBO-Version",
    "Action",
    "Path",
    "ID",
    "Type",
    "Content-Type",
    "Content-Encoding",
    "Content-Length",
    "Content-Hash",
    "Attestation",
    "Content-Schema",
    "Creator",
    "New-ID",
    "New-Owner",
    "New-Path",
    "Object-Path",
    "Origin",
    "Owner",
    "Policy-Ref",
    "Proof",
    "Proof-Type",
    "Registry-Path",
    "Related",
    "Signing-Key",
    "Signature",
];

/// Serialize a Message to wire format bytes
pub fn serialize(msg: &Message) -> Vec<u8> {
    let mut headers: Vec<(String, String)> = Vec::new();

    headers.push(("SBO-Version".to_string(), "0.5".to_string()));
    headers.push(("Action".to_string(), msg.action.name().to_string()));
    headers.push(("Path".to_string(), msg.path.to_string()));
    headers.push(("ID".to_string(), msg.id.as_str().to_string()));
    headers.push(("Type".to_string(), match msg.object_type {
        ObjectType::Object => "object",
        ObjectType::Collection => "collection",
    }.to_string()));

    if let Some(ref ct) = msg.content_type {
        headers.push(("Content-Type".to_string(), ct.clone()));
    }
    if let Some(ref ce) = msg.content_encoding {
        headers.push(("Content-Encoding".to_string(), ce.clone()));
    }
    if let Some(ref payload) = msg.payload {
        headers.push(("Content-Length".to_string(), payload.len().to_string()));
    }
    if let Some(ref ch) = msg.content_hash {
        headers.push(("Content-Hash".to_string(), ch.to_string()));
    }
    if let Some(ref cs) = msg.content_schema {
        headers.push(("Content-Schema".to_string(), cs.clone()));
    }
    if let Some(ref creator) = msg.creator {
        headers.push(("Creator".to_string(), creator.as_str().to_string()));
    }
    if let Some(ref owner) = msg.owner {
        headers.push(("Owner".to_string(), owner.as_str().to_string()));
    }
    if let Some(ref pr) = msg.policy_ref {
        headers.push(("Policy-Ref".to_string(), pr.clone()));
    }

    headers.push(("Signing-Key".to_string(), msg.signing_key.to_string()));
    headers.push(("Signature".to_string(), msg.signature.to_hex()));

    // Sort by canonical order
    headers.sort_by_key(|(name, _)| {
        HEADER_ORDER.iter().position(|&h| h == name).unwrap_or(999)
    });

    // Build output
    let mut output = Vec::new();
    for (name, value) in headers {
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.push(b'\n');
    }
    output.push(b'\n');

    if let Some(ref payload) = msg.payload {
        output.extend_from_slice(payload);
    }

    output
}
