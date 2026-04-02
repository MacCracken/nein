//! MCP tool building blocks for nein firewall management.
//!
//! Provides tool descriptors and request/response types for exposing
//! nein operations as MCP tools: `nein_status`, `nein_allow`, `nein_deny`,
//! `nein_list`.

use std::collections::HashMap;

use bote::{ToolDef, ToolSchema};
use serde::{Deserialize, Serialize};

/// Result from an MCP tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: String,
    #[serde(default)]
    pub is_error: bool,
}

impl ToolResult {
    #[must_use]
    pub fn ok(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_error: false,
        }
    }

    #[must_use]
    pub fn err(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_error: true,
        }
    }
}

// -- nein_status --

/// Request for `nein_status` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequest {}

/// Response for `nein_status` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub tables: Vec<String>,
    pub total_rules: usize,
    pub raw_ruleset: String,
}

// -- nein_allow --

/// Request for `nein_allow` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowRequest {
    /// Protocol: "tcp" or "udp".
    pub protocol: String,
    /// Port number to allow.
    pub port: u16,
    /// Source CIDR (optional, defaults to "any").
    #[serde(default)]
    pub source: Option<String>,
    /// Table to add the rule to.
    #[serde(default = "default_table")]
    pub table: String,
    /// Chain to add the rule to.
    #[serde(default = "default_input_chain")]
    pub chain: String,
}

fn default_table() -> String {
    "filter".to_string()
}

fn default_input_chain() -> String {
    "input".to_string()
}

// -- nein_deny --

/// Request for `nein_deny` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyRequest {
    /// Protocol: "tcp" or "udp".
    pub protocol: String,
    /// Port number to deny.
    pub port: u16,
    /// Source CIDR (optional, defaults to "any").
    #[serde(default)]
    pub source: Option<String>,
    /// Table to add the rule to.
    #[serde(default = "default_table")]
    pub table: String,
    /// Chain to add the rule to.
    #[serde(default = "default_input_chain")]
    pub chain: String,
}

// -- nein_list --

/// Request for `nein_list` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRequest {
    /// Optional table filter.
    #[serde(default)]
    pub table: Option<String>,
    /// Optional chain filter.
    #[serde(default)]
    pub chain: Option<String>,
}

/// A rule entry in a list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEntry {
    pub table: String,
    pub chain: String,
    pub rule: String,
    #[serde(default)]
    pub handle: Option<u64>,
}

/// Response for `nein_list` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub rules: Vec<ListEntry>,
    pub count: usize,
}

// -- Tool descriptors --

/// Return MCP tool descriptors for all nein tools.
#[must_use]
pub fn tool_descriptors() -> Vec<ToolDef> {
    vec![
        ToolDef::new(
            "nein_status",
            "Get current nftables firewall status — tables, rule count, raw ruleset",
            ToolSchema::new("object", HashMap::new(), vec![]),
        ),
        ToolDef::new(
            "nein_allow",
            "Allow traffic on a port — adds an accept rule to the firewall",
            ToolSchema::new(
                "object",
                HashMap::from([
                    (
                        "protocol".into(),
                        serde_json::json!({"type": "string", "enum": ["tcp", "udp"]}),
                    ),
                    (
                        "port".into(),
                        serde_json::json!({"type": "integer", "minimum": 1, "maximum": 65535}),
                    ),
                    (
                        "source".into(),
                        serde_json::json!({"type": "string", "description": "Source CIDR (optional)"}),
                    ),
                    (
                        "table".into(),
                        serde_json::json!({"type": "string", "default": "filter"}),
                    ),
                    (
                        "chain".into(),
                        serde_json::json!({"type": "string", "default": "input"}),
                    ),
                ]),
                vec!["protocol".into(), "port".into()],
            ),
        ),
        ToolDef::new(
            "nein_deny",
            "Deny traffic on a port — adds a drop rule to the firewall",
            ToolSchema::new(
                "object",
                HashMap::from([
                    (
                        "protocol".into(),
                        serde_json::json!({"type": "string", "enum": ["tcp", "udp"]}),
                    ),
                    (
                        "port".into(),
                        serde_json::json!({"type": "integer", "minimum": 1, "maximum": 65535}),
                    ),
                    (
                        "source".into(),
                        serde_json::json!({"type": "string", "description": "Source CIDR (optional)"}),
                    ),
                    (
                        "table".into(),
                        serde_json::json!({"type": "string", "default": "filter"}),
                    ),
                    (
                        "chain".into(),
                        serde_json::json!({"type": "string", "default": "input"}),
                    ),
                ]),
                vec!["protocol".into(), "port".into()],
            ),
        ),
        ToolDef::new(
            "nein_list",
            "List current firewall rules, optionally filtered by table/chain",
            ToolSchema::new(
                "object",
                HashMap::from([
                    (
                        "table".into(),
                        serde_json::json!({"type": "string", "description": "Filter by table name"}),
                    ),
                    (
                        "chain".into(),
                        serde_json::json!({"type": "string", "description": "Filter by chain name"}),
                    ),
                ]),
                vec![],
            ),
        ),
    ]
}

/// Build the nft rule string for an allow request.
///
/// Validates the source CIDR if provided.
pub fn build_allow_rule(req: &AllowRequest) -> Result<String, String> {
    crate::validate::validate_identifier(&req.table).map_err(|e| e.to_string())?;
    crate::validate::validate_identifier(&req.chain).map_err(|e| e.to_string())?;
    let proto = parse_protocol(&req.protocol)?;
    let mut parts = vec![format!("{proto} dport {}", req.port)];
    if let Some(src) = &req.source {
        validate_source(src)?;
        parts.insert(0, format!("ip saddr {src}"));
    }
    parts.push("accept".to_string());
    parts.push(format!("comment \"nein_allow {proto} {}\"", req.port));
    Ok(parts.join(" "))
}

/// Build the nft rule string for a deny request.
///
/// Validates the source CIDR if provided.
pub fn build_deny_rule(req: &DenyRequest) -> Result<String, String> {
    crate::validate::validate_identifier(&req.table).map_err(|e| e.to_string())?;
    crate::validate::validate_identifier(&req.chain).map_err(|e| e.to_string())?;
    let proto = parse_protocol(&req.protocol)?;
    let mut parts = vec![format!("{proto} dport {}", req.port)];
    if let Some(src) = &req.source {
        validate_source(src)?;
        parts.insert(0, format!("ip saddr {src}"));
    }
    parts.push("drop".to_string());
    parts.push(format!("comment \"nein_deny {proto} {}\"", req.port));
    Ok(parts.join(" "))
}

fn validate_source(s: &str) -> Result<(), String> {
    crate::validate::validate_addr(s).map_err(|e| e.to_string())
}

fn parse_protocol(s: &str) -> Result<&str, String> {
    match s {
        "tcp" | "udp" => Ok(s),
        _ => Err(format!("unsupported protocol: {s} (use tcp or udp)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_descriptors_count() {
        let tools = tool_descriptors();
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"nein_status"));
        assert!(names.contains(&"nein_allow"));
        assert!(names.contains(&"nein_deny"));
        assert!(names.contains(&"nein_list"));
    }

    #[test]
    fn tool_result_ok() {
        let r = ToolResult::ok("success");
        assert!(!r.is_error);
        assert_eq!(r.content, "success");
    }

    #[test]
    fn tool_result_err() {
        let r = ToolResult::err("failed");
        assert!(r.is_error);
        assert_eq!(r.content, "failed");
    }

    #[test]
    fn build_allow_rule_tcp() {
        let req = AllowRequest {
            protocol: "tcp".to_string(),
            port: 443,
            source: None,
            table: "filter".to_string(),
            chain: "input".to_string(),
        };
        let rule = build_allow_rule(&req).unwrap();
        assert_eq!(rule, "tcp dport 443 accept comment \"nein_allow tcp 443\"");
    }

    #[test]
    fn build_allow_rule_with_source() {
        let req = AllowRequest {
            protocol: "tcp".to_string(),
            port: 80,
            source: Some("10.0.0.0/8".to_string()),
            table: "filter".to_string(),
            chain: "input".to_string(),
        };
        let rule = build_allow_rule(&req).unwrap();
        assert!(rule.starts_with("ip saddr 10.0.0.0/8"));
        assert!(rule.contains("tcp dport 80 accept"));
    }

    #[test]
    fn build_deny_rule_udp() {
        let req = DenyRequest {
            protocol: "udp".to_string(),
            port: 53,
            source: None,
            table: "filter".to_string(),
            chain: "input".to_string(),
        };
        let rule = build_deny_rule(&req).unwrap();
        assert_eq!(rule, "udp dport 53 drop comment \"nein_deny udp 53\"");
    }

    #[test]
    fn build_deny_rule_with_source() {
        let req = DenyRequest {
            protocol: "tcp".to_string(),
            port: 22,
            source: Some("192.168.0.0/16".to_string()),
            table: "filter".to_string(),
            chain: "input".to_string(),
        };
        let rule = build_deny_rule(&req).unwrap();
        assert!(rule.starts_with("ip saddr 192.168.0.0/16"));
        assert!(rule.contains("drop"));
    }

    #[test]
    fn build_rule_bad_protocol() {
        let req = AllowRequest {
            protocol: "icmp".to_string(),
            port: 0,
            source: None,
            table: "filter".to_string(),
            chain: "input".to_string(),
        };
        assert!(build_allow_rule(&req).is_err());
    }

    #[test]
    fn status_request_deserialize() {
        let json = "{}";
        let _req: StatusRequest = serde_json::from_str(json).unwrap();
    }

    #[test]
    fn allow_request_defaults() {
        let json = r#"{"protocol": "tcp", "port": 80}"#;
        let req: AllowRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.table, "filter");
        assert_eq!(req.chain, "input");
        assert!(req.source.is_none());
    }

    #[test]
    fn list_request_optional_fields() {
        let json = "{}";
        let req: ListRequest = serde_json::from_str(json).unwrap();
        assert!(req.table.is_none());
        assert!(req.chain.is_none());
    }

    #[test]
    fn tool_schemas_are_valid() {
        for tool in tool_descriptors() {
            assert_eq!(tool.input_schema.schema_type, "object");
            assert!(!tool.description.is_empty());
        }
    }

    #[test]
    fn tool_descriptor_serializes() {
        let tools = tool_descriptors();
        let json = serde_json::to_string(&tools).unwrap();
        assert!(json.contains("nein_status"));
        assert!(json.contains("nein_allow"));
    }

    #[test]
    fn tool_descriptor_serde_roundtrip() {
        let tool = &tool_descriptors()[0];
        let json = serde_json::to_string(tool).unwrap();
        let back: ToolDef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, tool.name);
    }

    #[test]
    fn build_allow_bad_source() {
        let req = AllowRequest {
            protocol: "tcp".to_string(),
            port: 80,
            source: Some("evil;injection".to_string()),
            table: "filter".to_string(),
            chain: "input".to_string(),
        };
        assert!(build_allow_rule(&req).is_err());
    }

    #[test]
    fn build_deny_bad_source() {
        let req = DenyRequest {
            protocol: "tcp".to_string(),
            port: 22,
            source: Some("not an addr!".to_string()),
            table: "filter".to_string(),
            chain: "input".to_string(),
        };
        assert!(build_deny_rule(&req).is_err());
    }

    #[test]
    fn protocol_case_sensitive() {
        let req = AllowRequest {
            protocol: "TCP".to_string(),
            port: 80,
            source: None,
            table: "filter".to_string(),
            chain: "input".to_string(),
        };
        assert!(build_allow_rule(&req).is_err());
    }

    #[test]
    fn deny_request_defaults() {
        let json = r#"{"protocol": "tcp", "port": 22}"#;
        let req: DenyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.table, "filter");
        assert_eq!(req.chain, "input");
        assert!(req.source.is_none());
    }

    #[test]
    fn list_response_serializes() {
        let resp = ListResponse {
            rules: vec![ListEntry {
                table: "filter".to_string(),
                chain: "input".to_string(),
                rule: "tcp dport 80 accept".to_string(),
                handle: Some(42),
            }],
            count: 1,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"handle\":42"));
        assert!(json.contains("\"count\":1"));
    }

    #[test]
    fn status_response_serializes() {
        let resp = StatusResponse {
            tables: vec!["inet filter".to_string()],
            total_rules: 5,
            raw_ruleset: "table inet filter {...}".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("inet filter"));
        assert!(json.contains("\"total_rules\":5"));
    }
}
