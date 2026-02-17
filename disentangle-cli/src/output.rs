use clap::ValueEnum;
use serde_json::Value;

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

impl OutputFormat {
    pub fn print(&self, value: &Value) {
        match self {
            OutputFormat::Human => print_human(value),
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value).unwrap()),
        }
    }
}

fn print_human(value: &Value) {
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                match val {
                    Value::String(s) => println!("{}: {}", key, s),
                    Value::Number(n) => println!("{}: {}", key, n),
                    Value::Bool(b) => println!("{}: {}", key, b),
                    Value::Array(arr) => {
                        println!("{}:", key);
                        for item in arr {
                            println!("  - {}", format_value(item));
                        }
                    }
                    Value::Object(_) => {
                        println!("{}:", key);
                        print_nested(val, 2);
                    }
                    Value::Null => println!("{}: null", key),
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                println!("{}", format_value(item));
            }
        }
        _ => println!("{}", format_value(value)),
    }
}

fn print_nested(value: &Value, indent: usize) {
    let prefix = " ".repeat(indent);
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                match val {
                    Value::String(s) => println!("{}{}: {}", prefix, key, s),
                    Value::Number(n) => println!("{}{}: {}", prefix, key, n),
                    Value::Bool(b) => println!("{}{}: {}", prefix, key, b),
                    Value::Array(arr) => {
                        println!("{}{}:", prefix, key);
                        for item in arr {
                            println!("{}  - {}", prefix, format_value(item));
                        }
                    }
                    Value::Object(_) => {
                        println!("{}{}:", prefix, key);
                        print_nested(val, indent + 2);
                    }
                    Value::Null => println!("{}{}: null", prefix, key),
                }
            }
        }
        _ => println!("{}{}", prefix, format_value(value)),
    }
}

fn format_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Object(_) | Value::Array(_) => {
            serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_format_pretty_prints_object() {
        let value = json!({"did": "did:disentangle:abc", "status": "active"});
        let formatted = serde_json::to_string_pretty(&value).unwrap();
        assert!(formatted.contains("did:disentangle:abc"));
        assert!(formatted.contains("active"));
        // Verify it's valid JSON round-trip
        let reparsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(reparsed, value);
    }

    #[test]
    fn json_format_pretty_prints_array() {
        let value = json!([1, 2, 3]);
        let formatted = serde_json::to_string_pretty(&value).unwrap();
        let reparsed: Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(reparsed, value);
    }

    #[test]
    fn format_value_string() {
        assert_eq!(format_value(&json!("hello")), "hello");
    }

    #[test]
    fn format_value_number() {
        assert_eq!(format_value(&json!(42)), "42");
        assert_eq!(format_value(&json!(1.5)), "1.5");
    }

    #[test]
    fn format_value_bool() {
        assert_eq!(format_value(&json!(true)), "true");
        assert_eq!(format_value(&json!(false)), "false");
    }

    #[test]
    fn format_value_null() {
        assert_eq!(format_value(&json!(null)), "null");
    }

    #[test]
    fn format_value_object_returns_json_string() {
        let val = json!({"a": 1});
        let result = format_value(&val);
        // Should be valid compact JSON
        let reparsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(reparsed, val);
    }

    #[test]
    fn format_value_array_returns_json_string() {
        let val = json!([1, "two", true]);
        let result = format_value(&val);
        let reparsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(reparsed, val);
    }

    #[test]
    fn output_format_value_enum_parses_human() {
        // clap ValueEnum parsing
        let human = OutputFormat::from_str("human", false).unwrap();
        assert!(matches!(human, OutputFormat::Human));
    }

    #[test]
    fn output_format_value_enum_parses_json() {
        let json_fmt = OutputFormat::from_str("json", false).unwrap();
        assert!(matches!(json_fmt, OutputFormat::Json));
    }

    #[test]
    fn output_format_value_enum_rejects_invalid() {
        assert!(OutputFormat::from_str("xml", false).is_err());
    }

    /// print() should not panic for any Value variant.
    #[test]
    fn human_print_does_not_panic_on_object() {
        let format = OutputFormat::Human;
        let value = json!({"name": "alice", "age": 30, "active": true});
        // Just verify it doesn't panic -- output goes to stdout
        format.print(&value);
    }

    #[test]
    fn human_print_does_not_panic_on_array() {
        let format = OutputFormat::Human;
        let value = json!(["item1", "item2"]);
        format.print(&value);
    }

    #[test]
    fn human_print_does_not_panic_on_nested() {
        let format = OutputFormat::Human;
        let value = json!({
            "identity": {
                "did": "did:disentangle:abc",
                "created": 12345
            },
            "tags": ["alpha", "beta"],
            "verified": true,
            "metadata": null
        });
        format.print(&value);
    }

    #[test]
    fn human_print_does_not_panic_on_scalar() {
        let format = OutputFormat::Human;
        format.print(&json!("just a string"));
        format.print(&json!(42));
        format.print(&json!(null));
    }

    #[test]
    fn json_print_does_not_panic() {
        let format = OutputFormat::Json;
        let value = json!({"key": "value", "nested": {"a": [1,2,3]}});
        format.print(&value);
    }
}
