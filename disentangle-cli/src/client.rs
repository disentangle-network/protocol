use serde_json::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Node error: {0}")]
    NodeError(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("No signing key provided. Use --signing-key-hex or --did to load from key storage.")]
    MissingKey,
    #[error("No stored key found for DID: {0}")]
    KeyNotFound(String),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type CliResult<T> = Result<T, CliError>;

pub struct NodeClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl NodeClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn get(&self, path: &str) -> CliResult<Value> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.get(&url).send()?;

        if !response.status().is_success() {
            return Err(CliError::NodeError(format!(
                "HTTP {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            )));
        }

        let json = response.json()?;
        Ok(json)
    }

    pub fn post(&self, path: &str, body: &Value) -> CliResult<Value> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.post(&url).json(body).send()?;

        if !response.status().is_success() {
            return Err(CliError::NodeError(format!(
                "HTTP {}: {}",
                response.status(),
                response.text().unwrap_or_default()
            )));
        }

        let json = response.json()?;
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_client_stores_base_url() {
        let client = NodeClient::new("http://localhost:9999");
        assert_eq!(client.base_url, "http://localhost:9999");
    }

    #[test]
    fn get_connection_refused_returns_request_failed_error() {
        // Use a port that almost certainly has nothing listening
        let client = NodeClient::new("http://127.0.0.1:19");
        let result = client.get("/status");
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::RequestFailed(e) => {
                // The reqwest error should indicate a connection problem
                let msg = e.to_string();
                assert!(
                    msg.contains("error") || msg.contains("connect") || msg.contains("Connection"),
                    "Expected connection error, got: {}", msg
                );
            }
            other => panic!("Expected CliError::RequestFailed, got: {:?}", other),
        }
    }

    #[test]
    fn post_connection_refused_returns_request_failed_error() {
        let client = NodeClient::new("http://127.0.0.1:19");
        let body = serde_json::json!({"test": true});
        let result = client.post("/submit", &body);
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::RequestFailed(_) => { /* expected */ }
            other => panic!("Expected CliError::RequestFailed, got: {:?}", other),
        }
    }

    #[test]
    fn cli_error_display_messages() {
        let err = CliError::NodeError("test error".to_string());
        assert_eq!(err.to_string(), "Node error: test error");

        let err = CliError::NotImplemented("feature X".to_string());
        assert_eq!(err.to_string(), "Not implemented: feature X");

        let err = CliError::MissingKey;
        assert!(err.to_string().contains("No signing key provided"));

        let err = CliError::KeyNotFound("did:disentangle:abc".to_string());
        assert!(err.to_string().contains("did:disentangle:abc"));
    }

    #[test]
    fn cli_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let cli_err: CliError = io_err.into();
        assert!(matches!(cli_err, CliError::IoError(_)));
        assert!(cli_err.to_string().contains("file not found"));
    }

    #[test]
    fn cli_error_from_serde_error() {
        let serde_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let cli_err: CliError = serde_err.into();
        assert!(matches!(cli_err, CliError::JsonError(_)));
    }
}
