use std::path::{Path, PathBuf};
use std::fs;

const KEYS_DIR: &str = ".disentangle/keys";

pub fn keys_dir() -> PathBuf {
    let home = dirs::home_dir().expect("Could not find home directory");
    home.join(KEYS_DIR)
}

/// Save a signing key for the given DID into the specified directory.
pub fn save_key_in(dir: &Path, did: &str, signing_key_hex: &str) -> Result<(), std::io::Error> {
    fs::create_dir_all(dir)?;
    let safe_name = did.replace([':', '/'], "_");
    let path = dir.join(format!("{}.key", safe_name));
    fs::write(&path, signing_key_hex)?;
    // Set file permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load a signing key for the given DID from the specified directory.
pub fn load_key_in(dir: &Path, did: &str) -> Result<Option<String>, std::io::Error> {
    let safe_name = did.replace([':', '/'], "_");
    let path = dir.join(format!("{}.key", safe_name));
    if path.exists() {
        Ok(Some(fs::read_to_string(&path)?.trim().to_string()))
    } else {
        Ok(None)
    }
}

/// List all stored DIDs in the specified directory.
pub fn list_stored_dids_in(dir: &Path) -> Result<Vec<String>, std::io::Error> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut dids = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if name.ends_with(".key") {
                let did = name.trim_end_matches(".key").replace('_', ":");
                dids.push(did);
            }
        }
    }
    Ok(dids)
}

// --- Public convenience API (uses default keys_dir) ---

pub fn save_key(did: &str, signing_key_hex: &str) -> Result<(), std::io::Error> {
    save_key_in(&keys_dir(), did, signing_key_hex)
}

pub fn load_key(did: &str) -> Result<Option<String>, std::io::Error> {
    load_key_in(&keys_dir(), did)
}

pub fn list_stored_dids() -> Result<Vec<String>, std::io::Error> {
    list_stored_dids_in(&keys_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn save_then_load_returns_same_key() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");

        let did = "did:disentangle:abc123";
        let key_hex = "deadbeef01020304";

        save_key_in(&dir, did, key_hex).unwrap();
        let loaded = load_key_in(&dir, did).unwrap();
        assert_eq!(loaded, Some(key_hex.to_string()));
    }

    #[test]
    fn load_nonexistent_key_returns_none() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");
        // Don't save anything -- directory doesn't even exist yet.
        let loaded = load_key_in(&dir, "did:disentangle:nonexistent").unwrap();
        assert_eq!(loaded, None);
    }

    #[test]
    fn list_stored_dids_returns_saved_dids() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");

        save_key_in(&dir, "did:disentangle:alice", "aaa").unwrap();
        save_key_in(&dir, "did:disentangle:bob", "bbb").unwrap();

        let mut dids = list_stored_dids_in(&dir).unwrap();
        dids.sort();
        assert_eq!(dids.len(), 2);
        assert!(dids.contains(&"did:disentangle:alice".to_string()));
        assert!(dids.contains(&"did:disentangle:bob".to_string()));
    }

    #[test]
    fn list_stored_dids_empty_dir_returns_empty_vec() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("nonexistent_keys");
        let dids = list_stored_dids_in(&dir).unwrap();
        assert!(dids.is_empty());
    }

    #[test]
    fn save_key_overwrites_existing() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");

        let did = "did:disentangle:overwrite_test";
        save_key_in(&dir, did, "old_key").unwrap();
        save_key_in(&dir, did, "new_key").unwrap();

        let loaded = load_key_in(&dir, did).unwrap();
        assert_eq!(loaded, Some("new_key".to_string()));
    }

    #[test]
    fn did_with_special_characters_is_sanitized() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");

        // DID contains colons and slashes which are replaced by underscores
        let did = "did:disentangle:ns/path:sub";
        let key_hex = "cafebabe";

        save_key_in(&dir, did, key_hex).unwrap();

        // The file should exist with underscores
        let expected_file = dir.join("did_disentangle_ns_path_sub.key");
        assert!(expected_file.exists());

        // Loading by the original DID should work
        let loaded = load_key_in(&dir, did).unwrap();
        assert_eq!(loaded, Some(key_hex.to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn saved_key_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");

        save_key_in(&dir, "did:disentangle:perms", "secret").unwrap();

        let path = dir.join("did_disentangle_perms.key");
        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
