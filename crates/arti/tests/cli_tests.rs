#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn test_keys_list() {
        let output = Command::new("arti")
            .arg("keys")
            .arg("list")
            .arg("--keystore")
            .arg("/path/to/keystore")
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
        // Additional assertions can be added based on expected output
    }

    #[test]
    fn test_keys_check() {
        let output = Command::new("arti")
            .arg("keys")
            .arg("check")
            .arg("--keystore")
            .arg("/path/to/keystore")
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
        // Additional assertions can be added based on expected output
    }

    #[test]
    fn test_keys_remove() {
        let output = Command::new("arti")
            .arg("keys")
            .arg("remove")
            .arg("--keystore")
            .arg("/path/to/keystore")
            .arg("--key")
            .arg("key_to_remove")
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
        // Additional assertions can be added based on expected output
    }

    #[test]
    fn test_hss_destroy() {
        let output = Command::new("arti")
            .arg("hss")
            .arg("destroy")
            .arg("--confirm")
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
        // Additional assertions can be added based on expected output
    }

    // Existing tests
    #[test]
    fn cli_tests() {
        // Existing test implementation
    }

    // Other existing tests...
}
