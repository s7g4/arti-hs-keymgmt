# Arti Onion Service Key Management Enhancements

This repository contains contributions made as part of the **Google Summer of Code 2025** under the **Tor Project**, focusing on enhancing **Onion Service Tooling** for the **Arti** Rust-based Tor client.

## 🛠️ Summary of Improvements

This work implements CLI subcommands to support robust **key** and **state management** for Onion Services in arti/crates/arti/src/key_management.rs, aimed at improving usability and security within the Arti ecosystem.

---

## 🔑 Key Management Enhancements

A set of CLI subcommands were added to simplify and secure key handling:

- `arti hs key create` – Generate encrypted key pairs for Onion Services.
- `arti hs key list` – Display available keys managed by the Arti client.
- `arti hs key import` – Import key files securely.
- `arti hs key export` – Export keys while maintaining cryptographic integrity.
- `arti hs key delete` – Delete unused or compromised keys.

### Benefits:
- Enhances usability for developers and operators.
- Simplifies migration from the legacy C-based Tor tools.
- Uses **`tor-crypto`** for secure cryptographic operations.

---

## 🗃️ State Management Enhancements

Introduced a reliable and developer-friendly set of commands to manage Onion Service state data:

- `arti hs state backup` – Backup current service state (keys, settings, metadata).
- `arti hs state restore` – Restore from a previously backed up state.
- `arti hs state reset` – Reset the Onion Service to a clean state.

### Benefits:
- Prevents service misconfiguration during upgrades or crashes.
- Enables reliable service migration.
- Adds support for automatic restoration workflows.

---

## ✅ Quality Assurance

- Developed and ran **unit tests** and **integration tests** to ensure the robustness of new commands.
- Manual **stress testing** and real-world validation with community feedback.
- Improved **error handling** and **user-facing output** for command feedback.

---

## 📚 Documentation

- User guide for each command is available in the help section via `--help`.
- Comments and module-level documentation added to ease further development.

---

## 🚀 Getting Started

```bash
# Example usage
arti hs key create --output ./keys/onion_key
arti hs state backup --path ./backup/
