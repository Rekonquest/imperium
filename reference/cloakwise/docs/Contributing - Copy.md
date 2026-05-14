# Contributing to Cloakwise

Thank you for your interest in contributing to Cloakwise! This guide will help you get started.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## Ways to Contribute

### Report Bugs

1. Check if the issue already exists
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected vs actual behavior
   - System information
   - Relevant logs

### Suggest Features

1. Open a feature request issue
2. Describe the use case
3. Explain why it would be valuable
4. Consider implementation approaches

### Submit Code

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write tests
5. Submit a pull request

## Development Setup

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies
sudo apt install build-essential pkg-config libssl-dev

# Clone the repo
git clone https://github.com/Rekonquest/Dynamic-VPN.git
cd Dynamic-VPN
```

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -- -c config.yaml
```

### Code Style

We use standard Rust formatting:

```bash
# Format code
cargo fmt

# Check lints
cargo clippy

# Both must pass before PR is accepted
```

## Pull Request Process

1. **Create a branch**
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make changes**
   - Keep commits focused and atomic
   - Write clear commit messages
   - Add tests for new functionality

3. **Run checks**
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```

4. **Push and create PR**
   ```bash
   git push origin feature/my-feature
   ```
   Then create a PR on GitHub.

5. **PR Description**
   - Describe what changes you made
   - Link related issues
   - Note any breaking changes

## Architecture Guidelines

### Adding New Protocols

1. Create file in `src/vpn/`
2. Implement `Outbound` trait
3. Register in `OutboundRegistry`
4. Add configuration options
5. Update setup wizard
6. Add documentation

```rust
// Example: src/vpn/myprotocol.rs
use crate::core::transport::{Outbound, TransportError};

pub struct MyProtocol {
    config: MyProtocolConfig,
}

#[async_trait]
impl Outbound for MyProtocol {
    fn protocol_id(&self) -> &str { "myprotocol" }
    fn display_name(&self) -> &str { "My Protocol" }
    // ... implement other methods
}
```

### Adding Security Tools

1. Create file in `src/security/`
2. Implement detection/response logic
3. Register with `SensorBus`
4. Add configuration options
5. Update documentation

### Adding Hardware Support

1. Implement `HardwareDevice` trait
2. Add detection logic in `hardware_detect.rs`
3. Register in HAL
4. Update setup wizard

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_function() {
        assert_eq!(my_function(), expected_value);
    }
}
```

### Integration Tests

Place in `tests/` directory:

```rust
// tests/integration_test.rs
use cloakwise::*;

#[tokio::test]
async fn test_protocol_switch() {
    // Setup
    let config = Config::default();
    let registry = OutboundRegistry::new();

    // Test
    registry.switch("cloak").await.unwrap();

    // Assert
    assert_eq!(registry.active().await, Some("cloak"));
}
```

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_my_function

# With output
cargo test -- --nocapture

# Integration tests only
cargo test --test integration_test
```

## Documentation

### Code Comments

```rust
/// Brief description of the function.
///
/// More detailed explanation if needed.
///
/// # Arguments
///
/// * `param` - Description of parameter
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// When and why this function returns an error
///
/// # Example
///
/// ```
/// let result = my_function(42);
/// assert_eq!(result, expected);
/// ```
pub fn my_function(param: i32) -> Result<i32, Error> {
    // ...
}
```

### Wiki Documentation

Update relevant wiki pages in `docs/` when adding features.

## Release Process

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md
3. Create release PR
4. After merge, tag release
5. GitHub Actions builds binaries

## License

By contributing, you agree that your contributions will be licensed under the project's license (BUSL-1.1, converting to Apache 2.0).

## Questions?

- Open a discussion on GitHub
- Check existing documentation
- Review similar issues/PRs

Thank you for contributing!
