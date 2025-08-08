# Server Tester

A comprehensive server testing framework written in Rust that implements all major testing approaches for server applications.

## Features

### 🔧 **HTTP Client Testing**
- RESTful API testing (GET, POST, PUT, DELETE, etc.)
- Custom headers and authentication
- Response validation and timing
- Health check utilities

### ⚡ **Load Testing**
- Concurrent user simulation
- Configurable request patterns
- Ramp-up and think time controls
- Detailed performance metrics

### 🎯 **Performance Testing**
- Throughput measurement (RPS)
- Latency analysis (min, max, percentiles)
- Resource utilization monitoring
- Endurance and volume testing

### 🔒 **Security Testing**
- Authentication bypass detection
- Authorization testing
- Input validation checks
- SQL injection detection
- XSS vulnerability scanning
- CSRF protection testing
- Security header analysis
- SSL/TLS configuration testing

### 🌐 **Network Testing**
- Port scanning
- DNS resolution testing
- Latency measurement
- Connection limit testing
- Bandwidth analysis (optional)

### 🔥 **Stress Testing**
- Progressive load increases
- Spike testing capabilities
- Breaking point identification
- Recovery time analysis

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
server_tester = "0.1.0"
```

## Quick Start

### As a Library

```rust
use server_tester::*;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // HTTP Client Testing
    let client = HttpTester::new("https://api.example.com");
    let response = client.get("/health").await?;
    println!("Health check: {} ms", response.response_time_ms);

    // Load Testing
    let config = LoadTestConfig {
        concurrent_users: 10,
        total_requests: 100,
        duration_seconds: None,
        ramp_up_seconds: 5,
        think_time_ms: 1000,
        base_url: "https://api.example.com".to_string(),
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/api/data".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: Some(2000),
            }
        ],
    };
    
    let load_tester = LoadTester::new(config);
    let results = load_tester.run_load_test().await;
    println!("Success rate: {:.2}%", 
             (results.successful_requests as f64 / results.total_requests as f64) * 100.0);

    Ok(())
}
```

### As a CLI Tool

```bash
# Build the CLI
cargo build --release

# HTTP Testing
./target/release/server_tester http --url https://api.example.com --path /health

# Load Testing
./target/release/server_tester load --url https://api.example.com --users 10 --requests 100

# Performance Testing
./target/release/server_tester performance --url https://api.example.com --connections 10 --duration 60

# Security Testing
./target/release/server_tester security --url https://api.example.com --test-xss --test-sql --test-headers

# Network Testing
./target/release/server_tester network --host example.com --ports 80,443,22

# Comprehensive Testing
./target/release/server_tester all --url https://api.example.com --include-security --include-network

# Stress Testing
./target/release/server_tester stress --url https://api.example.com --max-users 100 --step-size 10

# Spike Testing
./target/release/server_tester spike --url https://api.example.com --normal-load 10 --spike-load 100
```

## Testing Approaches Implemented

### 1. **Functional Testing**
- API endpoint validation
- Request/response testing
- Integration testing
- End-to-end workflows

### 2. **Performance Testing**
- **Load Testing**: Normal expected traffic simulation
- **Stress Testing**: Beyond normal capacity until failure
- **Spike Testing**: Sudden traffic increases
- **Volume Testing**: Large amounts of data processing
- **Endurance Testing**: Extended time periods

### 3. **Security Testing**
- Authentication vulnerabilities
- Authorization bypasses
- Input validation flaws
- SQL injection attempts
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Security header analysis
- SSL/TLS configuration

### 4. **Network Testing**
- Port availability scanning
- DNS resolution performance
- Connection establishment
- Latency measurement
- Bandwidth utilization

## Configuration

### Load Test Configuration

```rust
let config = LoadTestConfig {
    concurrent_users: 50,           // Number of concurrent virtual users
    total_requests: 1000,           // Total requests to send
    duration_seconds: Some(300),    // Test duration (alternative to total_requests)
    ramp_up_seconds: 30,           // Time to reach full load
    think_time_ms: 1000,           // Delay between requests per user
    base_url: "https://api.example.com".to_string(),
    requests: vec![/* test scenarios */],
};
```

### Security Test Configuration

```rust
let config = SecurityTestConfig {
    base_url: "https://api.example.com".to_string(),
    test_authentication: true,      // Test auth bypasses
    test_authorization: true,       // Test privilege escalation
    test_input_validation: true,    // Test input sanitization
    test_sql_injection: true,       // Test SQL injection
    test_xss: true,                // Test XSS vulnerabilities
    test_csrf: true,               // Test CSRF protection
    test_security_headers: true,    // Test security headers
    test_ssl_tls: true,            // Test SSL/TLS config
    auth_token: Some("token".to_string()),
    test_endpoints: vec!["/api/users".to_string()],
};
```

## Examples

Run the comprehensive example:

```bash
cargo run --example basic_usage
```

This will demonstrate all testing approaches against a test API.

## Running Tests

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# Benchmarks
cargo bench

# All tests with output
cargo test -- --nocapture
```

## Metrics and Reporting

The framework provides detailed metrics for all testing types:

### Load Testing Metrics
- Total/successful/failed requests
- Response time statistics (min, max, avg, percentiles)
- Requests per second
- Error rate and status code distribution

### Performance Metrics
- Throughput (RPS)
- Latency distribution
- Connection metrics
- Resource utilization

### Security Results
- Vulnerability count by severity
- Security score calculation
- Detailed remediation recommendations

### Network Analysis
- Port scan results
- DNS resolution performance
- Connection success rates
- Latency statistics

## Dependencies

- `reqwest` - HTTP client
- `tokio` - Async runtime
- `serde` - Serialization
- `clap` - CLI interface
- `tracing` - Logging
- `histogram` - Statistics
- `criterion` - Benchmarking (dev)
- `mockito` - Testing (dev)

## Architecture

The project is structured into modular components:

```
src/
├── lib.rs              # Main library interface
├── http_client.rs      # HTTP testing functionality
├── load_tester.rs      # Load testing implementation
├── performance.rs      # Performance benchmarking
├── security.rs         # Security vulnerability testing
├── network.rs          # Network testing tools
├── cli.rs             # Command-line interface
└── main.rs            # CLI binary entry point

tests/
└── integration_tests.rs  # Integration test examples

benches/
└── performance_bench.rs   # Performance benchmarks

examples/
└── basic_usage.rs         # Comprehensive usage example
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Roadmap

- [ ] WebSocket testing support
- [ ] GraphQL API testing
- [ ] Database performance testing
- [ ] Container/Docker integration
- [ ] CI/CD pipeline integration
- [ ] HTML report generation
- [ ] Real-time monitoring dashboard
- [ ] Plugin system for custom tests

## Support

For questions, issues, or contributions, please visit the [GitHub repository](https://github.com/your-username/server_tester).