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

## Security Testing Methodologies

This framework focuses on comprehensive security testing approaches to identify vulnerabilities and ensure robust application security. Each testing method targets specific security weaknesses and follows proven methodologies.

### 1. **Authentication Bypass Detection**

**Purpose and Critical Importance:**
Authentication bypass detection identifies weaknesses in login mechanisms that could allow unauthorized access to systems without proper credentials. This is fundamental security testing as authentication is the first line of defense.

**How it works:**
The testing process systematically attempts to circumvent authentication mechanisms using various techniques. This includes testing default credentials, attempting to access restricted resources without authentication, manipulating authentication tokens, exploiting session management flaws, and testing for weak password policies. The system's response to each bypass attempt is carefully analyzed to identify vulnerabilities.

**Detection techniques:**
- **Direct URL Access**: Attempting to access protected resources by directly navigating to URLs without logging in
- **Session Token Manipulation**: Modifying, removing, or forging authentication tokens to gain unauthorized access
- **Parameter Tampering**: Altering authentication parameters in requests to bypass login requirements
- **Default Credential Testing**: Trying common username/password combinations and default system credentials
- **Authentication Logic Flaws**: Exploiting weaknesses in the authentication workflow or business logic
- **Brute Force Resistance**: Testing account lockout mechanisms and rate limiting effectiveness

**Vulnerability indicators:**
Authentication bypass vulnerabilities are indicated by successful access to protected resources without proper authentication, weak account lockout policies, predictable session tokens, or errors that reveal system information.

---

### 2. **Authorization Testing**

**Purpose and Security Focus:**
Authorization testing ensures that authenticated users can only access resources and perform actions they are explicitly permitted to. This prevents privilege escalation and unauthorized access to sensitive data or functionality.

**How it works:**
The testing methodology involves creating multiple user accounts with different permission levels and systematically attempting to access resources and functions beyond each user's authorized scope. This includes testing role-based access controls, resource-level permissions, and function-level security. Both horizontal privilege escalation (accessing other users' data) and vertical privilege escalation (gaining administrative privileges) are thoroughly tested.

**Testing approaches:**
- **Role-based Access Control Testing**: Verifying that users can only access resources appropriate to their assigned roles
- **Horizontal Privilege Escalation**: Attempting to access another user's data or resources at the same privilege level
- **Vertical Privilege Escalation**: Trying to gain higher-level permissions or administrative access
- **Resource-level Permissions**: Testing access controls on individual files, database records, or API endpoints
- **Function-level Authorization**: Verifying that administrative functions are properly restricted
- **Parameter Manipulation**: Modifying user IDs, account numbers, or other identifiers in requests

**Vulnerability detection:**
Authorization flaws are revealed when users can access resources they shouldn't, perform unauthorized actions, view other users' data, or execute administrative functions without proper permissions.

---

### 3. **Input Validation Checks**

**Purpose and Protection Scope:**
Input validation testing ensures that all user inputs are properly sanitized, validated, and handled to prevent injection attacks, data corruption, and system compromise. This is critical as improper input handling is a common vulnerability source.

**How it works:**
The testing process involves submitting various types of malicious and malformed inputs to all input fields, parameters, and interfaces throughout the application. This includes testing with oversized inputs, special characters, different encoding formats, boundary values, and completely invalid data types. Each input scenario is designed to test specific validation mechanisms and identify weaknesses in input handling.

**Validation testing categories:**
- **Data Type Validation**: Submitting wrong data types (text where numbers expected, etc.) to test type checking
- **Length Validation**: Testing with inputs exceeding expected maximum lengths to identify buffer overflow risks
- **Format Validation**: Providing incorrectly formatted data (invalid emails, dates, phone numbers) to test format checking
- **Special Character Handling**: Using characters with special meaning in various contexts (quotes, brackets, semicolons)
- **Encoding Attacks**: Testing different character encodings to bypass validation filters
- **Boundary Value Testing**: Using minimum and maximum allowed values plus edge cases
- **Null Value Testing**: Submitting empty, null, or undefined values where data is expected

**Vulnerability identification:**
Input validation flaws are detected when the system crashes, returns error messages revealing system information, processes invalid data incorrectly, or exhibits unexpected behavior with malformed inputs.

---

### 4. **SQL Injection Detection**

**Purpose and Attack Prevention:**
SQL injection testing identifies vulnerabilities where malicious SQL code can be executed through application inputs, potentially allowing unauthorized database access, data theft, or database manipulation.

**How it works:**
The testing methodology involves systematically inserting SQL code fragments into all input fields that interact with databases. Various SQL injection techniques are employed, including union-based injection, boolean-based blind injection, time-based blind injection, and error-based injection. The application's responses are carefully analyzed to determine if injected SQL code was executed, indicating a vulnerability.

**Injection testing techniques:**
- **Classic SQL Injection**: Directly inserting SQL commands into input fields to manipulate database queries
- **Blind SQL Injection**: Using conditional statements to infer database information when direct output isn't visible
- **Time-based SQL Injection**: Using SQL functions that cause delays to confirm code execution
- **Union-based Injection**: Using SQL UNION statements to extract data from different database tables
- **Error-based Injection**: Triggering database errors that reveal system information or data
- **Second-order SQL Injection**: Injecting code that gets stored and executed later by the application

**Detection indicators:**
SQL injection vulnerabilities are identified through database errors in responses, unexpected data in output, application timeouts from time-based attacks, or successful extraction of unauthorized database information.

---

### 5. **XSS Vulnerability Scanning**

**Purpose and Cross-Site Scripting Prevention:**
XSS vulnerability scanning identifies weaknesses where malicious scripts can be injected into web applications and executed by other users' browsers, potentially stealing sensitive information or performing unauthorized actions.

**How it works:**
The scanning process involves submitting various JavaScript and HTML payloads through all possible input vectors including form fields, URL parameters, headers, and file uploads. Different encoding techniques and payload variations are used to bypass input filters. The application's output is examined to determine if injected scripts are executed or properly neutralized.

**XSS testing categories:**
- **Reflected XSS**: Testing inputs that are immediately reflected back in the response, potentially executing in users' browsers
- **Stored XSS**: Injecting scripts that get saved in the application and executed when viewed by other users
- **DOM-based XSS**: Testing client-side script vulnerabilities where malicious code manipulates the Document Object Model
- **Filter Bypass Testing**: Using various encoding techniques and payload variations to circumvent input sanitization
- **Context-specific Testing**: Testing script injection in different HTML contexts (attributes, JavaScript, CSS)
- **Polyglot Payloads**: Using payloads that work in multiple contexts to maximize attack surface coverage

**Vulnerability confirmation:**
XSS vulnerabilities are confirmed when injected scripts execute in the browser, when script tags appear unescaped in HTML output, or when alert boxes or other JavaScript functions are triggered by payloads.

---

### 6. **CSRF Protection Testing**

**Purpose and Attack Prevention:**
CSRF (Cross-Site Request Forgery) protection testing verifies that applications properly prevent malicious websites from performing unauthorized actions on behalf of authenticated users without their knowledge or consent.

**How it works:**
The testing process involves creating malicious web pages or forms that attempt to submit requests to the target application using the victim's authentication session. Various CSRF attack scenarios are tested, including GET-based attacks through malicious links and POST-based attacks through hidden forms. The application's CSRF protection mechanisms are evaluated for effectiveness.

**CSRF testing methodology:**
- **Token Validation Testing**: Verifying that CSRF tokens are properly generated, validated, and required for sensitive operations
- **Referer Header Checking**: Testing whether the application properly validates the HTTP Referer header
- **Same-Site Cookie Testing**: Evaluating SameSite cookie attributes and their effectiveness against CSRF attacks
- **State-changing Operation Testing**: Focusing on operations that modify data or system state
- **Authentication Context Testing**: Ensuring CSRF protection works correctly with different authentication methods
- **Cross-origin Request Testing**: Verifying protection against requests from different domains

**Protection validation:**
CSRF protection effectiveness is confirmed when unauthorized cross-site requests are properly rejected, when missing or invalid CSRF tokens prevent request processing, and when legitimate same-origin requests continue to work normally.

---

### 7. **Security Header Analysis**

**Purpose and Header Validation:**
Security header analysis examines HTTP response headers to ensure proper security policies are implemented, protecting against various client-side attacks and enforcing security best practices.

**How it works:**
The analysis process involves examining all HTTP responses from the application to identify the presence, absence, and configuration of security-related headers. Each header's value is validated against security best practices and known attack mitigation techniques. The effectiveness of header policies is tested through various attack scenarios.

**Header analysis categories:**
- **Content Security Policy (CSP)**: Analyzing CSP directives to ensure they effectively prevent XSS and other injection attacks
- **X-Frame-Options**: Verifying protection against clickjacking attacks through frame embedding restrictions
- **X-XSS-Protection**: Checking browser XSS filter activation (though deprecated, still relevant for older browsers)
- **Strict-Transport-Security**: Validating HTTPS enforcement and HSTS policy configuration
- **X-Content-Type-Options**: Ensuring MIME type sniffing protection is enabled
- **Referrer-Policy**: Analyzing referrer information leakage controls
- **Feature-Policy/Permissions-Policy**: Examining feature access controls and permissions

**Security assessment:**
Header security is evaluated by identifying missing critical headers, analyzing header values for proper configuration, testing policy enforcement effectiveness, and verifying that security headers don't interfere with legitimate application functionality.

---

### 8. **SSL/TLS Configuration Testing**

**Purpose and Encryption Validation:**
SSL/TLS configuration testing validates the security of encrypted communications between clients and servers, ensuring that data in transit is properly protected against eavesdropping and man-in-the-middle attacks.

**How it works:**
The testing process involves comprehensive analysis of the SSL/TLS implementation, including certificate validation, supported protocol versions, cipher suite strength, and various configuration parameters. Different client configurations and attack scenarios are tested to identify potential weaknesses in the encryption setup.

**Configuration testing aspects:**
- **Certificate Validation**: Verifying certificate authenticity, expiration dates, proper certificate chains, and domain name matching
- **Protocol Version Testing**: Checking support for secure protocol versions and absence of deprecated versions (SSLv3, early TLS versions)
- **Cipher Suite Analysis**: Evaluating the strength of supported encryption algorithms and key exchange methods
- **Perfect Forward Secrecy**: Testing for ephemeral key exchange support to ensure session key security
- **Certificate Transparency**: Verifying certificate transparency log compliance for additional security
- **OCSP Stapling**: Testing Online Certificate Status Protocol implementation for revocation checking
- **Vulnerability Testing**: Checking for known SSL/TLS vulnerabilities like Heartbleed, POODLE, or BEAST

**Security validation:**
SSL/TLS security is confirmed through successful certificate chain validation, strong cipher suite negotiation, proper protocol version enforcement, absence of known vulnerabilities, and effective protection against common SSL/TLS attacks.
