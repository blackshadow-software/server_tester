use clap::{Parser, Subcommand};
use serde_json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use anyhow::Result;

use crate::{
    http_client::{HttpTester, TestRequest},
    load_tester::{LoadTester, LoadTestConfig},
    performance::{PerformanceTester, PerformanceTestConfig},
    security::{SecurityTester, SecurityTestConfig},
    network::{NetworkTester, NetworkTestConfig},
};

#[derive(Parser)]
#[command(name = "server-tester")]
#[command(about = "A comprehensive server testing tool")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run HTTP API tests
    Http {
        /// Target server URL
        #[arg(short, long)]
        url: String,
        
        /// HTTP method (GET, POST, PUT, DELETE, etc.)
        #[arg(short, long, default_value = "GET")]
        method: String,
        
        /// Request path
        #[arg(short, long, default_value = "/")]
        path: String,
        
        /// Request body (for POST/PUT requests)
        #[arg(short, long)]
        body: Option<String>,
        
        /// Expected status code
        #[arg(short, long, default_value = "200")]
        expected_status: u16,
        
        /// Request timeout in milliseconds
        #[arg(short, long, default_value = "30000")]
        timeout: u64,
        
        /// Additional headers (format: key=value)
        #[arg(long)]
        header: Vec<String>,
    },
    
    /// Run load tests
    Load {
        /// Target server URL
        #[arg(short, long)]
        url: String,
        
        /// Number of concurrent users
        #[arg(short, long, default_value = "10")]
        users: usize,
        
        /// Total number of requests
        #[arg(short, long, default_value = "100")]
        requests: usize,
        
        /// Ramp-up time in seconds
        #[arg(short, long, default_value = "10")]
        ramp_up: u64,
        
        /// Think time between requests in milliseconds
        #[arg(short, long, default_value = "1000")]
        think_time: u64,
        
        /// Test duration in seconds (alternative to total requests)
        #[arg(short, long)]
        duration: Option<u64>,
        
        /// Configuration file with test scenarios
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    
    /// Run performance benchmarks
    Performance {
        /// Target server URL
        #[arg(short, long)]
        url: String,
        
        /// Number of warmup requests
        #[arg(short, long, default_value = "10")]
        warmup: usize,
        
        /// Number of measurement requests
        #[arg(short, long, default_value = "100")]
        requests: usize,
        
        /// Number of concurrent connections
        #[arg(short, long, default_value = "10")]
        connections: usize,
        
        /// Test duration in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
        
        /// Run endurance test
        #[arg(long)]
        endurance: bool,
        
        /// Data sizes for volume testing (comma-separated)
        #[arg(long)]
        volume_sizes: Option<String>,
    },
    
    /// Run security tests
    Security {
        /// Target server URL
        #[arg(short, long)]
        url: String,
        
        /// Test authentication vulnerabilities
        #[arg(long)]
        test_auth: bool,
        
        /// Test authorization vulnerabilities
        #[arg(long)]
        test_authz: bool,
        
        /// Test input validation
        #[arg(long)]
        test_input: bool,
        
        /// Test SQL injection
        #[arg(long)]
        test_sql: bool,
        
        /// Test XSS vulnerabilities
        #[arg(long)]
        test_xss: bool,
        
        /// Test CSRF vulnerabilities
        #[arg(long)]
        test_csrf: bool,
        
        /// Test security headers
        #[arg(long)]
        test_headers: bool,
        
        /// Test SSL/TLS configuration
        #[arg(long)]
        test_ssl: bool,
        
        /// Authentication token
        #[arg(long)]
        auth_token: Option<String>,
        
        /// Endpoints to test (comma-separated)
        #[arg(short, long)]
        endpoints: Option<String>,
    },
    
    /// Run network tests
    Network {
        /// Target hostname or IP
        #[arg(short, long)]
        host: String,
        
        /// Ports to scan (comma-separated)
        #[arg(short, long, default_value = "80,443,22,21,25,53,110,995,993,143")]
        ports: String,
        
        /// Connection timeout in milliseconds
        #[arg(short, long, default_value = "5000")]
        timeout: u64,
        
        /// Number of connection attempts
        #[arg(short, long, default_value = "3")]
        attempts: usize,
        
        /// Number of concurrent connections for testing
        #[arg(short, long, default_value = "10")]
        concurrent: usize,
        
        /// Bandwidth test duration in seconds
        #[arg(short, long, default_value = "30")]
        bandwidth_duration: u64,
        
        /// Number of latency test packets
        #[arg(short, long, default_value = "100")]
        latency_count: usize,
        
        /// Skip bandwidth testing
        #[arg(long)]
        skip_bandwidth: bool,
    },
    
    /// Run comprehensive test suite
    All {
        /// Target server URL
        #[arg(short, long)]
        url: String,
        
        /// Output format (json, text, html)
        #[arg(short, long, default_value = "text")]
        format: String,
        
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Include security tests
        #[arg(long)]
        include_security: bool,
        
        /// Include network tests
        #[arg(long)]
        include_network: bool,
        
        /// Light testing mode (faster, fewer tests)
        #[arg(long)]
        light: bool,
    },
    
    /// Run stress tests
    Stress {
        /// Target server URL
        #[arg(short, long)]
        url: String,
        
        /// Maximum number of concurrent users
        #[arg(short, long, default_value = "100")]
        max_users: usize,
        
        /// Step size for user increase
        #[arg(short, long, default_value = "10")]
        step_size: usize,
        
        /// Duration for each step in seconds
        #[arg(short, long, default_value = "60")]
        step_duration: u64,
    },
    
    /// Run spike tests
    Spike {
        /// Target server URL
        #[arg(short, long)]
        url: String,
        
        /// Normal load (concurrent users)
        #[arg(short, long, default_value = "10")]
        normal_load: usize,
        
        /// Spike load (concurrent users)
        #[arg(short, long, default_value = "100")]
        spike_load: usize,
        
        /// Spike duration in seconds
        #[arg(short, long, default_value = "30")]
        spike_duration: u64,
    },
    
    /// Start web server
    Server {
        /// Port to run the server on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
}

pub async fn run_cli() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Http { 
            url, method, path, body, expected_status, timeout, header 
        } => {
            run_http_test(url, method, path, body, expected_status, timeout, header).await?;
        }
        
        Commands::Load { 
            url, users, requests, ramp_up, think_time, duration, config 
        } => {
            run_load_test(url, users, requests, ramp_up, think_time, duration, config).await?;
        }
        
        Commands::Performance { 
            url, warmup, requests, connections, duration, endurance, volume_sizes 
        } => {
            run_performance_test(url, warmup, requests, connections, duration, endurance, volume_sizes).await?;
        }
        
        Commands::Security { 
            url, test_auth, test_authz, test_input, test_sql, test_xss, 
            test_csrf, test_headers, test_ssl, auth_token, endpoints 
        } => {
            run_security_test(
                url, test_auth, test_authz, test_input, test_sql, test_xss,
                test_csrf, test_headers, test_ssl, auth_token, endpoints
            ).await?;
        }
        
        Commands::Network { 
            host, ports, timeout, attempts, concurrent, bandwidth_duration, 
            latency_count, skip_bandwidth 
        } => {
            run_network_test(
                host, ports, timeout, attempts, concurrent, 
                bandwidth_duration, latency_count, skip_bandwidth
            ).await?;
        }
        
        Commands::All { 
            url, format, output, include_security, include_network, light 
        } => {
            run_comprehensive_test(url, format, output, include_security, include_network, light).await?;
        }
        
        Commands::Stress { 
            url, max_users, step_size, step_duration 
        } => {
            run_stress_test(url, max_users, step_size, step_duration).await?;
        }
        
        Commands::Spike { 
            url, normal_load, spike_load, spike_duration 
        } => {
            run_spike_test(url, normal_load, spike_load, spike_duration).await?;
        }
        
        Commands::Server { port } => {
            run_web_server(port).await?;
        }
    }
    
    Ok(())
}

async fn run_http_test(
    url: String,
    method: String,
    path: String,
    body: Option<String>,
    expected_status: u16,
    timeout: u64,
    headers: Vec<String>,
) -> Result<()> {
    let http_tester = HttpTester::new(&url)
        .with_timeout(Duration::from_millis(timeout));
    
    let mut header_map = HashMap::new();
    for header in headers {
        if let Some((key, value)) = header.split_once('=') {
            header_map.insert(key.to_string(), value.to_string());
        }
    }
    
    let request = TestRequest {
        method,
        path,
        headers: header_map,
        body,
        expected_status,
        expected_response_time_ms: Some(timeout),
    };
    
    let response = http_tester.execute_test(&request).await?;
    
    println!("=== HTTP Test Results ===");
    println!("Status: {}", response.status);
    println!("Response Time: {} ms", response.response_time_ms);
    println!("Success: {}", response.success);
    
    if let Some(error) = response.error {
        println!("Error: {}", error);
    }
    
    if !response.body.is_empty() && response.body.len() < 1000 {
        println!("Response Body: {}", response.body);
    } else if !response.body.is_empty() {
        println!("Response Body: {} characters", response.body.len());
    }
    
    Ok(())
}

async fn run_load_test(
    url: String,
    users: usize,
    requests: usize,
    ramp_up: u64,
    think_time: u64,
    duration: Option<u64>,
    config_file: Option<PathBuf>,
) -> Result<()> {
    let config = if let Some(config_path) = config_file {
        let config_content = tokio::fs::read_to_string(config_path).await?;
        serde_json::from_str(&config_content)?
    } else {
        LoadTestConfig {
            concurrent_users: users,
            total_requests: requests,
            duration_seconds: duration,
            ramp_up_seconds: ramp_up,
            think_time_ms: think_time,
            base_url: url,
            requests: vec![TestRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: None,
            }],
        }
    };
    
    let load_tester = LoadTester::new(config);
    let results = load_tester.run_load_test().await;
    
    println!("=== Load Test Results ===");
    println!("Total Requests: {}", results.total_requests);
    println!("Successful Requests: {}", results.successful_requests);
    println!("Failed Requests: {}", results.failed_requests);
    println!("Success Rate: {:.2}%", (results.successful_requests as f64 / results.total_requests as f64) * 100.0);
    println!("Average Response Time: {:.2} ms", results.average_response_time_ms);
    println!("Min Response Time: {} ms", results.min_response_time_ms);
    println!("Max Response Time: {} ms", results.max_response_time_ms);
    println!("95th Percentile: {:.2} ms", results.p95_response_time_ms);
    println!("99th Percentile: {:.2} ms", results.p99_response_time_ms);
    println!("Requests per Second: {:.2}", results.requests_per_second);
    println!("Test Duration: {:.2} seconds", results.duration_seconds);
    println!("Error Rate: {:.2}%", results.error_rate);
    
    if !results.status_codes.is_empty() {
        println!("\n--- Status Code Distribution ---");
        for (code, count) in results.status_codes {
            println!("{}: {}", code, count);
        }
    }
    
    Ok(())
}

async fn run_performance_test(
    url: String,
    warmup: usize,
    requests: usize,
    connections: usize,
    duration: u64,
    endurance: bool,
    volume_sizes: Option<String>,
) -> Result<()> {
    let config = PerformanceTestConfig {
        base_url: url,
        warmup_requests: warmup,
        measurement_requests: requests,
        concurrent_connections: connections,
        test_duration_seconds: duration,
        requests: vec![TestRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            body: None,
            expected_status: 200,
            expected_response_time_ms: None,
        }],
    };
    
    let perf_tester = PerformanceTester::new(config);
    
    if endurance {
        println!("Running endurance test...");
        let metrics_series = perf_tester.run_endurance_test(Duration::from_secs(duration)).await;
        
        println!("=== Endurance Test Results ===");
        for (i, metrics) in metrics_series.iter().enumerate() {
            println!("Interval {}: {:.2} RPS, {:.2}ms avg latency", 
                     i + 1, metrics.throughput_rps, metrics.latency_ms.mean);
        }
    } else if let Some(sizes_str) = volume_sizes {
        let sizes: Vec<usize> = sizes_str.split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        
        if !sizes.is_empty() {
            println!("Running volume test with data sizes: {:?}", sizes);
            let metrics_series = perf_tester.run_volume_test(sizes).await;
            
            println!("=== Volume Test Results ===");
            for (i, metrics) in metrics_series.iter().enumerate() {
                println!("Size {}: {:.2} RPS", i + 1, metrics.throughput_rps);
            }
        }
    } else {
        let metrics = perf_tester.run_benchmark().await;
        perf_tester.print_performance_report(&metrics);
    }
    
    Ok(())
}

async fn run_security_test(
    url: String,
    test_auth: bool,
    test_authz: bool,
    test_input: bool,
    test_sql: bool,
    test_xss: bool,
    test_csrf: bool,
    test_headers: bool,
    test_ssl: bool,
    auth_token: Option<String>,
    endpoints: Option<String>,
) -> Result<()> {
    let test_endpoints = if let Some(endpoints_str) = endpoints {
        endpoints_str.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        vec!["/".to_string()]
    };
    
    let config = SecurityTestConfig {
        base_url: url,
        test_authentication: test_auth,
        test_authorization: test_authz,
        test_input_validation: test_input,
        test_sql_injection: test_sql,
        test_xss,
        test_csrf,
        test_security_headers: test_headers,
        test_ssl_tls: test_ssl,
        auth_token,
        test_endpoints,
    };
    
    let security_tester = SecurityTester::new(config);
    let results = security_tester.run_security_tests().await;
    
    println!("=== Security Test Results ===");
    println!("Total Tests: {}", results.total_tests);
    println!("Passed Tests: {}", results.passed_tests);
    println!("Failed Tests: {}", results.failed_tests);
    println!("Security Score: {:.1}%", results.security_score);
    
    if !results.vulnerabilities.is_empty() {
        println!("\n--- Vulnerabilities Found ---");
        for vuln in &results.vulnerabilities {
            println!("{:?} - {}: {}", vuln.severity, vuln.endpoint, vuln.description);
            println!("  Payload: {}", vuln.payload);
            println!("  Remediation: {}", vuln.remediation);
            println!();
        }
    }
    
    if !results.recommendations.is_empty() {
        println!("--- Security Recommendations ---");
        for rec in &results.recommendations {
            println!("• {}", rec);
        }
    }
    
    Ok(())
}

async fn run_network_test(
    host: String,
    ports: String,
    timeout: u64,
    attempts: usize,
    concurrent: usize,
    bandwidth_duration: u64,
    latency_count: usize,
    skip_bandwidth: bool,
) -> Result<()> {
    let port_list: Vec<u16> = ports.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    
    let config = NetworkTestConfig {
        target_host: host,
        target_ports: port_list,
        timeout_ms: timeout,
        connection_attempts: attempts,
        concurrent_connections: concurrent,
        bandwidth_test_duration_seconds: if skip_bandwidth { 0 } else { bandwidth_duration },
        latency_test_count: latency_count,
    };
    
    let network_tester = NetworkTester::new(config);
    let results = network_tester.run_comprehensive_test().await?;
    
    network_tester.print_network_report(&results);
    
    Ok(())
}

async fn run_comprehensive_test(
    url: String,
    format: String,
    output: Option<PathBuf>,
    include_security: bool,
    include_network: bool,
    light: bool,
) -> Result<()> {
    println!("Running comprehensive test suite...");
    
    // Basic HTTP health check
    let http_tester = HttpTester::new(&url);
    let health_check = http_tester.health_check("/").await?;
    println!("Health Check: {}", if health_check { "PASS" } else { "FAIL" });
    
    // Load test
    let load_config = LoadTestConfig {
        concurrent_users: if light { 2 } else { 10 },
        total_requests: if light { 20 } else { 100 },
        duration_seconds: None,
        ramp_up_seconds: if light { 2 } else { 10 },
        think_time_ms: 1000,
        base_url: url.clone(),
        requests: vec![TestRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            body: None,
            expected_status: 200,
            expected_response_time_ms: None,
        }],
    };
    
    let load_tester = LoadTester::new(load_config);
    let load_results = load_tester.run_load_test().await;
    
    // Performance test
    let perf_config = PerformanceTestConfig {
        base_url: url.clone(),
        warmup_requests: if light { 5 } else { 10 },
        measurement_requests: if light { 20 } else { 50 },
        concurrent_connections: if light { 5 } else { 10 },
        test_duration_seconds: if light { 30 } else { 60 },
        requests: vec![TestRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            body: None,
            expected_status: 200,
            expected_response_time_ms: None,
        }],
    };
    
    let perf_tester = PerformanceTester::new(perf_config);
    let perf_results = perf_tester.run_benchmark().await;
    
    // Comprehensive report
    println!("\n=== Comprehensive Test Results ===");
    println!("Health Check: {}", if health_check { "PASS" } else { "FAIL" });
    println!("Load Test: {}/{} successful ({:.1}% success rate)", 
             load_results.successful_requests,
             load_results.total_requests,
             (load_results.successful_requests as f64 / load_results.total_requests as f64) * 100.0);
    println!("Performance: {:.2} RPS, {:.2}ms avg latency",
             perf_results.throughput_rps,
             perf_results.latency_ms.mean);
    
    // Optional security and network tests
    if include_security {
        println!("Running security tests...");
        // Add security test implementation
    }
    
    if include_network {
        println!("Running network tests...");
        // Add network test implementation
    }
    
    // Output results based on format
    match format.as_str() {
        "json" => {
            let json_output = serde_json::json!({
                "health_check": health_check,
                "load_test": load_results,
                "performance": perf_results
            });
            
            if let Some(output_path) = output {
                tokio::fs::write(output_path, serde_json::to_string_pretty(&json_output)?).await?;
            } else {
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            }
        }
        "html" => {
            // HTML report generation would go here
            println!("HTML format not yet implemented");
        }
        _ => {
            // Text format already printed above
        }
    }
    
    Ok(())
}

async fn run_stress_test(
    url: String,
    max_users: usize,
    step_size: usize,
    step_duration: u64,
) -> Result<()> {
    let config = LoadTestConfig {
        concurrent_users: step_size, // Will be overridden
        total_requests: 1000,
        duration_seconds: Some(step_duration),
        ramp_up_seconds: 5,
        think_time_ms: 500,
        base_url: url,
        requests: vec![TestRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            body: None,
            expected_status: 200,
            expected_response_time_ms: None,
        }],
    };
    
    let load_tester = LoadTester::new(config);
    let results = load_tester.run_stress_test(
        max_users,
        step_size,
        Duration::from_secs(step_duration)
    ).await;
    
    println!("=== Stress Test Results ===");
    for (i, result) in results.iter().enumerate() {
        let users = (i + 1) * step_size;
        println!("Users: {}, RPS: {:.2}, Avg Latency: {:.2}ms, Success Rate: {:.1}%",
                 users,
                 result.requests_per_second,
                 result.average_response_time_ms,
                 (result.successful_requests as f64 / result.total_requests as f64) * 100.0);
    }
    
    Ok(())
}

async fn run_spike_test(
    url: String,
    normal_load: usize,
    spike_load: usize,
    spike_duration: u64,
) -> Result<()> {
    let config = LoadTestConfig {
        concurrent_users: normal_load, // Will be overridden
        total_requests: 1000,
        duration_seconds: Some(spike_duration),
        ramp_up_seconds: 1,
        think_time_ms: 100,
        base_url: url,
        requests: vec![TestRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            body: None,
            expected_status: 200,
            expected_response_time_ms: None,
        }],
    };
    
    let load_tester = LoadTester::new(config);
    let result = load_tester.run_spike_test(
        normal_load,
        spike_load,
        Duration::from_secs(spike_duration)
    ).await;
    
    println!("=== Spike Test Results ===");
    println!("Spike: {} -> {} users for {} seconds", normal_load, spike_load, spike_duration);
    println!("Total Requests: {}", result.total_requests);
    println!("Successful Requests: {}", result.successful_requests);
    println!("Success Rate: {:.1}%", (result.successful_requests as f64 / result.total_requests as f64) * 100.0);
    println!("Requests per Second: {:.2}", result.requests_per_second);
    println!("Average Response Time: {:.2} ms", result.average_response_time_ms);
    
    Ok(())
}

async fn run_web_server(port: u16) -> Result<()> {
    use crate::web_server::start_server;
    println!("🚀 Starting Security Tester Web Server on port {}", port);
    println!("🌐 Access the web interface at: http://localhost:{}", port);
    println!("📖 API Documentation:");
    println!("   POST /api/test/xss - Test XSS vulnerabilities");
    println!("   POST /api/test/csrf - Test CSRF vulnerabilities");
    println!("   POST /api/test/ssl - Test SSL/TLS configuration");
    println!("   POST /api/test/headers - Test security headers");
    println!("   POST /api/test/sql-injection - Test SQL injection");
    println!("   POST /api/test/all-security - Run all security tests");
    println!("   GET  /api/health - Health check");
    println!();
    start_server(port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cli_parsing() {
        // Test that CLI parsing works correctly
        let args = vec!["server-tester", "http", "--url", "http://example.com"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
    }
}