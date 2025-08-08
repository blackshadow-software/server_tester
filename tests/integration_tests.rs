use server_tester::*;
use std::collections::HashMap;
use std::time::Duration;
use tokio;
use serde_json;

#[tokio::test]
async fn test_http_client_integration() {
    // Test with a mock server or a real testing endpoint
    let base_url = "https://httpbin.org"; // Public testing API
    let client = HttpTester::new(base_url);

    // Test GET request
    let response = client.get("/get").await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status, 200);
    assert!(response.success);

    // Test POST request
    let post_data = r#"{"test": "data"}"#;
    let response = client.post("/post", post_data).await;
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status, 200);
    assert!(response.body.contains("test"));
}

#[tokio::test]
async fn test_load_testing_integration() {
    let config = LoadTestConfig {
        concurrent_users: 2,
        total_requests: 10,
        duration_seconds: None,
        ramp_up_seconds: 1,
        think_time_ms: 100,
        base_url: "https://httpbin.org".to_string(),
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: Some(5000),
            }
        ],
    };

    let load_tester = LoadTester::new(config);
    let results = load_tester.run_load_test().await;

    assert!(results.total_requests > 0);
    assert!(results.requests_per_second > 0.0);
    assert!(results.average_response_time_ms > 0.0);
}

#[tokio::test]
async fn test_performance_testing_integration() {
    let config = PerformanceTestConfig {
        base_url: "https://httpbin.org".to_string(),
        warmup_requests: 2,
        measurement_requests: 5,
        concurrent_connections: 2,
        test_duration_seconds: 10,
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: None,
            }
        ],
    };

    let perf_tester = PerformanceTester::new(config);
    let metrics = perf_tester.run_benchmark().await;

    assert!(metrics.throughput_rps > 0.0);
    assert!(metrics.latency_ms.mean > 0.0);
    assert!(metrics.connection_metrics.successful_connections > 0);
}

#[tokio::test]
async fn test_security_testing_integration() {
    let config = SecurityTestConfig {
        base_url: "https://httpbin.org".to_string(),
        test_authentication: true,
        test_authorization: false, // Skip auth tests for public API
        test_input_validation: true,
        test_sql_injection: true,
        test_xss: true,
        test_csrf: false, // Skip CSRF for GET-only testing
        test_security_headers: true,
        test_ssl_tls: true,
        auth_token: None,
        test_endpoints: vec!["/get".to_string(), "/post".to_string()],
    };

    let security_tester = SecurityTester::new(config);
    let results = security_tester.run_security_tests().await;

    assert!(results.total_tests > 0);
    // Security score might vary based on the target, so we don't assert specific values
    println!("Security score: {}%", results.security_score);
}

#[tokio::test]
async fn test_network_testing_integration() {
    let config = NetworkTestConfig {
        target_host: "google.com".to_string(),
        target_ports: vec![80, 443],
        timeout_ms: 5000,
        connection_attempts: 3,
        concurrent_connections: 5,
        bandwidth_test_duration_seconds: 5, // Short test
        latency_test_count: 10,
    };

    let network_tester = NetworkTester::new(config);
    let results = network_tester.run_comprehensive_test().await;

    assert!(results.is_ok());
    let results = results.unwrap();
    
    // Should have scanned the specified ports
    assert_eq!(results.port_scan_results.len(), 2);
    
    // Should have latency measurements
    assert!(!results.latency_results.measurements.is_empty());
    
    // DNS resolution should work for google.com
    assert!(results.dns_results.success);
    assert!(!results.dns_results.resolved_ips.is_empty());
}

#[tokio::test]
async fn test_end_to_end_workflow() {
    // Test a complete workflow combining multiple testing approaches
    let base_url = "https://httpbin.org";
    
    // 1. First, test basic connectivity
    let http_client = HttpTester::new(base_url);
    let health_check = http_client.health_check("/get").await;
    assert!(health_check.is_ok() && health_check.unwrap());

    // 2. Run a quick load test
    let load_config = LoadTestConfig {
        concurrent_users: 2,
        total_requests: 4,
        duration_seconds: None,
        ramp_up_seconds: 0,
        think_time_ms: 0,
        base_url: base_url.to_string(),
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: Some(10000),
            }
        ],
    };

    let load_tester = LoadTester::new(load_config);
    let load_results = load_tester.run_load_test().await;
    assert!(load_results.successful_requests > 0);

    // 3. Run performance analysis
    let perf_config = PerformanceTestConfig {
        base_url: base_url.to_string(),
        warmup_requests: 1,
        measurement_requests: 3,
        concurrent_connections: 1,
        test_duration_seconds: 5,
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: None,
            }
        ],
    };

    let perf_tester = PerformanceTester::new(perf_config);
    let perf_results = perf_tester.run_benchmark().await;
    assert!(perf_results.throughput_rps > 0.0);

    // 4. Basic security check
    let security_config = SecurityTestConfig {
        base_url: base_url.to_string(),
        test_authentication: false, // Skip for public API
        test_authorization: false,
        test_input_validation: true,
        test_sql_injection: true,
        test_xss: true,
        test_csrf: false,
        test_security_headers: true,
        test_ssl_tls: true,
        auth_token: None,
        test_endpoints: vec!["/get".to_string()],
    };

    let security_tester = SecurityTester::new(security_config);
    let security_results = security_tester.run_security_tests().await;
    assert!(security_results.total_tests > 0);

    println!("End-to-end test completed successfully!");
    println!("Load test: {} successful requests", load_results.successful_requests);
    println!("Performance: {:.2} RPS", perf_results.throughput_rps);
    println!("Security score: {:.1}%", security_results.security_score);
}

#[tokio::test]
async fn test_stress_testing_scenario() {
    // Simulate a stress test scenario
    let config = LoadTestConfig {
        concurrent_users: 1,
        total_requests: 5,
        duration_seconds: None,
        ramp_up_seconds: 0,
        think_time_ms: 0,
        base_url: "https://httpbin.org".to_string(),
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: Some(10000),
            }
        ],
    };

    let load_tester = LoadTester::new(config);
    
    // Run stress test with increasing load
    let stress_results = load_tester.run_stress_test(
        3, // max users
        1, // step size
        Duration::from_secs(2) // step duration
    ).await;

    assert!(!stress_results.is_empty());
    assert_eq!(stress_results.len(), 3); // Should have 3 steps (1, 2, 3 users)
    
    for (i, result) in stress_results.iter().enumerate() {
        println!("Step {}: {} RPS", i + 1, result.requests_per_second);
        assert!(result.total_requests > 0);
    }
}

#[tokio::test]
async fn test_volume_testing() {
    // Test different payload sizes
    let config = PerformanceTestConfig {
        base_url: "https://httpbin.org".to_string(),
        warmup_requests: 1,
        measurement_requests: 2,
        concurrent_connections: 1,
        test_duration_seconds: 5,
        requests: vec![
            TestRequest {
                method: "POST".to_string(),
                path: "/post".to_string(),
                headers: HashMap::new(),
                body: Some("test".to_string()), // Will be replaced in volume test
                expected_status: 200,
                expected_response_time_ms: None,
            }
        ],
    };

    let perf_tester = PerformanceTester::new(config);
    
    // Test with different data sizes
    let data_sizes = vec![100, 1000, 5000]; // bytes
    let volume_results = perf_tester.run_volume_test(data_sizes).await;

    assert_eq!(volume_results.len(), 3);
    
    for (i, result) in volume_results.iter().enumerate() {
        println!("Size {}: {:.2} RPS", (i + 1) * 100 * 10, result.throughput_rps);
        assert!(result.throughput_rps >= 0.0);
    }
}

#[tokio::test]
async fn test_spike_testing() {
    let config = LoadTestConfig {
        concurrent_users: 1,
        total_requests: 3,
        duration_seconds: None,
        ramp_up_seconds: 0,
        think_time_ms: 0,
        base_url: "https://httpbin.org".to_string(),
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: Some(10000),
            }
        ],
    };

    let load_tester = LoadTester::new(config);
    
    // Simulate spike from 1 to 3 users
    let spike_result = load_tester.run_spike_test(
        1, // normal load
        3, // spike load
        Duration::from_secs(2) // spike duration
    ).await;

    assert!(spike_result.total_requests > 0);
    println!("Spike test: {} total requests, {:.2} RPS", 
             spike_result.total_requests, spike_result.requests_per_second);
}

// Helper function to create a comprehensive test report
#[tokio::test]
async fn test_comprehensive_report_generation() {
    let base_url = "https://httpbin.org";
    
    // Run all tests and generate a comprehensive report
    println!("\n=== Comprehensive Server Testing Report ===");
    
    // Basic connectivity test
    let http_client = HttpTester::new(base_url);
    let health = http_client.health_check("/get").await.unwrap_or(false);
    println!("Health Check: {}", if health { "PASS" } else { "FAIL" });
    
    // Load test
    let load_config = LoadTestConfig {
        concurrent_users: 2,
        total_requests: 6,
        duration_seconds: None,
        ramp_up_seconds: 1,
        think_time_ms: 100,
        base_url: base_url.to_string(),
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: Some(5000),
            }
        ],
    };
    
    let load_tester = LoadTester::new(load_config);
    let load_results = load_tester.run_load_test().await;
    println!("Load Test: {}/{} successful ({:.1}% success rate)", 
             load_results.successful_requests, 
             load_results.total_requests,
             (load_results.successful_requests as f64 / load_results.total_requests as f64) * 100.0);
    
    // Performance test
    let perf_config = PerformanceTestConfig {
        base_url: base_url.to_string(),
        warmup_requests: 2,
        measurement_requests: 4,
        concurrent_connections: 2,
        test_duration_seconds: 5,
        requests: vec![
            TestRequest {
                method: "GET".to_string(),
                path: "/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: None,
            }
        ],
    };
    
    let perf_tester = PerformanceTester::new(perf_config);
    let perf_results = perf_tester.run_benchmark().await;
    println!("Performance: {:.2} RPS, {:.2}ms avg latency", 
             perf_results.throughput_rps, 
             perf_results.latency_ms.mean);
    
    println!("=== Report Complete ===\n");
    
    // Assert that all tests produced meaningful results
    assert!(load_results.total_requests > 0);
    assert!(perf_results.throughput_rps > 0.0);
}