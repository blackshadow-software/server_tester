use server_tester::*;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🚀 Server Tester - Comprehensive Testing Demo");
    println!("============================================\n");

    // Test target - using httpbin.org as it's a reliable testing service
    let base_url = "https://httpbin.org";
    
    // 1. Basic HTTP Client Testing
    println!("📡 1. HTTP Client Testing");
    println!("--------------------------");
    
    let http_client = HttpTester::new(base_url);
    
    // Health check
    let health = http_client.health_check("/get").await?;
    println!("✅ Health Check: {}", if health { "PASS" } else { "FAIL" });
    
    // Basic GET request
    let get_response = http_client.get("/get").await?;
    println!("✅ GET /get: {} ms (Status: {})", 
             get_response.response_time_ms, get_response.status);
    
    // POST request with JSON data
    let post_data = r#"{"message": "Hello from Rust Server Tester!", "timestamp": "2024-01-01"}"#;
    let post_response = http_client.post("/post", post_data).await?;
    println!("✅ POST /post: {} ms (Status: {})", 
             post_response.response_time_ms, post_response.status);
    
    println!();
    
    // 2. Load Testing
    println!("⚡ 2. Load Testing");
    println!("------------------");
    
    let load_config = LoadTestConfig {
        concurrent_users: 3,
        total_requests: 9,
        duration_seconds: None,
        ramp_up_seconds: 1,
        think_time_ms: 200,
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
    
    println!("✅ Total Requests: {}", load_results.total_requests);
    println!("✅ Success Rate: {:.1}%", 
             (load_results.successful_requests as f64 / load_results.total_requests as f64) * 100.0);
    println!("✅ Average Response Time: {:.2} ms", load_results.average_response_time_ms);
    println!("✅ Requests per Second: {:.2}", load_results.requests_per_second);
    
    println!();
    
    // 3. Performance Testing
    println!("🎯 3. Performance Testing");
    println!("--------------------------");
    
    let perf_config = PerformanceTestConfig {
        base_url: base_url.to_string(),
        warmup_requests: 2,
        measurement_requests: 6,
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
    
    let perf_tester = PerformanceTester::new(perf_config);
    let perf_results = perf_tester.run_benchmark().await;
    
    println!("✅ Throughput: {:.2} RPS", perf_results.throughput_rps);
    println!("✅ Average Latency: {:.2} ms", perf_results.latency_ms.mean);
    println!("✅ 95th Percentile: {:.2} ms", perf_results.latency_ms.p95);
    println!("✅ 99th Percentile: {:.2} ms", perf_results.latency_ms.p99);
    
    println!();
    
    // 4. Security Testing (Basic)
    println!("🔒 4. Security Testing");
    println!("----------------------");
    
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
    
    println!("✅ Security Tests Run: {}", security_results.total_tests);
    println!("✅ Security Score: {:.1}%", security_results.security_score);
    println!("✅ Vulnerabilities Found: {}", security_results.vulnerabilities.len());
    
    if !security_results.vulnerabilities.is_empty() {
        println!("⚠️  Security Issues:");
        for vuln in &security_results.vulnerabilities {
            println!("   - {:?}: {}", vuln.severity, vuln.description);
        }
    }
    
    println!();
    
    // 5. Network Testing
    println!("🌐 5. Network Testing");
    println!("---------------------");
    
    let network_config = NetworkTestConfig {
        target_host: "httpbin.org".to_string(),
        target_ports: vec![80, 443],
        timeout_ms: 3000,
        connection_attempts: 3,
        concurrent_connections: 3,
        bandwidth_test_duration_seconds: 0, // Skip bandwidth test
        latency_test_count: 5,
    };
    
    let network_tester = NetworkTester::new(network_config);
    match network_tester.run_comprehensive_test().await {
        Ok(network_results) => {
            println!("✅ DNS Resolution: {}", if network_results.dns_results.success { "PASS" } else { "FAIL" });
            println!("✅ DNS Response Time: {:.2} ms", network_results.dns_results.resolution_time_ms);
            
            let open_ports: Vec<_> = network_results.port_scan_results
                .iter()
                .filter(|(_, status)| status.is_open)
                .map(|(port, _)| port)
                .collect();
            println!("✅ Open Ports: {:?}", open_ports);
            
            println!("✅ Average Latency: {:.2} ms", network_results.latency_results.avg_ms);
            println!("✅ Packet Loss: {:.1}%", network_results.latency_results.packet_loss_percent);
        }
        Err(e) => {
            println!("❌ Network test failed: {}", e);
        }
    }
    
    println!();
    
    // 6. Stress Testing
    println!("🔥 6. Stress Testing");
    println!("--------------------");
    
    let stress_config = LoadTestConfig {
        concurrent_users: 1, // Will be overridden
        total_requests: 6,
        duration_seconds: Some(3),
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
                expected_response_time_ms: None,
            }
        ],
    };
    
    let stress_tester = LoadTester::new(stress_config);
    let stress_results = stress_tester.run_stress_test(
        3, // max users
        1, // step size
        Duration::from_secs(2) // step duration
    ).await;
    
    println!("✅ Stress Test Steps: {}", stress_results.len());
    for (i, result) in stress_results.iter().enumerate() {
        let users = i + 1;
        println!("   {} users: {:.2} RPS, {:.1}% success", 
                 users, result.requests_per_second,
                 (result.successful_requests as f64 / result.total_requests as f64) * 100.0);
    }
    
    println!();
    
    // Summary
    println!("📊 Test Summary");
    println!("===============");
    println!("✅ HTTP Client Tests: COMPLETED");
    println!("✅ Load Testing: {} requests processed", load_results.total_requests);
    println!("✅ Performance Testing: {:.2} RPS achieved", perf_results.throughput_rps);
    println!("✅ Security Testing: {:.1}% security score", security_results.security_score);
    println!("✅ Network Testing: COMPLETED");
    println!("✅ Stress Testing: {} steps executed", stress_results.len());
    
    println!("\n🎉 All server testing approaches have been successfully demonstrated!");
    println!("This Rust project now provides comprehensive server testing capabilities including:");
    println!("  • HTTP API testing (GET, POST, PUT, DELETE, etc.)");
    println!("  • Load testing with concurrent users and request patterns");
    println!("  • Performance benchmarking with detailed latency metrics");
    println!("  • Security vulnerability scanning (XSS, SQL injection, etc.)");
    println!("  • Network testing (port scanning, latency, DNS resolution)");
    println!("  • Stress testing with progressive load increases");
    println!("  • CLI interface for easy command-line usage");
    println!("  • Integration tests and benchmarks");
    
    Ok(())
}