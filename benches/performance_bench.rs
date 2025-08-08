use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use server_tester::{
    http_client::{HttpTester, TestRequest},
    load_tester::{LoadTester, LoadTestConfig},
    performance::{PerformanceTester, PerformanceTestConfig},
};
use std::collections::HashMap;
use tokio::runtime::Runtime;

fn bench_http_client(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("http_client_creation", |b| {
        b.iter(|| {
            let _client = HttpTester::new(black_box("http://httpbin.org"));
        })
    });
    
    c.bench_function("test_request_creation", |b| {
        b.iter(|| {
            let _request = TestRequest {
                method: black_box("GET".to_string()),
                path: black_box("/get".to_string()),
                headers: black_box(HashMap::new()),
                body: black_box(None),
                expected_status: black_box(200),
                expected_response_time_ms: black_box(Some(5000)),
            };
        })
    });
}

fn bench_load_tester_creation(c: &mut Criterion) {
    c.bench_function("load_tester_creation", |b| {
        b.iter(|| {
            let config = LoadTestConfig {
                concurrent_users: black_box(10),
                total_requests: black_box(100),
                duration_seconds: black_box(None),
                ramp_up_seconds: black_box(5),
                think_time_ms: black_box(1000),
                base_url: black_box("http://httpbin.org".to_string()),
                requests: black_box(vec![TestRequest {
                    method: "GET".to_string(),
                    path: "/get".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    expected_status: 200,
                    expected_response_time_ms: Some(5000),
                }]),
            };
            let _tester = LoadTester::new(black_box(config));
        })
    });
}

fn bench_performance_tester_creation(c: &mut Criterion) {
    c.bench_function("performance_tester_creation", |b| {
        b.iter(|| {
            let config = PerformanceTestConfig {
                base_url: black_box("http://httpbin.org".to_string()),
                warmup_requests: black_box(5),
                measurement_requests: black_box(20),
                concurrent_connections: black_box(5),
                test_duration_seconds: black_box(30),
                requests: black_box(vec![TestRequest {
                    method: "GET".to_string(),
                    path: "/get".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    expected_status: 200,
                    expected_response_time_ms: None,
                }]),
            };
            let _tester = PerformanceTester::new(black_box(config));
        })
    });
}

fn bench_concurrent_users(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_users");
    
    for users in [1, 2, 5, 10].iter() {
        group.bench_with_input(BenchmarkId::new("load_test", users), users, |b, &users| {
            b.to_async(&rt).iter(|| async {
                let config = LoadTestConfig {
                    concurrent_users: black_box(users),
                    total_requests: black_box(users * 2), // 2 requests per user
                    duration_seconds: black_box(None),
                    ramp_up_seconds: black_box(0),
                    think_time_ms: black_box(0),
                    base_url: black_box("http://httpbin.org".to_string()),
                    requests: black_box(vec![TestRequest {
                        method: "GET".to_string(),
                        path: "/get".to_string(),
                        headers: HashMap::new(),
                        body: None,
                        expected_status: 200,
                        expected_response_time_ms: Some(10000),
                    }]),
                };
                
                let load_tester = LoadTester::new(config);
                let _results = load_tester.run_load_test().await;
            })
        });
    }
    group.finish();
}

fn bench_data_serialization(c: &mut Criterion) {
    let config = LoadTestConfig {
        concurrent_users: 10,
        total_requests: 100,
        duration_seconds: None,
        ramp_up_seconds: 5,
        think_time_ms: 1000,
        base_url: "http://httpbin.org".to_string(),
        requests: vec![TestRequest {
            method: "GET".to_string(),
            path: "/get".to_string(),
            headers: HashMap::new(),
            body: None,
            expected_status: 200,
            expected_response_time_ms: Some(5000),
        }],
    };
    
    c.bench_function("serialize_load_config", |b| {
        b.iter(|| {
            let _json = serde_json::to_string(black_box(&config)).unwrap();
        })
    });
    
    c.bench_function("deserialize_load_config", |b| {
        let json = serde_json::to_string(&config).unwrap();
        b.iter(|| {
            let _config: LoadTestConfig = serde_json::from_str(black_box(&json)).unwrap();
        })
    });
}

fn bench_payload_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload_sizes");
    
    for size in [100, 1000, 10000, 100000].iter() {
        group.bench_with_input(BenchmarkId::new("create_payload", size), size, |b, &size| {
            b.iter(|| {
                let _payload = "x".repeat(black_box(size));
            })
        });
    }
    
    for size in [100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::new("json_payload", size), size, |b, &size| {
            b.iter(|| {
                let payload = "x".repeat(size);
                let _json = serde_json::json!({
                    "data": black_box(payload)
                });
            })
        });
    }
    
    group.finish();
}

fn bench_response_parsing(c: &mut Criterion) {
    let sample_responses = vec![
        r#"{"status": "ok", "data": "test"}"#,
        r#"{"status": "ok", "data": {"nested": "value", "array": [1, 2, 3]}}"#,
        r#"{"status": "ok", "data": {"large": "data", "with": "many", "fields": "here", "numbers": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}}"#,
    ];
    
    let mut group = c.benchmark_group("response_parsing");
    
    for (i, response) in sample_responses.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("parse_json", i), response, |b, response| {
            b.iter(|| {
                let _parsed: serde_json::Value = serde_json::from_str(black_box(response)).unwrap();
            })
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_http_client,
    bench_load_tester_creation,
    bench_performance_tester_creation,
    bench_concurrent_users,
    bench_data_serialization,
    bench_payload_sizes,
    bench_response_parsing
);

criterion_main!(benches);