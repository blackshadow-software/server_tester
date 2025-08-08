use crate::http_client::{HttpTester, TestRequest, TestResponse};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use histogram::Histogram;
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTestConfig {
    pub base_url: String,
    pub warmup_requests: usize,
    pub measurement_requests: usize,
    pub concurrent_connections: usize,
    pub test_duration_seconds: u64,
    pub requests: Vec<TestRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub throughput_rps: f64,
    pub latency_ms: LatencyMetrics,
    pub connection_metrics: ConnectionMetrics,
    pub resource_utilization: ResourceMetrics,
    pub error_metrics: ErrorMetrics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LatencyMetrics {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub median: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub p99_9: f64,
    pub stddev: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    pub total_connections: usize,
    pub successful_connections: usize,
    pub failed_connections: usize,
    pub connection_success_rate: f64,
    pub avg_connection_time_ms: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub network_io_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorMetrics {
    pub total_errors: usize,
    pub error_rate_percent: f64,
    pub error_types: HashMap<String, usize>,
    pub timeout_count: usize,
}

pub struct PerformanceTester {
    http_tester: HttpTester,
    config: PerformanceTestConfig,
}

impl PerformanceTester {
    pub fn new(config: PerformanceTestConfig) -> Self {
        let http_tester = HttpTester::new(&config.base_url);
        Self {
            http_tester,
            config,
        }
    }

    pub async fn run_benchmark(&self) -> PerformanceMetrics {
        info!("Starting performance benchmark");
        
        // Warmup phase
        self.warmup().await;
        
        // Measurement phase
        let start_time = Instant::now();
        let responses = self.run_measurement_phase().await;
        let total_duration = start_time.elapsed();
        
        self.calculate_metrics(responses, total_duration)
    }

    pub async fn run_endurance_test(&self, duration: Duration) -> Vec<PerformanceMetrics> {
        info!("Starting endurance test for {:?}", duration);
        
        let mut metrics = Vec::new();
        let interval = Duration::from_secs(60); // Collect metrics every minute
        let start_time = Instant::now();
        
        while start_time.elapsed() < duration {
            let interval_start = Instant::now();
            let responses = self.run_measurement_phase().await;
            let interval_duration = interval_start.elapsed();
            
            let interval_metrics = self.calculate_metrics(responses, interval_duration);
            metrics.push(interval_metrics);
            
            // Sleep for the remainder of the interval
            if interval_duration < interval {
                tokio::time::sleep(interval - interval_duration).await;
            }
        }
        
        metrics
    }

    pub async fn run_volume_test(&self, data_sizes: Vec<usize>) -> Vec<PerformanceMetrics> {
        info!("Starting volume test with different data sizes");
        
        let mut results = Vec::new();
        
        for size in data_sizes {
            info!("Testing with data size: {} bytes", size);
            
            // Create test data of specified size
            let test_data = "x".repeat(size);
            
            let mut volume_config = self.config.clone();
            for request in &mut volume_config.requests {
                if request.method.to_uppercase() == "POST" || request.method.to_uppercase() == "PUT" {
                    request.body = Some(test_data.clone());
                }
            }
            
            let volume_tester = PerformanceTester::new(volume_config);
            let metrics = volume_tester.run_benchmark().await;
            results.push(metrics);
        }
        
        results
    }

    async fn warmup(&self) {
        info!("Running warmup phase with {} requests", self.config.warmup_requests);
        
        let tasks: Vec<_> = (0..self.config.warmup_requests)
            .map(|_| {
                let http_tester = self.http_tester.clone();
                let requests = self.config.requests.clone();
                
                tokio::spawn(async move {
                    for request in requests {
                        let _ = http_tester.execute_test(&request).await;
                    }
                })
            })
            .collect();
        
        futures::future::join_all(tasks).await;
        info!("Warmup phase completed");
    }

    async fn run_measurement_phase(&self) -> Vec<TestResponse> {
        info!("Running measurement phase with {} requests", self.config.measurement_requests);
        
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.config.concurrent_connections));
        let tasks: Vec<_> = (0..self.config.measurement_requests)
            .map(|_| {
                let http_tester = self.http_tester.clone();
                let requests = self.config.requests.clone();
                let semaphore = semaphore.clone();
                
                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let mut responses = Vec::new();
                    
                    for request in requests {
                        match http_tester.execute_test(&request).await {
                            Ok(response) => responses.push(response),
                            Err(e) => {
                                responses.push(TestResponse {
                                    status: 0,
                                    headers: HashMap::new(),
                                    body: String::new(),
                                    response_time_ms: 0,
                                    success: false,
                                    error: Some(e.to_string()),
                                });
                            }
                        }
                    }
                    responses
                })
            })
            .collect();
        
        let results = futures::future::join_all(tasks).await;
        let mut all_responses = Vec::new();
        
        for result in results {
            match result {
                Ok(responses) => all_responses.extend(responses),
                Err(e) => warn!("Task failed: {}", e),
            }
        }
        
        all_responses
    }

    fn calculate_metrics(&self, responses: Vec<TestResponse>, duration: Duration) -> PerformanceMetrics {
        let total_requests = responses.len();
        let successful_requests = responses.iter().filter(|r| r.success).count();
        let failed_requests = total_requests - successful_requests;
        
        // Throughput
        let throughput_rps = if duration.as_secs_f64() > 0.0 {
            successful_requests as f64 / duration.as_secs_f64()
        } else {
            0.0
        };
        
        // Latency metrics
        let response_times: Vec<f64> = responses
            .iter()
            .filter(|r| r.success)
            .map(|r| r.response_time_ms as f64)
            .collect();
        
        let latency_metrics = if !response_times.is_empty() {
            let mut histogram = Histogram::new();
            for &time in &response_times {
                histogram.increment(time as u64).ok();
            }
            
            let sum: f64 = response_times.iter().sum();
            let mean = sum / response_times.len() as f64;
            
            let variance: f64 = response_times
                .iter()
                .map(|&x| (x - mean).powi(2))
                .sum::<f64>() / response_times.len() as f64;
            
            LatencyMetrics {
                min: histogram.minimum().unwrap_or(0) as f64,
                max: histogram.maximum().unwrap_or(0) as f64,
                mean,
                median: histogram.percentile(50.0).unwrap_or(0) as f64,
                p90: histogram.percentile(90.0).unwrap_or(0) as f64,
                p95: histogram.percentile(95.0).unwrap_or(0) as f64,
                p99: histogram.percentile(99.0).unwrap_or(0) as f64,
                p99_9: histogram.percentile(99.9).unwrap_or(0) as f64,
                stddev: variance.sqrt(),
            }
        } else {
            LatencyMetrics {
                min: 0.0,
                max: 0.0,
                mean: 0.0,
                median: 0.0,
                p90: 0.0,
                p95: 0.0,
                p99: 0.0,
                p99_9: 0.0,
                stddev: 0.0,
            }
        };
        
        // Connection metrics
        let connection_success_rate = if total_requests > 0 {
            (successful_requests as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };
        
        let connection_metrics = ConnectionMetrics {
            total_connections: total_requests,
            successful_connections: successful_requests,
            failed_connections: failed_requests,
            connection_success_rate,
            avg_connection_time_ms: latency_metrics.mean,
        };
        
        // Resource metrics (simplified - in real implementation would use system monitoring)
        let resource_metrics = ResourceMetrics {
            memory_usage_mb: 0.0, // Would require system monitoring
            cpu_usage_percent: 0.0, // Would require system monitoring
            network_io_bytes: 0, // Would require system monitoring
        };
        
        // Error metrics
        let mut error_types = HashMap::new();
        let mut timeout_count = 0;
        
        for response in &responses {
            if let Some(error) = &response.error {
                if error.contains("timeout") {
                    timeout_count += 1;
                }
                *error_types.entry(error.clone()).or_insert(0) += 1;
            }
        }
        
        let error_rate_percent = if total_requests > 0 {
            (failed_requests as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };
        
        let error_metrics = ErrorMetrics {
            total_errors: failed_requests,
            error_rate_percent,
            error_types,
            timeout_count,
        };
        
        PerformanceMetrics {
            throughput_rps,
            latency_ms: latency_metrics,
            connection_metrics,
            resource_utilization: resource_metrics,
            error_metrics,
        }
    }

    pub fn print_performance_report(&self, metrics: &PerformanceMetrics) {
        println!("\n=== Performance Test Results ===");
        println!("Throughput: {:.2} requests/second", metrics.throughput_rps);
        
        println!("\n--- Latency Metrics (ms) ---");
        println!("Min: {:.2}", metrics.latency_ms.min);
        println!("Max: {:.2}", metrics.latency_ms.max);
        println!("Mean: {:.2}", metrics.latency_ms.mean);
        println!("Median: {:.2}", metrics.latency_ms.median);
        println!("90th percentile: {:.2}", metrics.latency_ms.p90);
        println!("95th percentile: {:.2}", metrics.latency_ms.p95);
        println!("99th percentile: {:.2}", metrics.latency_ms.p99);
        println!("99.9th percentile: {:.2}", metrics.latency_ms.p99_9);
        println!("Standard deviation: {:.2}", metrics.latency_ms.stddev);
        
        println!("\n--- Connection Metrics ---");
        println!("Total connections: {}", metrics.connection_metrics.total_connections);
        println!("Successful connections: {}", metrics.connection_metrics.successful_connections);
        println!("Failed connections: {}", metrics.connection_metrics.failed_connections);
        println!("Success rate: {:.2}%", metrics.connection_metrics.connection_success_rate);
        
        println!("\n--- Error Metrics ---");
        println!("Total errors: {}", metrics.error_metrics.total_errors);
        println!("Error rate: {:.2}%", metrics.error_metrics.error_rate_percent);
        println!("Timeouts: {}", metrics.error_metrics.timeout_count);
        
        if !metrics.error_metrics.error_types.is_empty() {
            println!("\n--- Error Types ---");
            for (error_type, count) in &metrics.error_metrics.error_types {
                println!("{}: {}", error_type, count);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_latency_calculation() {
        let responses = vec![
            TestResponse {
                status: 200,
                headers: HashMap::new(),
                body: "OK".to_string(),
                response_time_ms: 100,
                success: true,
                error: None,
            },
            TestResponse {
                status: 200,
                headers: HashMap::new(),
                body: "OK".to_string(),
                response_time_ms: 200,
                success: true,
                error: None,
            },
            TestResponse {
                status: 200,
                headers: HashMap::new(),
                body: "OK".to_string(),
                response_time_ms: 300,
                success: true,
                error: None,
            },
        ];
        
        let config = PerformanceTestConfig {
            base_url: "http://localhost".to_string(),
            warmup_requests: 0,
            measurement_requests: 3,
            concurrent_connections: 1,
            test_duration_seconds: 10,
            requests: vec![],
        };
        
        let tester = PerformanceTester::new(config);
        let metrics = tester.calculate_metrics(responses, Duration::from_secs(1));
        
        assert_eq!(metrics.throughput_rps, 3.0);
        assert_eq!(metrics.latency_ms.mean, 200.0);
        assert_eq!(metrics.connection_metrics.successful_connections, 3);
    }
}