use crate::http_client::{HttpTester, TestRequest, TestResponse};
use futures::future::join_all;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Semaphore;
use serde::{Serialize, Deserialize};
use histogram::Histogram;
use tracing::{info, warn, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestConfig {
    pub concurrent_users: usize,
    pub total_requests: usize,
    pub duration_seconds: Option<u64>,
    pub ramp_up_seconds: u64,
    pub think_time_ms: u64,
    pub base_url: String,
    pub requests: Vec<TestRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoadTestResults {
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub average_response_time_ms: f64,
    pub min_response_time_ms: u64,
    pub max_response_time_ms: u64,
    pub p50_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub requests_per_second: f64,
    pub duration_seconds: f64,
    pub error_rate: f64,
    pub status_codes: std::collections::HashMap<u16, usize>,
    pub errors: Vec<String>,
}

pub struct LoadTester {
    http_tester: HttpTester,
    config: LoadTestConfig,
}

impl LoadTester {
    pub fn new(config: LoadTestConfig) -> Self {
        let http_tester = HttpTester::new(&config.base_url);
        Self {
            http_tester,
            config,
        }
    }

    pub async fn run_load_test(&self) -> LoadTestResults {
        info!("Starting load test with {} concurrent users", self.config.concurrent_users);
        
        let start_time = Instant::now();
        let semaphore = Arc::new(Semaphore::new(self.config.concurrent_users));
        let mut tasks = Vec::new();
        
        let requests_per_user = self.config.total_requests / self.config.concurrent_users;
        let remaining_requests = self.config.total_requests % self.config.concurrent_users;

        for user_id in 0..self.config.concurrent_users {
            let user_requests = if user_id < remaining_requests {
                requests_per_user + 1
            } else {
                requests_per_user
            };

            let semaphore = Arc::clone(&semaphore);
            let http_tester = self.http_tester.clone();
            let requests = self.config.requests.clone();
            let think_time = Duration::from_millis(self.config.think_time_ms);
            let ramp_up_delay = Duration::from_millis(
                (user_id as u64 * self.config.ramp_up_seconds * 1000) / self.config.concurrent_users as u64
            );

            let task = tokio::spawn(async move {
                tokio::time::sleep(ramp_up_delay).await;
                
                let mut results = Vec::new();
                for _ in 0..user_requests {
                    let _permit = semaphore.acquire().await.unwrap();
                    
                    for request in &requests {
                        let result = http_tester.execute_test(request).await;
                        match result {
                            Ok(response) => results.push(response),
                            Err(e) => {
                                error!("Request failed: {}", e);
                                results.push(TestResponse {
                                    status: 0,
                                    headers: std::collections::HashMap::new(),
                                    body: String::new(),
                                    response_time_ms: 0,
                                    success: false,
                                    error: Some(e.to_string()),
                                });
                            }
                        }
                        
                        if think_time.as_millis() > 0 {
                            tokio::time::sleep(think_time).await;
                        }
                    }
                }
                results
            });
            
            tasks.push(task);
        }

        let all_results = join_all(tasks).await;
        let duration = start_time.elapsed();
        
        let mut all_responses = Vec::new();
        for task_result in all_results {
            match task_result {
                Ok(responses) => all_responses.extend(responses),
                Err(e) => error!("Task failed: {}", e),
            }
        }

        self.calculate_results(all_responses, duration)
    }

    pub async fn run_stress_test(&self, max_users: usize, step_size: usize, step_duration: Duration) -> Vec<LoadTestResults> {
        info!("Starting stress test, ramping up to {} users", max_users);
        
        let mut results = Vec::new();
        let mut current_users = step_size;
        
        while current_users <= max_users {
            info!("Testing with {} concurrent users", current_users);
            
            let mut stress_config = self.config.clone();
            stress_config.concurrent_users = current_users;
            stress_config.duration_seconds = Some(step_duration.as_secs());
            
            let stress_tester = LoadTester::new(stress_config);
            let result = stress_tester.run_duration_test(step_duration).await;
            results.push(result);
            
            current_users += step_size;
        }
        
        results
    }

    pub async fn run_spike_test(&self, normal_load: usize, spike_load: usize, spike_duration: Duration) -> LoadTestResults {
        info!("Starting spike test: {} -> {} users for {:?}", normal_load, spike_load, spike_duration);
        
        // Normal load phase
        let mut normal_config = self.config.clone();
        normal_config.concurrent_users = normal_load;
        let normal_tester = LoadTester::new(normal_config);
        
        // Spike phase
        let mut spike_config = self.config.clone();
        spike_config.concurrent_users = spike_load;
        let spike_tester = LoadTester::new(spike_config);
        
        let spike_results = spike_tester.run_duration_test(spike_duration).await;
        spike_results
    }

    async fn run_duration_test(&self, duration: Duration) -> LoadTestResults {
        let start_time = Instant::now();
        let semaphore = Arc::new(Semaphore::new(self.config.concurrent_users));
        let mut tasks = Vec::new();
        
        for user_id in 0..self.config.concurrent_users {
            let semaphore = Arc::clone(&semaphore);
            let http_tester = self.http_tester.clone();
            let requests = self.config.requests.clone();
            let think_time = Duration::from_millis(self.config.think_time_ms);
            let test_duration = duration;
            
            let task = tokio::spawn(async move {
                let user_start = Instant::now();
                let mut results = Vec::new();
                
                while user_start.elapsed() < test_duration {
                    let _permit = semaphore.acquire().await.unwrap();
                    
                    for request in &requests {
                        if user_start.elapsed() >= test_duration {
                            break;
                        }
                        
                        let result = http_tester.execute_test(request).await;
                        match result {
                            Ok(response) => results.push(response),
                            Err(e) => {
                                results.push(TestResponse {
                                    status: 0,
                                    headers: std::collections::HashMap::new(),
                                    body: String::new(),
                                    response_time_ms: 0,
                                    success: false,
                                    error: Some(e.to_string()),
                                });
                            }
                        }
                        
                        if think_time.as_millis() > 0 {
                            tokio::time::sleep(think_time).await;
                        }
                    }
                }
                results
            });
            
            tasks.push(task);
        }

        let all_results = join_all(tasks).await;
        let actual_duration = start_time.elapsed();
        
        let mut all_responses = Vec::new();
        for task_result in all_results {
            match task_result {
                Ok(responses) => all_responses.extend(responses),
                Err(e) => error!("Task failed: {}", e),
            }
        }

        self.calculate_results(all_responses, actual_duration)
    }

    fn calculate_results(&self, responses: Vec<TestResponse>, duration: Duration) -> LoadTestResults {
        let total_requests = responses.len();
        let successful_requests = responses.iter().filter(|r| r.success).count();
        let failed_requests = total_requests - successful_requests;
        
        let mut response_times: Vec<u64> = responses.iter().map(|r| r.response_time_ms).collect();
        response_times.sort_unstable();
        
        let mut histogram = Histogram::new();
        for &time in &response_times {
            histogram.increment(time).ok();
        }
        
        let average_response_time = if !response_times.is_empty() {
            response_times.iter().sum::<u64>() as f64 / response_times.len() as f64
        } else {
            0.0
        };
        
        let min_response_time = response_times.first().copied().unwrap_or(0);
        let max_response_time = response_times.last().copied().unwrap_or(0);
        
        let p50 = histogram.percentile(50.0).unwrap_or(0) as f64;
        let p95 = histogram.percentile(95.0).unwrap_or(0) as f64;
        let p99 = histogram.percentile(99.0).unwrap_or(0) as f64;
        
        let requests_per_second = if duration.as_secs_f64() > 0.0 {
            total_requests as f64 / duration.as_secs_f64()
        } else {
            0.0
        };
        
        let error_rate = if total_requests > 0 {
            (failed_requests as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };
        
        let mut status_codes = std::collections::HashMap::new();
        for response in &responses {
            *status_codes.entry(response.status).or_insert(0) += 1;
        }
        
        let errors: Vec<String> = responses
            .iter()
            .filter_map(|r| r.error.as_ref().cloned())
            .collect();
        
        LoadTestResults {
            total_requests,
            successful_requests,
            failed_requests,
            average_response_time_ms: average_response_time,
            min_response_time_ms: min_response_time,
            max_response_time_ms: max_response_time,
            p50_response_time_ms: p50,
            p95_response_time_ms: p95,
            p99_response_time_ms: p99,
            requests_per_second,
            duration_seconds: duration.as_secs_f64(),
            error_rate,
            status_codes,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_load_test_config() {
        let config = LoadTestConfig {
            concurrent_users: 2,
            total_requests: 10,
            duration_seconds: None,
            ramp_up_seconds: 1,
            think_time_ms: 100,
            base_url: "http://localhost:8080".to_string(),
            requests: vec![TestRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                expected_response_time_ms: Some(1000),
            }],
        };
        
        assert_eq!(config.concurrent_users, 2);
        assert_eq!(config.total_requests, 10);
    }

    #[tokio::test]
    async fn test_results_calculation() {
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
                status: 500,
                headers: HashMap::new(),
                body: "Error".to_string(),
                response_time_ms: 200,
                success: false,
                error: Some("Server error".to_string()),
            },
        ];
        
        let config = LoadTestConfig {
            concurrent_users: 1,
            total_requests: 2,
            duration_seconds: None,
            ramp_up_seconds: 0,
            think_time_ms: 0,
            base_url: "http://localhost".to_string(),
            requests: vec![],
        };
        
        let tester = LoadTester::new(config);
        let results = tester.calculate_results(responses, Duration::from_secs(1));
        
        assert_eq!(results.total_requests, 2);
        assert_eq!(results.successful_requests, 1);
        assert_eq!(results.failed_requests, 1);
        assert_eq!(results.error_rate, 50.0);
    }
}