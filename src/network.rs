use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use futures::future::join_all;
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTestConfig {
    pub target_host: String,
    pub target_ports: Vec<u16>,
    pub timeout_ms: u64,
    pub connection_attempts: usize,
    pub concurrent_connections: usize,
    pub bandwidth_test_duration_seconds: u64,
    pub latency_test_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkTestResults {
    pub port_scan_results: HashMap<u16, PortStatus>,
    pub latency_results: LatencyResults,
    pub bandwidth_results: Option<BandwidthResults>,
    pub connection_results: ConnectionResults,
    pub dns_results: DnsResults,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortStatus {
    pub is_open: bool,
    pub response_time_ms: u64,
    pub service_banner: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LatencyResults {
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub median_ms: f64,
    pub packet_loss_percent: f64,
    pub jitter_ms: f64,
    pub measurements: Vec<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BandwidthResults {
    pub upload_mbps: f64,
    pub download_mbps: f64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub test_duration_seconds: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionResults {
    pub max_concurrent_connections: usize,
    pub connection_establishment_time_ms: f64,
    pub connection_success_rate: f64,
    pub failed_connections: usize,
    pub successful_connections: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsResults {
    pub resolution_time_ms: f64,
    pub resolved_ips: Vec<String>,
    pub dns_servers_tested: Vec<String>,
    pub success: bool,
    pub error: Option<String>,
}

pub struct NetworkTester {
    config: NetworkTestConfig,
}

impl NetworkTester {
    pub fn new(config: NetworkTestConfig) -> Self {
        Self { config }
    }

    pub async fn run_comprehensive_test(&self) -> Result<NetworkTestResults> {
        // Run all network tests concurrently where possible
        let port_scan_future = self.scan_ports();
        let latency_future = self.test_latency();
        let dns_future = self.test_dns_resolution();
        let connection_future = self.test_connection_limits();

        let (port_results, latency_results, dns_results, connection_results) = 
            tokio::join!(port_scan_future, latency_future, dns_future, connection_future);

        // Bandwidth test (optional, as it's resource intensive)
        let bandwidth_results = if self.config.bandwidth_test_duration_seconds > 0 {
            Some(self.test_bandwidth().await?)
        } else {
            None
        };

        Ok(NetworkTestResults {
            port_scan_results: port_results?,
            latency_results: latency_results?,
            bandwidth_results,
            connection_results: connection_results?,
            dns_results: dns_results?,
        })
    }

    pub async fn scan_ports(&self) -> Result<HashMap<u16, PortStatus>> {
        let mut results = HashMap::new();
        let timeout = Duration::from_millis(self.config.timeout_ms);

        // Create concurrent tasks for port scanning
        let tasks: Vec<_> = self.config.target_ports.iter().map(|&port| {
            let host = self.config.target_host.clone();
            tokio::spawn(async move {
                let start_time = Instant::now();
                let addr = format!("{}:{}", host, port);
                
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                    Ok(Ok(_stream)) => {
                        let response_time = start_time.elapsed().as_millis() as u64;
                        
                        // Try to read service banner (simplified for async)
                        let service_banner: Option<String> = None;

                        (port, PortStatus {
                            is_open: true,
                            response_time_ms: response_time,
                            service_banner,
                            error: None,
                        })
                    }
                    Ok(Err(e)) => {
                        let response_time = start_time.elapsed().as_millis() as u64;
                        (port, PortStatus {
                            is_open: false,
                            response_time_ms: response_time,
                            service_banner: None,
                            error: Some(e.to_string()),
                        })
                    }
                    Err(_) => {
                        let response_time = start_time.elapsed().as_millis() as u64;
                        (port, PortStatus {
                            is_open: false,
                            response_time_ms: response_time,
                            service_banner: None,
                            error: Some("Timeout".to_string()),
                        })
                    }
                }
            })
        }).collect();

        let scan_results = join_all(tasks).await;
        for result in scan_results {
            match result {
                Ok((port, status)) => {
                    results.insert(port, status);
                }
                Err(e) => {
                    eprintln!("Task failed: {}", e);
                }
            }
        }

        Ok(results)
    }

    pub async fn test_latency(&self) -> Result<LatencyResults> {
        let mut measurements = Vec::new();
        let target_addr = format!("{}:80", self.config.target_host);
        
        for _ in 0..self.config.latency_test_count {
            let start_time = Instant::now();
            
            match tokio::time::timeout(
                Duration::from_millis(self.config.timeout_ms),
                tokio::net::TcpStream::connect(&target_addr)
            ).await {
                Ok(Ok(_)) => {
                    let latency = start_time.elapsed().as_millis() as f64;
                    measurements.push(latency);
                }
                _ => {
                    // Consider timeouts as maximum latency
                    measurements.push(self.config.timeout_ms as f64);
                }
            }
            
            // Small delay between measurements
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        if measurements.is_empty() {
            return Ok(LatencyResults {
                min_ms: 0.0,
                max_ms: 0.0,
                avg_ms: 0.0,
                median_ms: 0.0,
                packet_loss_percent: 100.0,
                jitter_ms: 0.0,
                measurements,
            });
        }

        measurements.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let min_ms = measurements[0];
        let max_ms = measurements[measurements.len() - 1];
        let avg_ms = measurements.iter().sum::<f64>() / measurements.len() as f64;
        let median_ms = if measurements.len() % 2 == 0 {
            (measurements[measurements.len() / 2 - 1] + measurements[measurements.len() / 2]) / 2.0
        } else {
            measurements[measurements.len() / 2]
        };

        // Calculate jitter (variation in latency)
        let variance = measurements.iter()
            .map(|&x| (x - avg_ms).powi(2))
            .sum::<f64>() / measurements.len() as f64;
        let jitter_ms = variance.sqrt();

        // Calculate packet loss (timeouts)
        let timeouts = measurements.iter()
            .filter(|&&x| x >= self.config.timeout_ms as f64)
            .count();
        let packet_loss_percent = (timeouts as f64 / measurements.len() as f64) * 100.0;

        Ok(LatencyResults {
            min_ms,
            max_ms,
            avg_ms,
            median_ms,
            packet_loss_percent,
            jitter_ms,
            measurements,
        })
    }

    pub async fn test_bandwidth(&self) -> Result<BandwidthResults> {
        // This is a simplified bandwidth test
        // In a real implementation, you'd want to use a dedicated bandwidth testing protocol
        
        let test_duration = Duration::from_secs(self.config.bandwidth_test_duration_seconds);
        let start_time = Instant::now();
        
        let mut total_bytes_sent = 0u64;
        let mut total_bytes_received = 0u64;
        
        // Create test data
        let test_data = vec![0u8; 64 * 1024]; // 64KB chunks
        
        let target_addr = format!("{}:80", self.config.target_host);
        
        while start_time.elapsed() < test_duration {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(&target_addr).await {
                // Upload test
                if let Ok(bytes_sent) = stream.write(&test_data).await {
                    total_bytes_sent += bytes_sent as u64;
                }
                
                // Download test (read response)
                let mut buffer = vec![0u8; 64 * 1024];
                if let Ok(bytes_received) = stream.read(&mut buffer).await {
                    total_bytes_received += bytes_received as u64;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        let actual_duration = start_time.elapsed().as_secs_f64();
        
        let upload_mbps = (total_bytes_sent as f64 * 8.0) / (actual_duration * 1_000_000.0);
        let download_mbps = (total_bytes_received as f64 * 8.0) / (actual_duration * 1_000_000.0);
        
        Ok(BandwidthResults {
            upload_mbps,
            download_mbps,
            total_bytes_sent,
            total_bytes_received,
            test_duration_seconds: actual_duration,
        })
    }

    pub async fn test_connection_limits(&self) -> Result<ConnectionResults> {
        let mut successful_connections = 0;
        let mut failed_connections = 0;
        let mut connection_times = Vec::new();
        
        let target_addr = format!("{}:80", self.config.target_host);
        
        // Test concurrent connections
        let tasks: Vec<_> = (0..self.config.concurrent_connections).map(|_| {
            let addr = target_addr.clone();
            let timeout = self.config.timeout_ms;
            
            tokio::spawn(async move {
                let start_time = Instant::now();
                
                match tokio::time::timeout(
                    Duration::from_millis(timeout),
                    tokio::net::TcpStream::connect(&addr)
                ).await {
                    Ok(Ok(_stream)) => {
                        let connection_time = start_time.elapsed();
                        (true, connection_time.as_millis() as f64)
                    }
                    _ => (false, 0.0),
                }
            })
        }).collect();

        let results = join_all(tasks).await;
        
        for result in results {
            match result {
                Ok((success, time)) => {
                    if success {
                        successful_connections += 1;
                        connection_times.push(time);
                    } else {
                        failed_connections += 1;
                    }
                }
                Err(_) => {
                    failed_connections += 1;
                }
            }
        }
        
        let connection_success_rate = if successful_connections + failed_connections > 0 {
            (successful_connections as f64 / (successful_connections + failed_connections) as f64) * 100.0
        } else {
            0.0
        };
        
        let avg_connection_time = if !connection_times.is_empty() {
            connection_times.iter().sum::<f64>() / connection_times.len() as f64
        } else {
            0.0
        };
        
        Ok(ConnectionResults {
            max_concurrent_connections: successful_connections,
            connection_establishment_time_ms: avg_connection_time,
            connection_success_rate,
            failed_connections,
            successful_connections,
        })
    }

    pub async fn test_dns_resolution(&self) -> Result<DnsResults> {
        let start_time = Instant::now();
        
        match tokio::net::lookup_host(format!("{}:80", self.config.target_host)).await {
            Ok(addresses) => {
                let resolution_time = start_time.elapsed().as_millis() as f64;
                let resolved_ips: Vec<String> = addresses
                    .map(|addr| addr.ip().to_string())
                    .collect();
                
                Ok(DnsResults {
                    resolution_time_ms: resolution_time,
                    resolved_ips,
                    dns_servers_tested: vec!["system_default".to_string()],
                    success: true,
                    error: None,
                })
            }
            Err(e) => {
                let resolution_time = start_time.elapsed().as_millis() as f64;
                Ok(DnsResults {
                    resolution_time_ms: resolution_time,
                    resolved_ips: vec![],
                    dns_servers_tested: vec!["system_default".to_string()],
                    success: false,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    pub async fn test_specific_port(&self, port: u16) -> Result<PortStatus> {
        let start_time = Instant::now();
        let addr = format!("{}:{}", self.config.target_host, port);
        let timeout = Duration::from_millis(self.config.timeout_ms);

        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_stream)) => {
                let response_time = start_time.elapsed().as_millis() as u64;
                
                // Try to read service banner (simplified for async)
                let service_banner: Option<String> = None;

                Ok(PortStatus {
                    is_open: true,
                    response_time_ms: response_time,
                    service_banner,
                    error: None,
                })
            }
            Ok(Err(e)) => {
                let response_time = start_time.elapsed().as_millis() as u64;
                Ok(PortStatus {
                    is_open: false,
                    response_time_ms: response_time,
                    service_banner: None,
                    error: Some(e.to_string()),
                })
            }
            Err(_) => {
                let response_time = start_time.elapsed().as_millis() as u64;
                Ok(PortStatus {
                    is_open: false,
                    response_time_ms: response_time,
                    service_banner: None,
                    error: Some("Timeout".to_string()),
                })
            }
        }
    }

    pub fn print_network_report(&self, results: &NetworkTestResults) {
        println!("\n=== Network Test Results ===");
        
        println!("\n--- Port Scan Results ---");
        for (&port, status) in &results.port_scan_results {
            let status_str = if status.is_open { "OPEN" } else { "CLOSED" };
            println!("Port {}: {} ({} ms)", port, status_str, status.response_time_ms);
            if let Some(banner) = &status.service_banner {
                println!("  Service banner: {}", banner.trim());
            }
            if let Some(error) = &status.error {
                println!("  Error: {}", error);
            }
        }
        
        println!("\n--- Latency Results ---");
        println!("Min: {:.2} ms", results.latency_results.min_ms);
        println!("Max: {:.2} ms", results.latency_results.max_ms);
        println!("Average: {:.2} ms", results.latency_results.avg_ms);
        println!("Median: {:.2} ms", results.latency_results.median_ms);
        println!("Jitter: {:.2} ms", results.latency_results.jitter_ms);
        println!("Packet Loss: {:.2}%", results.latency_results.packet_loss_percent);
        
        if let Some(bandwidth) = &results.bandwidth_results {
            println!("\n--- Bandwidth Results ---");
            println!("Upload: {:.2} Mbps", bandwidth.upload_mbps);
            println!("Download: {:.2} Mbps", bandwidth.download_mbps);
            println!("Total bytes sent: {} bytes", bandwidth.total_bytes_sent);
            println!("Total bytes received: {} bytes", bandwidth.total_bytes_received);
            println!("Test duration: {:.2} seconds", bandwidth.test_duration_seconds);
        }
        
        println!("\n--- Connection Results ---");
        println!("Successful connections: {}", results.connection_results.successful_connections);
        println!("Failed connections: {}", results.connection_results.failed_connections);
        println!("Success rate: {:.2}%", results.connection_results.connection_success_rate);
        println!("Average connection time: {:.2} ms", results.connection_results.connection_establishment_time_ms);
        
        println!("\n--- DNS Results ---");
        println!("Resolution time: {:.2} ms", results.dns_results.resolution_time_ms);
        println!("Success: {}", results.dns_results.success);
        if !results.dns_results.resolved_ips.is_empty() {
            println!("Resolved IPs: {}", results.dns_results.resolved_ips.join(", "));
        }
        if let Some(error) = &results.dns_results.error {
            println!("Error: {}", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_creation() {
        let config = NetworkTestConfig {
            target_host: "example.com".to_string(),
            target_ports: vec![80, 443, 22],
            timeout_ms: 5000,
            connection_attempts: 3,
            concurrent_connections: 10,
            bandwidth_test_duration_seconds: 30,
            latency_test_count: 100,
        };
        
        assert_eq!(config.target_host, "example.com");
        assert_eq!(config.target_ports.len(), 3);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[tokio::test]
    async fn test_dns_resolution() {
        let config = NetworkTestConfig {
            target_host: "google.com".to_string(),
            target_ports: vec![80],
            timeout_ms: 5000,
            connection_attempts: 1,
            concurrent_connections: 1,
            bandwidth_test_duration_seconds: 0,
            latency_test_count: 1,
        };
        
        let tester = NetworkTester::new(config);
        let dns_result = tester.test_dns_resolution().await.unwrap();
        
        assert!(dns_result.success);
        assert!(!dns_result.resolved_ips.is_empty());
    }
}