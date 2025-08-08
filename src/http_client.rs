use reqwest::{Client, Response, Method, header::HeaderMap};
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct HttpTester {
    client: Client,
    base_url: String,
    default_headers: HeaderMap,
    timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub expected_status: u16,
    pub expected_response_time_ms: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub response_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
}

impl HttpTester {
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.to_string(),
            default_headers: HeaderMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.client = Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");
        self
    }

    pub fn with_default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    pub async fn execute_test(&self, test_request: &TestRequest) -> Result<TestResponse> {
        let start_time = Instant::now();
        let url = format!("{}{}", self.base_url, test_request.path);
        
        let method = match test_request.method.to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            "HEAD" => Method::HEAD,
            "OPTIONS" => Method::OPTIONS,
            _ => Method::GET,
        };

        let mut request = self.client.request(method, &url);

        // Add default headers
        for (key, value) in &self.default_headers {
            request = request.header(key, value);
        }

        // Add custom headers
        for (key, value) in &test_request.headers {
            request = request.header(key, value);
        }

        // Add body if present
        if let Some(body) = &test_request.body {
            request = request.body(body.clone());
        }

        match request.send().await {
            Ok(response) => {
                let response_time_ms = start_time.elapsed().as_millis() as u64;
                let status = response.status().as_u16();
                
                let headers: HashMap<String, String> = response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();

                let body = response.text().await.unwrap_or_default();
                
                let success = status == test_request.expected_status &&
                    test_request.expected_response_time_ms
                        .map(|expected| response_time_ms <= expected)
                        .unwrap_or(true);

                Ok(TestResponse {
                    status,
                    headers,
                    body,
                    response_time_ms,
                    success,
                    error: None,
                })
            }
            Err(e) => {
                let response_time = start_time.elapsed().as_millis() as u64;
                Ok(TestResponse {
                    status: 0,
                    headers: HashMap::new(),
                    body: String::new(),
                    response_time_ms: response_time,
                    success: false,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    pub async fn get(&self, path: &str) -> Result<TestResponse> {
        let test_request = TestRequest {
            method: "GET".to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: None,
            expected_status: 200,
            expected_response_time_ms: None,
        };
        self.execute_test(&test_request).await
    }

    pub async fn post(&self, path: &str, body: &str) -> Result<TestResponse> {
        let test_request = TestRequest {
            method: "POST".to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: Some(body.to_string()),
            expected_status: 200,
            expected_response_time_ms: None,
        };
        self.execute_test(&test_request).await
    }

    pub async fn health_check(&self, endpoint: &str) -> Result<bool> {
        match self.get(endpoint).await {
            Ok(response) => Ok(response.status >= 200 && response.status < 300),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_http_get() {
        let mut server = Server::new_async().await;
        let mock = server.mock("GET", "/test")
            .with_status(200)
            .with_body("Hello World")
            .create_async()
            .await;

        let tester = HttpTester::new(&server.url());
        let response = tester.get("/test").await.unwrap();
        
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "Hello World");
        assert!(response.success);
        
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_http_post() {
        let mut server = Server::new_async().await;
        let mock = server.mock("POST", "/api/data")
            .with_status(201)
            .with_body("{\"id\": 1}")
            .create_async()
            .await;

        let tester = HttpTester::new(&server.url());
        let response = tester.post("/api/data", "{\"name\": \"test\"}").await.unwrap();
        
        assert_eq!(response.status, 201);
        assert!(response.body.contains("\"id\": 1"));
        
        mock.assert_async().await;
    }
}