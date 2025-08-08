use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing::{info, error};
use anyhow::Result;

use crate::{
    security::{SecurityTester, SecurityTestConfig, SecurityTestResults},
    http_client::{HttpTester, TestRequest as HttpTestRequest},
    load_tester::{LoadTester, LoadTestConfig},
    performance::{PerformanceTester, PerformanceTestConfig},
};

#[derive(Debug, Deserialize)]
pub struct TestRequest {
    pub url: String,
    pub endpoints: Option<String>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: String,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

pub async fn create_app() -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/test/xss", post(test_xss))
        .route("/api/test/csrf", post(test_csrf))
        .route("/api/test/ssl", post(test_ssl))
        .route("/api/test/headers", post(test_headers))
        .route("/api/test/sql-injection", post(test_sql_injection))
        .route("/api/test/all-security", post(test_all_security))
        .route("/api/health", get(health_check))
        .nest_service("/static", ServeDir::new("static"))
        .layer(CorsLayer::permissive())
}

async fn serve_index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn health_check() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse::success("Server is running"))
}

async fn test_xss(Json(params): Json<TestRequest>) -> Json<ApiResponse<SecurityTestResults>> {
    info!("XSS test requested for URL: {}", params.url);
    
    let endpoints = parse_endpoints(params.endpoints);
    let config = SecurityTestConfig {
        base_url: params.url,
        test_authentication: false,
        test_authorization: false,
        test_input_validation: false,
        test_sql_injection: false,
        test_xss: true,
        test_csrf: false,
        test_security_headers: false,
        test_ssl_tls: false,
        auth_token: params.auth_token,
        test_endpoints: endpoints,
    };

    match run_security_test(config).await {
        Ok(results) => Json(ApiResponse::success(results)),
        Err(e) => {
            error!("XSS test failed: {}", e);
            Json(ApiResponse::error(format!("Test failed: {}", e)))
        }
    }
}

async fn test_csrf(Json(params): Json<TestRequest>) -> Json<ApiResponse<SecurityTestResults>> {
    info!("CSRF test requested for URL: {}", params.url);
    
    let endpoints = parse_endpoints(params.endpoints);
    let config = SecurityTestConfig {
        base_url: params.url,
        test_authentication: false,
        test_authorization: false,
        test_input_validation: false,
        test_sql_injection: false,
        test_xss: false,
        test_csrf: true,
        test_security_headers: false,
        test_ssl_tls: false,
        auth_token: params.auth_token,
        test_endpoints: endpoints,
    };

    match run_security_test(config).await {
        Ok(results) => Json(ApiResponse::success(results)),
        Err(e) => {
            error!("CSRF test failed: {}", e);
            Json(ApiResponse::error(format!("Test failed: {}", e)))
        }
    }
}

async fn test_ssl(Json(params): Json<TestRequest>) -> Json<ApiResponse<SecurityTestResults>> {
    info!("SSL test requested for URL: {}", params.url);
    
    let endpoints = parse_endpoints(params.endpoints);
    let config = SecurityTestConfig {
        base_url: params.url,
        test_authentication: false,
        test_authorization: false,
        test_input_validation: false,
        test_sql_injection: false,
        test_xss: false,
        test_csrf: false,
        test_security_headers: false,
        test_ssl_tls: true,
        auth_token: params.auth_token,
        test_endpoints: endpoints,
    };

    match run_security_test(config).await {
        Ok(results) => Json(ApiResponse::success(results)),
        Err(e) => {
            error!("SSL test failed: {}", e);
            Json(ApiResponse::error(format!("Test failed: {}", e)))
        }
    }
}

async fn test_headers(Json(params): Json<TestRequest>) -> Json<ApiResponse<SecurityTestResults>> {
    info!("Security headers test requested for URL: {}", params.url);
    
    let endpoints = parse_endpoints(params.endpoints);
    let config = SecurityTestConfig {
        base_url: params.url,
        test_authentication: false,
        test_authorization: false,
        test_input_validation: false,
        test_sql_injection: false,
        test_xss: false,
        test_csrf: false,
        test_security_headers: true,
        test_ssl_tls: false,
        auth_token: params.auth_token,
        test_endpoints: endpoints,
    };

    match run_security_test(config).await {
        Ok(results) => Json(ApiResponse::success(results)),
        Err(e) => {
            error!("Headers test failed: {}", e);
            Json(ApiResponse::error(format!("Test failed: {}", e)))
        }
    }
}

async fn test_sql_injection(Json(params): Json<TestRequest>) -> Json<ApiResponse<SecurityTestResults>> {
    info!("SQL injection test requested for URL: {}", params.url);
    
    let endpoints = parse_endpoints(params.endpoints);
    let config = SecurityTestConfig {
        base_url: params.url,
        test_authentication: false,
        test_authorization: false,
        test_input_validation: false,
        test_sql_injection: true,
        test_xss: false,
        test_csrf: false,
        test_security_headers: false,
        test_ssl_tls: false,
        auth_token: params.auth_token,
        test_endpoints: endpoints,
    };

    match run_security_test(config).await {
        Ok(results) => Json(ApiResponse::success(results)),
        Err(e) => {
            error!("SQL injection test failed: {}", e);
            Json(ApiResponse::error(format!("Test failed: {}", e)))
        }
    }
}

async fn test_all_security(Json(params): Json<TestRequest>) -> Json<ApiResponse<SecurityTestResults>> {
    info!("All security tests requested for URL: {}", params.url);
    
    let endpoints = parse_endpoints(params.endpoints);
    let config = SecurityTestConfig {
        base_url: params.url,
        test_authentication: true,
        test_authorization: true,
        test_input_validation: true,
        test_sql_injection: true,
        test_xss: true,
        test_csrf: true,
        test_security_headers: true,
        test_ssl_tls: true,
        auth_token: params.auth_token,
        test_endpoints: endpoints,
    };

    match run_security_test(config).await {
        Ok(results) => Json(ApiResponse::success(results)),
        Err(e) => {
            error!("All security tests failed: {}", e);
            Json(ApiResponse::error(format!("Test failed: {}", e)))
        }
    }
}

async fn run_security_test(config: SecurityTestConfig) -> Result<SecurityTestResults> {
    let security_tester = SecurityTester::new(config);
    let results = security_tester.run_security_tests().await;
    Ok(results)
}

fn parse_endpoints(endpoints: Option<String>) -> Vec<String> {
    match endpoints {
        Some(endpoints_str) => {
            endpoints_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
        None => vec!["/".to_string()],
    }
}

pub async fn start_server(port: u16) -> Result<()> {
    let app = create_app().await;
    
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Server running on http://0.0.0.0:{}", port);
    
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_endpoints() {
        assert_eq!(parse_endpoints(None), vec!["/"]);
        assert_eq!(
            parse_endpoints(Some("/api,/test".to_string())),
            vec!["/api", "/test"]
        );
        assert_eq!(
            parse_endpoints(Some("/api, /test , /admin".to_string())),
            vec!["/api", "/test", "/admin"]
        );
    }
}