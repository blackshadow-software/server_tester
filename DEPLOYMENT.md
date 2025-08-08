# Security Tester Web Interface - Deployment Guide

## 🚀 Quick Start

### Local Development
```bash
# Build the project
cargo build --release

# Start the web server on default port 8080
./target/release/server_tester server

# Or specify a custom port
./target/release/server_tester server --port 3000
```

### Access the Web Interface
- Open your browser and go to: `http://localhost:8080`
- The web interface provides a user-friendly way to test websites

## 🌐 VPS Deployment

### 1. Prepare Your VPS
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install required system dependencies
sudo apt install -y build-essential pkg-config libssl-dev
```

### 2. Deploy the Application
```bash
# Clone your repository (or upload files)
git clone <your-repo-url>
cd server_tester

# Build for production
cargo build --release

# Create a systemd service (optional)
sudo nano /etc/systemd/system/security-tester.service
```

### 3. Systemd Service Configuration
```ini
[Unit]
Description=Security Tester Web Service
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/path/to/server_tester
ExecStart=/path/to/server_tester/target/release/server_tester server --port 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 4. Start the Service
```bash
# Reload systemd and start service
sudo systemctl daemon-reload
sudo systemctl enable security-tester
sudo systemctl start security-tester

# Check status
sudo systemctl status security-tester
```

### 5. Configure Firewall
```bash
# Allow HTTP traffic on your chosen port
sudo ufw allow 8080/tcp
sudo ufw enable
```

## 🔧 Configuration Options

### Environment Variables
```bash
# Set custom port
export PORT=8080

# Start server with environment
./target/release/server_tester server --port $PORT
```

### Nginx Reverse Proxy (Recommended)
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📡 API Endpoints

Your deployed service will provide these REST API endpoints:

### Health Check
```bash
GET http://your-vps-ip:8080/api/health
```

### Security Tests
All test endpoints accept POST requests with JSON payload:

```json
{
    "url": "https://example.com",
    "endpoints": "/api/login,/contact,/admin",  // optional
    "auth_token": "Bearer your-token"           // optional
}
```

**Available Test Endpoints:**
- `POST /api/test/xss` - XSS vulnerability testing
- `POST /api/test/csrf` - CSRF protection testing  
- `POST /api/test/ssl` - SSL/TLS configuration testing
- `POST /api/test/headers` - Security headers analysis
- `POST /api/test/sql-injection` - SQL injection testing
- `POST /api/test/all-security` - Comprehensive security testing

### Example API Usage

```bash
# Test XSS vulnerabilities
curl -X POST http://your-vps-ip:8080/api/test/xss \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "endpoints": "/search,/contact"
  }'

# Test security headers
curl -X POST http://your-vps-ip:8080/api/test/headers \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://portfolio.blackshadow.software"
  }'
```

## 🛡️ Security Considerations

### Rate Limiting
Consider implementing rate limiting to prevent abuse:
```bash
# Install fail2ban
sudo apt install fail2ban

# Configure custom jail for your service
sudo nano /etc/fail2ban/jail.d/security-tester.conf
```

### Authentication (Optional)
For production use, consider adding API key authentication:
```bash
# Add environment variable
export API_KEY="your-secret-api-key"
```

### HTTPS Setup
Use Let's Encrypt for SSL certificates:
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d your-domain.com
```

## 📊 Monitoring

### Log Files
```bash
# View service logs
sudo journalctl -u security-tester -f

# Application logs location
tail -f /var/log/security-tester.log
```

### Health Monitoring
```bash
# Simple health check script
#!/bin/bash
response=$(curl -s http://localhost:8080/api/health)
if [[ $response == *"success"* ]]; then
    echo "Service is healthy"
else
    echo "Service is down"
    sudo systemctl restart security-tester
fi
```

## 🔥 Usage Examples

### Web Interface
1. Open `http://your-vps-ip:8080` in browser
2. Enter target URL (e.g., `https://example.com`)
3. Optional: Add specific endpoints to test
4. Click on desired security test
5. View detailed results with vulnerabilities and recommendations

### API Integration
```javascript
// JavaScript example
const testWebsite = async (url, testType) => {
    const response = await fetch(`http://your-vps-ip:8080/api/test/${testType}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url: url,
            endpoints: '/api,/login,/admin'
        })
    });
    
    const results = await response.json();
    console.log('Security test results:', results);
};

// Test XSS vulnerabilities
testWebsite('https://example.com', 'xss');
```

### Python Integration
```python
import requests

def test_security(url, test_type, endpoints=None):
    payload = {
        "url": url,
        "endpoints": endpoints
    }
    
    response = requests.post(
        f"http://your-vps-ip:8080/api/test/{test_type}",
        json=payload
    )
    
    return response.json()

# Example usage
result = test_security('https://example.com', 'all-security', '/api,/login')
print(f"Security Score: {result['data']['security_score']}%")
```

## 🚨 Legal Notice

**Important:** Only use this tool to test websites that you own or have explicit permission to test. Unauthorized security testing may violate laws and terms of service.

This tool is designed for defensive security purposes only. Use responsibly and ethically.