# CUSP V6 Unified — Enterprise-Grade Unified Security Platform

A comprehensive, single-file security platform that provides enterprise-grade security orchestration, automated healing, IDS/IPS management, compliance reporting, and unified monitoring.

## Features

### 🔄 Auto-Heal / Self-Update
- SHA-256 hash verification
- Optional GPG signature verification
- Automatic rollback on failure
- Health check integration
- Continuous monitoring mode

### 🛡️ IDS/IPS Rule Manager
- Support for multiple platforms:
  - Suricata
  - Snort
  - Windows Defender
- Dynamic rule deployment
- Rule versioning and management

### 📊 Unified Dashboard API
- Real-time telemetry collection
- Security alert management
- System statistics and metrics
- SQLite-backed storage
- RESTful API interface

### 🤖 Orchestrator (SOAR-lite)
- Policy-driven automation
- Condition evaluation engine
- Multi-action execution
- Alert-based triggers
- Time-based policies

### 📋 Compliance Generator
- Framework support:
  - NIST Cybersecurity Framework (CSF)
  - ISO 27001
  - PCI DSS
- Automated evidence collection
- Control mapping
- Compliance reports

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install fastapi uvicorn pydantic requests
```

## Quick Start

### 1. Run Dashboard API

Start the unified dashboard on port 8443:

```bash
python CUSP_V6_Unified.py --dashboard --dash-port 8443
```

Access the API:
- Health check: `http://localhost:8443/health`
- API documentation: `http://localhost:8443/docs`

### 2. Run Orchestrator API

Start the orchestrator on port 8450:

```bash
python CUSP_V6_Unified.py --orchestrator --orch-port 8450
```

Access the API:
- API documentation: `http://localhost:8450/docs`

### 3. Run Auto-Heal (One-shot)

Perform a single auto-heal check and update:

```bash
python CUSP_V6_Unified.py --autoheal \
    --owner YourGitHubOrg \
    --repo YourRepo \
    --asset your_app.py \
    --target /opt/app/your_app.py \
    --health-url http://127.0.0.1:8443/health
```

### 4. Run Auto-Heal in Loop

Continuous monitoring with updates every 10 minutes:

```bash
python CUSP_V6_Unified.py --autoheal \
    --owner YourGitHubOrg \
    --repo YourRepo \
    --asset your_app.py \
    --target /opt/app/your_app.py \
    --health-url http://127.0.0.1:8443/health \
    --loop \
    --interval 600
```

### 5. Run All Components Together

Start dashboard, orchestrator, and auto-heal in a single process:

```bash
python CUSP_V6_Unified.py --all \
    --owner YourGitHubOrg \
    --repo YourRepo \
    --asset your_app.py \
    --target /opt/app/your_app.py \
    --health-url http://127.0.0.1:8443/health \
    --loop \
    --interval 600
```

## API Usage Examples

### Dashboard API

#### Add Telemetry Data
```bash
curl -X POST http://localhost:8443/telemetry \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "source": "web-server",
    "metric_type": "cpu_usage",
    "metric_value": 45.5,
    "metadata": {"hostname": "server-01"}
  }'
```

#### Add Security Alert
```bash
curl -X POST http://localhost:8443/alerts \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "severity": "high",
    "alert_type": "intrusion_attempt",
    "message": "Multiple failed login attempts detected",
    "source": "auth-service"
  }'
```

#### Get Recent Alerts
```bash
curl http://localhost:8443/alerts?limit=50&severity=high
```

#### Get System Statistics
```bash
curl http://localhost:8443/stats
```

### Orchestrator API

#### Add IDS/IPS Rule
```bash
curl -X POST http://localhost:8450/rules \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "rule_id": "custom-001",
    "platform": "suricata",
    "rule_content": "alert tcp any any -> any 22 (msg:\"SSH Connection\"; sid:1000001;)"
  }'
```

#### Deploy Rules to Platform
```bash
curl -X POST http://localhost:8450/rules/suricata/deploy \
  -H "X-API-Key: your-api-key"
```

#### Add Orchestration Policy
```bash
curl -X POST http://localhost:8450/policies \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "policy_id": "block-high-severity",
    "name": "Block High Severity Threats",
    "description": "Automatically block IPs with high severity alerts",
    "conditions": {
      "type": "alert",
      "severity": "high",
      "threshold": 3
    },
    "actions": {
      "type": "block_ip",
      "ip_address": "192.168.1.100"
    }
  }'
```

#### Get Compliance Report
```bash
curl http://localhost:8450/compliance/NIST_CSF
```

#### Get Specific Control Evidence
```bash
curl http://localhost:8450/compliance/ISO_27001/A.9
```

## Configuration

### Environment Variables

Set these environment variables for enhanced security:

```bash
# API authentication key
export CUSP_API_KEY="your-secret-api-key"

# GPG key path for signature verification
export CUSP_GPG_KEY="/path/to/gpg/key"

# GitHub token for private repositories
export GITHUB_TOKEN="your-github-token"
```

### Database

CUSP V6 uses SQLite by default. The database file `cusp_v6.db` is created automatically in the current directory.

Database schema includes:
- **telemetry**: System metrics and monitoring data
- **alerts**: Security alerts and events
- **autoheal_events**: Auto-heal activity logs
- **ids_rules**: IDS/IPS rule definitions
- **policies**: Orchestration policies
- **compliance_evidence**: Compliance audit trail

## Security Considerations

### API Authentication

When `CUSP_API_KEY` is set, all write operations require the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-secret-api-key" ...
```

### GPG Signature Verification

Enable GPG verification for auto-heal updates:

```bash
python CUSP_V6_Unified.py --autoheal --verify-gpg ...
```

Requires:
- GPG installed on the system
- Signature files (.sig) available for downloads
- `CUSP_GPG_KEY` environment variable set

### File Permissions

The auto-heal module sets executable permissions (755) on updated files. Ensure the target directory has appropriate ownership and permissions.

### Network Security

- Use HTTPS/TLS for production deployments
- Configure firewall rules to restrict API access
- Use strong API keys
- Implement rate limiting at the network level

## Architecture

```
CUSP V6 Unified
├── Database Manager (SQLite)
│   ├── Telemetry storage
│   ├── Alert management
│   └── Audit logging
│
├── Auto-Heal Manager
│   ├── SHA-256 verification
│   ├── GPG signature checking
│   ├── Automatic rollback
│   └── Health monitoring
│
├── IDS/IPS Manager
│   ├── Rule management
│   ├── Multi-platform support
│   └── Dynamic deployment
│
├── Orchestrator (SOAR-lite)
│   ├── Policy engine
│   ├── Condition evaluation
│   └── Action execution
│
├── Compliance Generator
│   ├── Framework mapping
│   ├── Evidence collection
│   └── Report generation
│
└── API Servers
    ├── Dashboard API (FastAPI)
    └── Orchestrator API (FastAPI)
```

## Supported Platforms

- **Linux**: Full support for all features
- **Windows**: Limited IDS/IPS support (Windows Defender only)
- **macOS**: Dashboard and orchestrator fully supported

## Troubleshooting

### Common Issues

**Import Error: FastAPI not installed**
```bash
pip install fastapi uvicorn pydantic
```

**Import Error: requests not installed**
```bash
pip install requests
```

**Permission denied on auto-heal**
- Ensure write permissions on target file
- Run with appropriate user privileges

**Health check fails**
- Verify the health URL is accessible
- Check if the service is running
- Review firewall rules

**IDS/IPS deployment fails**
- Verify platform-specific directories exist
- Check service permissions
- Review platform-specific logs

## Development

### Running Tests

The platform includes built-in health checks and logging. Monitor the console output for operational status.

### Extending Functionality

The modular design allows easy extension:

1. **Add new IDS/IPS platforms**: Extend `IDSIPSManager` class
2. **Add compliance frameworks**: Update `ComplianceGenerator.FRAMEWORKS`
3. **Add orchestrator actions**: Extend `Orchestrator.execute_actions()`

## License

Enterprise-Grade Unified Security Platform

## Version History

- **v6.0.0** - Initial unified release
  - Integrated auto-heal, IDS/IPS, dashboard, orchestrator, and compliance
  - Single-file deployment
  - FastAPI-based REST APIs
  - SQLite database backend

## Support

For issues and questions:
1. Check the logs for detailed error messages
2. Review the API documentation at `/docs` endpoint
3. Verify all dependencies are installed
4. Ensure proper permissions and network connectivity

## Credits

CUSP V6 Unified Security Platform - Next Generation Cyber Defence System
