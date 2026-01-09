#!/bin/bash
# CUSP V6 Unified - Production Deployment Examples
# ================================================

# Stop script on error
set -e

echo "CUSP V6 Unified Security Platform - Production Examples"
echo "========================================================"

# Example 1: Start Dashboard Only
# --------------------------------
example_dashboard() {
    echo ""
    echo "Example 1: Running Dashboard API"
    echo "---------------------------------"
    echo "Starting dashboard on port 8443 with API key authentication..."
    echo ""
    echo "Command:"
    echo "  export CUSP_API_KEY='your-secure-api-key-here'"
    echo "  python3 CUSP_V6_Unified.py --dashboard --dash-port 8443"
    echo ""
    echo "Access at: https://localhost:8443/docs"
}

# Example 2: Start Orchestrator Only
# -----------------------------------
example_orchestrator() {
    echo ""
    echo "Example 2: Running Orchestrator API"
    echo "------------------------------------"
    echo "Starting orchestrator on port 8450..."
    echo ""
    echo "Command:"
    echo "  export CUSP_API_KEY='your-secure-api-key-here'"
    echo "  python3 CUSP_V6_Unified.py --orchestrator --orch-port 8450"
    echo ""
    echo "Access at: https://localhost:8450/docs"
}

# Example 3: Auto-Heal with GitHub Integration
# ---------------------------------------------
example_autoheal() {
    echo ""
    echo "Example 3: Auto-Heal from GitHub"
    echo "--------------------------------"
    echo "Monitor and auto-update application from GitHub repository..."
    echo ""
    echo "Command:"
    echo "  export GITHUB_TOKEN='your-github-token'"
    echo "  python3 CUSP_V6_Unified.py --autoheal \\"
    echo "    --owner your-org \\"
    echo "    --repo your-repo \\"
    echo "    --asset your-app.py \\"
    echo "    --target /opt/app/your-app.py \\"
    echo "    --health-url http://localhost:8443/health \\"
    echo "    --loop \\"
    echo "    --interval 600"
    echo ""
    echo "With GPG verification:"
    echo "  export CUSP_GPG_KEY='/path/to/gpg/key'"
    echo "  python3 CUSP_V6_Unified.py --autoheal --verify-gpg ..."
}

# Example 4: All-in-One Production Setup
# ---------------------------------------
example_all_in_one() {
    echo ""
    echo "Example 4: All-in-One Production Setup"
    echo "--------------------------------------"
    echo "Run all components together..."
    echo ""
    echo "Command:"
    echo "  export CUSP_API_KEY='your-secure-api-key-here'"
    echo "  export GITHUB_TOKEN='your-github-token'"
    echo "  python3 CUSP_V6_Unified.py --all \\"
    echo "    --owner your-org \\"
    echo "    --repo your-repo \\"
    echo "    --asset your-app.py \\"
    echo "    --target /opt/app/your-app.py \\"
    echo "    --health-url http://localhost:8443/health \\"
    echo "    --loop \\"
    echo "    --interval 600 \\"
    echo "    --dash-port 8443 \\"
    echo "    --orch-port 8450"
}

# Example 5: Systemd Service Configuration
# -----------------------------------------
example_systemd() {
    echo ""
    echo "Example 5: Systemd Service Configuration"
    echo "----------------------------------------"
    echo "Create /etc/systemd/system/cusp-v6-dashboard.service:"
    echo ""
    cat << 'EOF'
[Unit]
Description=CUSP V6 Unified Dashboard
After=network.target

[Service]
Type=simple
User=cusp
Group=cusp
WorkingDirectory=/opt/cusp
Environment="CUSP_API_KEY=your-secure-api-key-here"
ExecStart=/usr/bin/python3 /opt/cusp/CUSP_V6_Unified.py --dashboard --dash-port 8443
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    echo ""
    echo "Enable and start:"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable cusp-v6-dashboard"
    echo "  sudo systemctl start cusp-v6-dashboard"
}

# Example 6: Docker Container
# ----------------------------
example_docker() {
    echo ""
    echo "Example 6: Docker Container"
    echo "--------------------------"
    echo "Create Dockerfile:"
    echo ""
    cat << 'EOF'
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY CUSP_V6_Unified.py .

EXPOSE 8443 8450

ENV CUSP_API_KEY=""
ENV GITHUB_TOKEN=""

CMD ["python3", "CUSP_V6_Unified.py", "--all", \
     "--dash-port", "8443", \
     "--orch-port", "8450"]
EOF
    echo ""
    echo "Build and run:"
    echo "  docker build -t cusp-v6:latest ."
    echo "  docker run -d -p 8443:8443 -p 8450:8450 \\"
    echo "    -e CUSP_API_KEY='your-key' \\"
    echo "    -e GITHUB_TOKEN='your-token' \\"
    echo "    --name cusp-v6 \\"
    echo "    cusp-v6:latest"
}

# Example 7: API Usage with curl
# -------------------------------
example_api_usage() {
    echo ""
    echo "Example 7: API Usage with curl"
    echo "------------------------------"
    echo ""
    echo "# Add telemetry data:"
    echo "curl -X POST http://localhost:8443/telemetry \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -H 'X-API-Key: your-api-key' \\"
    echo "  -d '{"
    echo "    \"source\": \"web-server-01\","
    echo "    \"metric_type\": \"cpu_usage\","
    echo "    \"metric_value\": 78.5,"
    echo "    \"metadata\": {\"hostname\": \"web01\", \"region\": \"us-east-1\"}"
    echo "  }'"
    echo ""
    echo "# Add security alert:"
    echo "curl -X POST http://localhost:8443/alerts \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -H 'X-API-Key: your-api-key' \\"
    echo "  -d '{"
    echo "    \"severity\": \"high\","
    echo "    \"alert_type\": \"intrusion_attempt\","
    echo "    \"message\": \"Multiple failed login attempts\","
    echo "    \"source\": \"auth-service\""
    echo "  }'"
    echo ""
    echo "# Get alerts:"
    echo "curl http://localhost:8443/alerts?limit=50&severity=high"
    echo ""
    echo "# Get system stats:"
    echo "curl http://localhost:8443/stats"
    echo ""
    echo "# Add IDS rule:"
    echo "curl -X POST http://localhost:8450/rules \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -H 'X-API-Key: your-api-key' \\"
    echo "  -d '{"
    echo "    \"rule_id\": \"custom-001\","
    echo "    \"platform\": \"suricata\","
    echo "    \"rule_content\": \"alert tcp any any -> any 22 (msg:SSH; sid:1000001;)\""
    echo "  }'"
    echo ""
    echo "# Get compliance report:"
    echo "curl http://localhost:8450/compliance/NIST_CSF"
}

# Example 8: Python Integration
# ------------------------------
example_python_integration() {
    echo ""
    echo "Example 8: Python Integration"
    echo "-----------------------------"
    echo ""
    cat << 'EOF'
# Import CUSP V6 modules
from CUSP_V6_Unified import (
    DatabaseManager,
    AutoHealManager,
    IDSIPSManager,
    ComplianceGenerator,
    Orchestrator
)

# Initialize
db = DatabaseManager('/opt/cusp/production.db')
autoheal = AutoHealManager(db)
ids_ips = IDSIPSManager(db)
compliance = ComplianceGenerator(db)

# Add telemetry
db.add_telemetry('app-server', 'response_time', 145.2, {
    'endpoint': '/api/users',
    'method': 'GET'
})

# Add security alert
db.add_alert('critical', 'sql_injection', 
             'SQL injection attempt detected', 
             'web-firewall')

# Add IDS rule
ids_ips.add_rule('prod-rule-001', 'suricata',
                'alert tcp any any -> $HOME_NET 3306 '
                '(msg:"MySQL connection"; sid:2000001;)')

# Generate compliance evidence
evidence = compliance.generate_evidence('ISO_27001', 'A.12')
report = compliance.generate_report('NIST_CSF')

# Perform auto-heal
success = autoheal.perform_update(
    owner='your-org',
    repo='your-repo',
    asset='app.py',
    target='/opt/app/app.py',
    health_url='http://localhost:8443/health'
)
EOF
}

# Example 9: Monitoring and Logging
# ----------------------------------
example_monitoring() {
    echo ""
    echo "Example 9: Monitoring and Logging"
    echo "---------------------------------"
    echo ""
    echo "# Monitor logs in real-time:"
    echo "journalctl -u cusp-v6-dashboard -f"
    echo ""
    echo "# Query database for alerts:"
    echo "sqlite3 cusp_v6.db \"SELECT * FROM alerts WHERE severity='high' ORDER BY timestamp DESC LIMIT 10;\""
    echo ""
    echo "# Monitor auto-heal events:"
    echo "sqlite3 cusp_v6.db \"SELECT * FROM autoheal_events ORDER BY timestamp DESC LIMIT 10;\""
    echo ""
    echo "# Export telemetry data:"
    echo "sqlite3 -header -csv cusp_v6.db \"SELECT * FROM telemetry WHERE timestamp > datetime('now', '-1 day');\" > telemetry_export.csv"
}

# Example 10: Production Checklist
# ---------------------------------
example_production_checklist() {
    echo ""
    echo "Example 10: Production Deployment Checklist"
    echo "-------------------------------------------"
    echo ""
    echo "1. Security:"
    echo "   ☐ Set strong CUSP_API_KEY"
    echo "   ☐ Configure HTTPS/TLS for APIs"
    echo "   ☐ Set up firewall rules"
    echo "   ☐ Configure GitHub token with minimal permissions"
    echo "   ☐ Enable GPG verification for auto-heal"
    echo ""
    echo "2. Monitoring:"
    echo "   ☐ Set up log rotation"
    echo "   ☐ Configure database backups"
    echo "   ☐ Monitor disk space for database growth"
    echo "   ☐ Set up alerts for service failures"
    echo ""
    echo "3. Performance:"
    echo "   ☐ Tune database connection pool"
    echo "   ☐ Configure appropriate auto-heal intervals"
    echo "   ☐ Set resource limits (CPU, memory)"
    echo "   ☐ Enable database vacuuming"
    echo ""
    echo "4. High Availability:"
    echo "   ☐ Set up service restart on failure"
    echo "   ☐ Configure load balancing if needed"
    echo "   ☐ Test rollback procedures"
    echo "   ☐ Document recovery procedures"
}

# Main menu
show_menu() {
    echo ""
    echo "Select an example to view:"
    echo "=========================="
    echo "1.  Dashboard API"
    echo "2.  Orchestrator API"
    echo "3.  Auto-Heal with GitHub"
    echo "4.  All-in-One Setup"
    echo "5.  Systemd Service"
    echo "6.  Docker Container"
    echo "7.  API Usage with curl"
    echo "8.  Python Integration"
    echo "9.  Monitoring and Logging"
    echo "10. Production Checklist"
    echo "11. Show All Examples"
    echo "0.  Exit"
    echo ""
    read -p "Enter choice [0-11]: " choice
    
    case $choice in
        1) example_dashboard ;;
        2) example_orchestrator ;;
        3) example_autoheal ;;
        4) example_all_in_one ;;
        5) example_systemd ;;
        6) example_docker ;;
        7) example_api_usage ;;
        8) example_python_integration ;;
        9) example_monitoring ;;
        10) example_production_checklist ;;
        11) 
            example_dashboard
            example_orchestrator
            example_autoheal
            example_all_in_one
            example_systemd
            example_docker
            example_api_usage
            example_python_integration
            example_monitoring
            example_production_checklist
            ;;
        0) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice"; show_menu ;;
    esac
    
    # Show menu again unless exiting
    if [ "$choice" != "0" ]; then
        show_menu
    fi
}

# If script is run with arguments, show all examples
if [ "$1" == "--all" ] || [ "$1" == "-a" ]; then
    example_dashboard
    example_orchestrator
    example_autoheal
    example_all_in_one
    example_systemd
    example_docker
    example_api_usage
    example_python_integration
    example_monitoring
    example_production_checklist
    echo ""
    echo "All examples displayed."
else
    # Otherwise show interactive menu
    show_menu
fi
