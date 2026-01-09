#!/usr/bin/env python3
"""
CUSP V6 Demo Script
Demonstrates all major features of the CUSP V6 Unified Security Platform
"""

import json
import time
import requests
import subprocess
import signal
import sys
from pathlib import Path

# Configuration
DASHBOARD_PORT = 8891
ORCHESTRATOR_PORT = 8892
BASE_DIR = Path(__file__).parent

def start_service(service_type, port):
    """Start a CUSP V6 service in the background."""
    cmd = [
        sys.executable,
        str(BASE_DIR / "CUSP_V6_Unified.py"),
        f"--{service_type}",
        f"--{service_type[:4]}-port", str(port)
    ]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)  # Give it time to start
    return process

def stop_service(process):
    """Stop a CUSP V6 service."""
    process.send_signal(signal.SIGTERM)
    process.wait(timeout=5)

def test_dashboard():
    """Test Dashboard API features."""
    print("\n" + "="*60)
    print("Testing CUSP V6 Dashboard API")
    print("="*60)
    
    process = start_service("dashboard", DASHBOARD_PORT)
    base_url = f"http://localhost:{DASHBOARD_PORT}"
    
    try:
        # Test health endpoint
        print("\n1. Health Check:")
        response = requests.get(f"{base_url}/health")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {json.dumps(response.json(), indent=2)}")
        
        # Add telemetry data
        print("\n2. Adding Telemetry Data:")
        telemetry = {
            "source": "demo-server",
            "metric_type": "cpu_usage",
            "metric_value": 67.5,
            "metadata": {"hostname": "demo-01", "region": "us-east"}
        }
        response = requests.post(f"{base_url}/telemetry", json=telemetry)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        
        # Add security alert
        print("\n3. Adding Security Alert:")
        alert = {
            "severity": "high",
            "alert_type": "intrusion_attempt",
            "message": "Multiple failed SSH login attempts from 192.168.1.100",
            "source": "ssh-monitor"
        }
        response = requests.post(f"{base_url}/alerts", json=alert)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        
        # Get alerts
        print("\n4. Retrieving Alerts:")
        response = requests.get(f"{base_url}/alerts?limit=10")
        alerts_data = response.json()
        print(f"   Status: {response.status_code}")
        print(f"   Total Alerts: {alerts_data['count']}")
        if alerts_data['alerts']:
            print(f"   Latest Alert: {alerts_data['alerts'][0]['message']}")
        
        # Get stats
        print("\n5. System Statistics:")
        response = requests.get(f"{base_url}/stats")
        stats = response.json()
        print(f"   Status: {response.status_code}")
        print(f"   Stats: {json.dumps(stats, indent=2)}")
        
    finally:
        stop_service(process)
        print("\n✓ Dashboard tests completed")

def test_orchestrator():
    """Test Orchestrator API features."""
    print("\n" + "="*60)
    print("Testing CUSP V6 Orchestrator API")
    print("="*60)
    
    process = start_service("orchestrator", ORCHESTRATOR_PORT)
    base_url = f"http://localhost:{ORCHESTRATOR_PORT}"
    
    try:
        # Test root endpoint
        print("\n1. Orchestrator Status:")
        response = requests.get(f"{base_url}/")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {json.dumps(response.json(), indent=2)}")
        
        # Add IDS rule
        print("\n2. Adding IDS/IPS Rule:")
        rule = {
            "rule_id": "demo-rule-001",
            "platform": "suricata",
            "rule_content": 'alert tcp any any -> any 22 (msg:"SSH Connection Detected"; sid:1000001; rev:1;)'
        }
        response = requests.post(f"{base_url}/rules", json=rule)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        
        # Get rules
        print("\n3. Retrieving IDS/IPS Rules:")
        response = requests.get(f"{base_url}/rules")
        rules_data = response.json()
        print(f"   Status: {response.status_code}")
        print(f"   Total Rules: {rules_data['count']}")
        if rules_data['rules']:
            print(f"   Rule ID: {rules_data['rules'][0]['rule_id']}")
        
        # Add orchestration policy
        print("\n4. Adding Orchestration Policy:")
        policy = {
            "policy_id": "auto-block-high-severity",
            "name": "Auto-Block High Severity Threats",
            "description": "Automatically respond to high severity security alerts",
            "conditions": {
                "type": "alert",
                "severity": "high",
                "threshold": 3
            },
            "actions": {
                "type": "alert",
                "severity": "critical",
                "alert_type": "policy_triggered",
                "message": "Policy triggered: Multiple high severity alerts detected"
            }
        }
        response = requests.post(f"{base_url}/policies", json=policy)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        
        # Get policies
        print("\n5. Retrieving Policies:")
        response = requests.get(f"{base_url}/policies")
        policies_data = response.json()
        print(f"   Status: {response.status_code}")
        print(f"   Total Policies: {policies_data['count']}")
        if policies_data['policies']:
            print(f"   Policy Name: {policies_data['policies'][0]['name']}")
        
        # Get compliance report
        print("\n6. Compliance Report (NIST CSF):")
        response = requests.get(f"{base_url}/compliance/NIST_CSF")
        report = response.json()
        print(f"   Status: {response.status_code}")
        print(f"   Framework: {report['framework']}")
        print(f"   Controls Checked: {report['summary']['total']}")
        print(f"   Compliant: {report['summary']['compliant']}")
        
        # Get specific control evidence
        print("\n7. Control Evidence (ISO 27001 - A.9):")
        response = requests.get(f"{base_url}/compliance/ISO_27001/A.9")
        evidence = response.json()
        print(f"   Status: {response.status_code}")
        print(f"   Control: {evidence['control_id']}")
        print(f"   Status: {evidence['status']}")
        print(f"   Checks: {len(evidence['checks'])}")
        
    finally:
        stop_service(process)
        print("\n✓ Orchestrator tests completed")

def demo_cli_usage():
    """Demonstrate CLI usage."""
    print("\n" + "="*60)
    print("CUSP V6 CLI Usage Examples")
    print("="*60)
    
    print("\n1. Version Information:")
    result = subprocess.run(
        [sys.executable, str(BASE_DIR / "CUSP_V6_Unified.py"), "--version"],
        capture_output=True,
        text=True
    )
    print(f"   {result.stdout.strip()}")
    
    print("\n2. Database Operations:")
    print("   Testing database initialization...")
    test_code = """
from CUSP_V6_Unified import DatabaseManager
db = DatabaseManager('/tmp/demo_cusp.db')
db.add_telemetry('cli-demo', 'memory_usage', 78.2, {'test': 'demo'})
db.add_alert('medium', 'demo_alert', 'CLI demonstration alert')
print('✓ Database operations successful')
"""
    subprocess.run([sys.executable, "-c", test_code])
    
    print("\n3. Auto-Heal Module:")
    print("   Testing SHA-256 calculation...")
    test_code = """
from CUSP_V6_Unified import AutoHealManager, DatabaseManager
import tempfile
db = DatabaseManager('/tmp/demo_cusp.db')
autoheal = AutoHealManager(db)
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write('test content')
    hash_val = autoheal.calculate_sha256(f.name)
print(f'✓ SHA-256 hash calculated: {hash_val[:16]}...')
"""
    subprocess.run([sys.executable, "-c", test_code])

def main():
    """Run all demonstrations."""
    print("\n" + "="*60)
    print("CUSP V6 Unified Security Platform - Comprehensive Demo")
    print("="*60)
    print("\nThis demo will test all major components:")
    print("  • Dashboard API (telemetry, alerts, stats)")
    print("  • Orchestrator API (policies, rules, compliance)")
    print("  • CLI operations (database, auto-heal)")
    
    try:
        demo_cli_usage()
        test_dashboard()
        test_orchestrator()
        
        print("\n" + "="*60)
        print("All CUSP V6 demonstrations completed successfully! ✓")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nError during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
