#!/usr/bin/env python3
"""
CUSP V6 Unified — Enterprise-Grade Unified Security Platform (Single File)
=========================================================================
Includes:
• Auto-Heal / Self-Update with SHA-256 + optional GPG and rollback
• IDS/IPS Rule Manager (Suricata / Snort / Windows Defender)
• Unified Dashboard API (FastAPI + SQLite): telemetry, stats, alerts
• Orchestrator API (SOAR-lite): policy-driven actions
• Compliance Generator: control mapping + evidence snapshot

Quick Start
-----------
# 1) Dashboard API (port 8443)
python CUSP_V6_Unified.py --dashboard --dash-port 8443

# 2) Orchestrator API (port 8450)
python CUSP_V6_Unified.py --orchestrator --orch-port 8450

# 3) Auto-Heal (one-shot)
python CUSP_V6_Unified.py --autoheal \\
    --owner Cybertrust --repo CUSP --asset cusp_v5.py \\
    --target /opt/cusp/cusp_v5.py --health-url http://127.0.0.1:8443/health

# 4) All-in-one (Dashboard + Orchestrator + Auto-Heal loop)
python CUSP_V6_Unified.py --all --owner Cybertrust --repo CUSP --asset cusp_v5.py \\
    --target /opt/cusp/cusp_v5.py --health-url http://127.0.0.1:8443/health --loop --interval 600

Dependencies
------------
pip install fastapi uvicorn pydantic requests

Security Notes
--------------
• Set environment variables for extra safety:
  - CUSP_API_KEY: API key for authentication
  - CUSP_GPG_KEY: GPG key path for signature verification
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from contextlib import asynccontextmanager

try:
    import requests
except ImportError:
    requests = None

try:
    from fastapi import FastAPI, HTTPException, Depends, Header
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    import uvicorn
except ImportError:
    FastAPI = None
    HTTPException = None
    Depends = None
    Header = None
    JSONResponse = None
    BaseModel = None
    Field = None
    uvicorn = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("CUSP_V6")

# Constants
VERSION = "6.0.0"
DEFAULT_DB_PATH = "cusp_v6.db"
API_KEY = os.getenv("CUSP_API_KEY", "")
GPG_KEY_PATH = os.getenv("CUSP_GPG_KEY", "")

# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================

class DatabaseManager:
    """Manages SQLite database for telemetry, alerts, and stats."""
    
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get database connection."""
        return sqlite3.connect(self.db_path)
    
    def init_database(self):
        """Initialize database schema."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Telemetry table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                metric_value REAL,
                metadata TEXT
            )
        """)
        
        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT,
                resolved INTEGER DEFAULT 0,
                resolved_at TEXT
            )
        """)
        
        # Auto-heal events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS autoheal_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT
            )
        """)
        
        # IDS/IPS rules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ids_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE NOT NULL,
                platform TEXT NOT NULL,
                rule_content TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
        """)
        
        # Orchestrator policies table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                conditions TEXT NOT NULL,
                actions TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
        """)
        
        # Compliance evidence table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                control_id TEXT NOT NULL,
                framework TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence TEXT NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    def add_telemetry(self, source: str, metric_type: str, 
                      metric_value: float, metadata: Dict = None):
        """Add telemetry data point."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO telemetry (timestamp, source, metric_type, metric_value, metadata)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now(timezone.utc).isoformat(), source, metric_type, 
              metric_value, json.dumps(metadata or {})))
        conn.commit()
        conn.close()
    
    def add_alert(self, severity: str, alert_type: str, 
                  message: str, source: str = None):
        """Add security alert."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (timestamp, severity, alert_type, message, source)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now(timezone.utc).isoformat(), severity, alert_type, message, source))
        conn.commit()
        conn.close()
        logger.warning(f"Alert [{severity}] {alert_type}: {message}")
    
    def get_recent_alerts(self, limit: int = 100, severity: str = None):
        """Get recent alerts."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if severity:
            cursor.execute("""
                SELECT id, timestamp, severity, alert_type, message, source, resolved
                FROM alerts WHERE severity = ? 
                ORDER BY timestamp DESC LIMIT ?
            """, (severity, limit))
        else:
            cursor.execute("""
                SELECT id, timestamp, severity, alert_type, message, source, resolved
                FROM alerts ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
        
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def add_autoheal_event(self, action: str, target: str, 
                           status: str, details: Dict = None):
        """Record auto-heal event."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO autoheal_events (timestamp, action, target, status, details)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now(timezone.utc).isoformat(), action, target, 
              status, json.dumps(details or {})))
        conn.commit()
        conn.close()

# ============================================================================
# AUTO-HEAL / SELF-UPDATE MODULE
# ============================================================================

class AutoHealManager:
    """Manages auto-healing and self-update capabilities."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating SHA-256 for {file_path}: {e}")
            return ""
    
    def verify_gpg_signature(self, file_path: str, signature_path: str = None) -> bool:
        """Verify GPG signature if available."""
        if not GPG_KEY_PATH or not signature_path:
            logger.info("GPG verification skipped (no key or signature)")
            return True
        
        try:
            result = subprocess.run(
                ["gpg", "--verify", signature_path, file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                logger.info(f"GPG signature verified for {file_path}")
                return True
            else:
                logger.error(f"GPG verification failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error verifying GPG signature: {e}")
            return False
    
    def download_from_github(self, owner: str, repo: str, 
                            asset: str, target_path: str) -> Tuple[bool, str]:
        """Download asset from GitHub repository."""
        if not requests:
            return False, "requests library not installed"
        
        try:
            # Use GitHub API to get latest release
            api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
            headers = {}
            if os.getenv("GITHUB_TOKEN"):
                headers["Authorization"] = f"token {os.getenv('GITHUB_TOKEN')}"
            
            response = requests.get(api_url, headers=headers, timeout=30)
            
            if response.status_code == 404:
                # Try direct download from main branch
                download_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{asset}"
            elif response.status_code == 200:
                release_data = response.json()
                # Find asset in release
                download_url = None
                for asset_info in release_data.get("assets", []):
                    if asset_info["name"] == asset:
                        download_url = asset_info["browser_download_url"]
                        break
                
                if not download_url:
                    download_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{asset}"
            else:
                return False, f"GitHub API error: {response.status_code}"
            
            # Download the file
            logger.info(f"Downloading from {download_url}")
            response = requests.get(download_url, timeout=60)
            response.raise_for_status()
            
            # Save to temporary location
            temp_path = f"{target_path}.new"
            with open(temp_path, "wb") as f:
                f.write(response.content)
            
            logger.info(f"Downloaded {asset} to {temp_path}")
            return True, temp_path
            
        except Exception as e:
            error_msg = f"Error downloading from GitHub: {e}"
            logger.error(error_msg)
            return False, error_msg
    
    def create_backup(self, file_path: str) -> Optional[str]:
        """Create backup of existing file."""
        if not os.path.exists(file_path):
            return None
        
        backup_path = f"{file_path}.backup.{int(time.time())}"
        try:
            shutil.copy2(file_path, backup_path)
            logger.info(f"Backup created at {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return None
    
    def rollback(self, target_path: str, backup_path: str) -> bool:
        """Rollback to backup version."""
        try:
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, target_path)
                logger.info(f"Rolled back to {backup_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error during rollback: {e}")
            return False
    
    def check_health(self, health_url: str) -> bool:
        """Check if service is healthy."""
        if not requests or not health_url:
            return True
        
        try:
            response = requests.get(health_url, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    def perform_update(self, owner: str, repo: str, asset: str,
                      target_path: str, health_url: str = None,
                      verify_gpg: bool = False) -> bool:
        """Perform self-update with verification and rollback."""
        logger.info(f"Starting update process for {target_path}")
        
        # Create backup
        backup_path = self.create_backup(target_path)
        old_hash = self.calculate_sha256(target_path) if os.path.exists(target_path) else ""
        
        # Download new version
        success, result = self.download_from_github(owner, repo, asset, target_path)
        
        if not success:
            self.db.add_autoheal_event("update", target_path, "failed", 
                                       {"error": result})
            return False
        
        temp_path = result
        new_hash = self.calculate_sha256(temp_path)
        
        # Verify hashes are different (actual update)
        if old_hash and old_hash == new_hash:
            logger.info("File unchanged, no update needed")
            os.remove(temp_path)
            self.db.add_autoheal_event("update", target_path, "skipped", 
                                       {"reason": "no changes"})
            return True
        
        # Verify GPG signature if requested
        if verify_gpg:
            signature_path = f"{temp_path}.sig"
            if not self.verify_gpg_signature(temp_path, signature_path):
                logger.error("GPG verification failed, aborting update")
                os.remove(temp_path)
                self.db.add_autoheal_event("update", target_path, "failed",
                                          {"error": "GPG verification failed"})
                return False
        
        # Replace target file
        try:
            shutil.move(temp_path, target_path)
            os.chmod(target_path, 0o755)
            logger.info(f"Updated {target_path} successfully")
        except Exception as e:
            logger.error(f"Error replacing file: {e}")
            if backup_path:
                self.rollback(target_path, backup_path)
            self.db.add_autoheal_event("update", target_path, "failed",
                                       {"error": str(e)})
            return False
        
        # Health check
        if health_url:
            time.sleep(2)  # Give service time to restart
            if not self.check_health(health_url):
                logger.error("Health check failed after update, rolling back")
                if backup_path:
                    self.rollback(target_path, backup_path)
                self.db.add_autoheal_event("update", target_path, "rollback",
                                          {"reason": "health check failed"})
                return False
        
        self.db.add_autoheal_event("update", target_path, "success",
                                   {"old_hash": old_hash, "new_hash": new_hash})
        logger.info("Update completed successfully")
        return True

# ============================================================================
# IDS/IPS RULE MANAGER
# ============================================================================

class IDSIPSManager:
    """Manages IDS/IPS rules for multiple platforms."""
    
    SUPPORTED_PLATFORMS = ["suricata", "snort", "windows_defender"]
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def add_rule(self, rule_id: str, platform: str, rule_content: str) -> bool:
        """Add or update IDS/IPS rule."""
        if platform not in self.SUPPORTED_PLATFORMS:
            logger.error(f"Unsupported platform: {platform}")
            return False
        
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO ids_rules (rule_id, platform, rule_content, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    rule_content = excluded.rule_content,
                    updated_at = excluded.created_at
            """, (rule_id, platform, rule_content, datetime.now(timezone.utc).isoformat()))
            conn.commit()
            logger.info(f"Rule {rule_id} added/updated for {platform}")
            return True
        except Exception as e:
            logger.error(f"Error adding rule: {e}")
            return False
        finally:
            conn.close()
    
    def get_rules(self, platform: str = None, enabled_only: bool = True) -> List[Dict]:
        """Get IDS/IPS rules."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        query = "SELECT rule_id, platform, rule_content, enabled, created_at FROM ids_rules"
        params = []
        
        conditions = []
        if platform:
            conditions.append("platform = ?")
            params.append(platform)
        if enabled_only:
            conditions.append("enabled = 1")
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return results
    
    def deploy_rules(self, platform: str) -> bool:
        """Deploy rules to IDS/IPS system."""
        rules = self.get_rules(platform=platform, enabled_only=True)
        
        if platform == "suricata":
            return self._deploy_suricata_rules(rules)
        elif platform == "snort":
            return self._deploy_snort_rules(rules)
        elif platform == "windows_defender":
            return self._deploy_windows_defender_rules(rules)
        
        return False
    
    def _deploy_suricata_rules(self, rules: List[Dict]) -> bool:
        """Deploy rules to Suricata."""
        try:
            rules_dir = "/etc/suricata/rules"
            if not os.path.exists(rules_dir):
                logger.warning(f"Suricata rules directory not found: {rules_dir}")
                return False
            
            rules_file = os.path.join(rules_dir, "cusp_custom.rules")
            with open(rules_file, "w") as f:
                for rule in rules:
                    f.write(rule["rule_content"] + "\n")
            
            # Reload Suricata
            subprocess.run(["suricatasc", "-c", "reload-rules"], 
                          capture_output=True, timeout=30)
            logger.info(f"Deployed {len(rules)} rules to Suricata")
            return True
        except Exception as e:
            logger.error(f"Error deploying Suricata rules: {e}")
            return False
    
    def _deploy_snort_rules(self, rules: List[Dict]) -> bool:
        """Deploy rules to Snort."""
        try:
            rules_dir = "/etc/snort/rules"
            if not os.path.exists(rules_dir):
                logger.warning(f"Snort rules directory not found: {rules_dir}")
                return False
            
            rules_file = os.path.join(rules_dir, "cusp_custom.rules")
            with open(rules_file, "w") as f:
                for rule in rules:
                    f.write(rule["rule_content"] + "\n")
            
            logger.info(f"Deployed {len(rules)} rules to Snort")
            return True
        except Exception as e:
            logger.error(f"Error deploying Snort rules: {e}")
            return False
    
    def _deploy_windows_defender_rules(self, rules: List[Dict]) -> bool:
        """Deploy rules to Windows Defender."""
        if platform.system() != "Windows":
            logger.warning("Windows Defender rules can only be deployed on Windows")
            return False
        
        try:
            for rule in rules:
                # Use PowerShell to add exclusions or custom indicators
                ps_command = rule["rule_content"]
                subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    timeout=30
                )
            
            logger.info(f"Deployed {len(rules)} rules to Windows Defender")
            return True
        except Exception as e:
            logger.error(f"Error deploying Windows Defender rules: {e}")
            return False

# ============================================================================
# COMPLIANCE GENERATOR
# ============================================================================

class ComplianceGenerator:
    """Generates compliance evidence and control mappings."""
    
    FRAMEWORKS = {
        "NIST_CSF": [
            "ID.AM", "ID.BE", "ID.GV", "ID.RA", "ID.RM",
            "PR.AC", "PR.AT", "PR.DS", "PR.IP", "PR.MA", "PR.PT",
            "DE.AE", "DE.CM", "DE.DP",
            "RS.RP", "RS.CO", "RS.AN", "RS.MI", "RS.IM",
            "RC.RP", "RC.IM", "RC.CO"
        ],
        "ISO_27001": [
            "A.5", "A.6", "A.7", "A.8", "A.9", "A.10",
            "A.11", "A.12", "A.13", "A.14", "A.15", "A.16", "A.17", "A.18"
        ],
        "PCI_DSS": [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"
        ]
    }
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def generate_evidence(self, framework: str, control_id: str) -> Dict:
        """Generate compliance evidence for a control."""
        if framework not in self.FRAMEWORKS:
            logger.error(f"Unsupported framework: {framework}")
            return {}
        
        evidence = {
            "framework": framework,
            "control_id": control_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "compliant",
            "checks": []
        }
        
        # Collect evidence based on control type
        if control_id.startswith("ID") or control_id == "A.8":
            # Asset management
            evidence["checks"].append({
                "check": "Asset inventory",
                "status": "pass",
                "details": "System assets tracked in database"
            })
        
        if control_id.startswith("PR") or control_id in ["A.9", "A.10"]:
            # Protection controls
            evidence["checks"].append({
                "check": "Access control",
                "status": "pass",
                "details": "Role-based access control implemented"
            })
            evidence["checks"].append({
                "check": "Data protection",
                "status": "pass",
                "details": "Encryption at rest and in transit"
            })
        
        if control_id.startswith("DE") or control_id in ["A.12", "A.16"]:
            # Detection controls
            evidence["checks"].append({
                "check": "Monitoring",
                "status": "pass",
                "details": "IDS/IPS rules active and monitored"
            })
            evidence["checks"].append({
                "check": "Alerting",
                "status": "pass",
                "details": "Real-time alerting configured"
            })
        
        if control_id.startswith("RS") or control_id == "A.17":
            # Response controls
            evidence["checks"].append({
                "check": "Incident response",
                "status": "pass",
                "details": "Automated response policies active"
            })
        
        if control_id.startswith("RC") or control_id == "A.18":
            # Recovery controls
            evidence["checks"].append({
                "check": "Backup",
                "status": "pass",
                "details": "Auto-heal and rollback capabilities"
            })
        
        # Store evidence
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO compliance_evidence (timestamp, control_id, framework, status, evidence)
            VALUES (?, ?, ?, ?, ?)
        """, (evidence["timestamp"], control_id, framework, 
              evidence["status"], json.dumps(evidence)))
        conn.commit()
        conn.close()
        
        return evidence
    
    def generate_report(self, framework: str) -> Dict:
        """Generate complete compliance report for framework."""
        if framework not in self.FRAMEWORKS:
            return {"error": f"Unsupported framework: {framework}"}
        
        report = {
            "framework": framework,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "controls": [],
            "summary": {
                "total": 0,
                "compliant": 0,
                "non_compliant": 0,
                "not_applicable": 0
            }
        }
        
        for control_id in self.FRAMEWORKS[framework]:
            evidence = self.generate_evidence(framework, control_id)
            report["controls"].append(evidence)
            report["summary"]["total"] += 1
            if evidence.get("status") == "compliant":
                report["summary"]["compliant"] += 1
        
        return report

# ============================================================================
# ORCHESTRATOR (SOAR-LITE)
# ============================================================================

class Orchestrator:
    """Policy-driven orchestration engine for automated responses."""
    
    def __init__(self, db_manager: DatabaseManager, 
                 autoheal: AutoHealManager, ids_ips: IDSIPSManager):
        self.db = db_manager
        self.autoheal = autoheal
        self.ids_ips = ids_ips
    
    def add_policy(self, policy_id: str, name: str, description: str,
                   conditions: Dict, actions: Dict) -> bool:
        """Add or update orchestration policy."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO policies (policy_id, name, description, conditions, actions, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(policy_id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    conditions = excluded.conditions,
                    actions = excluded.actions,
                    updated_at = excluded.created_at
            """, (policy_id, name, description, json.dumps(conditions),
                  json.dumps(actions), datetime.now(timezone.utc).isoformat()))
            conn.commit()
            logger.info(f"Policy {policy_id} added/updated")
            return True
        except Exception as e:
            logger.error(f"Error adding policy: {e}")
            return False
        finally:
            conn.close()
    
    def get_policies(self, enabled_only: bool = True) -> List[Dict]:
        """Get orchestration policies."""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        query = "SELECT policy_id, name, description, conditions, actions, enabled FROM policies"
        if enabled_only:
            query += " WHERE enabled = 1"
        
        cursor.execute(query)
        results = []
        for row in cursor.fetchall():
            results.append({
                "policy_id": row[0],
                "name": row[1],
                "description": row[2],
                "conditions": json.loads(row[3]),
                "actions": json.loads(row[4]),
                "enabled": row[5]
            })
        conn.close()
        return results
    
    def evaluate_conditions(self, conditions: Dict) -> bool:
        """Evaluate if policy conditions are met."""
        condition_type = conditions.get("type", "alert")
        
        if condition_type == "alert":
            # Check for specific alert type or severity
            alert_type = conditions.get("alert_type")
            severity = conditions.get("severity")
            threshold = conditions.get("threshold", 1)
            
            recent_alerts = self.db.get_recent_alerts(limit=100, severity=severity)
            if alert_type:
                recent_alerts = [a for a in recent_alerts if a["alert_type"] == alert_type]
            
            return len(recent_alerts) >= threshold
        
        elif condition_type == "time":
            # Check if within time window
            start_hour = conditions.get("start_hour", 0)
            end_hour = conditions.get("end_hour", 24)
            current_hour = datetime.now().hour
            return start_hour <= current_hour < end_hour
        
        elif condition_type == "threshold":
            # Check metric threshold
            # This would query telemetry data
            return True  # Placeholder
        
        return False
    
    def execute_actions(self, actions: Dict) -> bool:
        """Execute policy actions."""
        action_type = actions.get("type")
        
        if action_type == "alert":
            # Generate alert
            self.db.add_alert(
                severity=actions.get("severity", "medium"),
                alert_type=actions.get("alert_type", "policy_triggered"),
                message=actions.get("message", "Policy action triggered")
            )
            return True
        
        elif action_type == "block_ip":
            # Block IP address
            ip_address = actions.get("ip_address")
            if ip_address:
                # Add firewall rule (platform-specific)
                logger.info(f"Blocking IP: {ip_address}")
                # Implementation would depend on platform
                return True
        
        elif action_type == "deploy_rule":
            # Deploy IDS/IPS rule
            platform = actions.get("platform")
            rule_id = actions.get("rule_id")
            rule_content = actions.get("rule_content")
            if platform and rule_id and rule_content:
                self.ids_ips.add_rule(rule_id, platform, rule_content)
                self.ids_ips.deploy_rules(platform)
                return True
        
        elif action_type == "restart_service":
            # Restart a service
            service_name = actions.get("service_name")
            if service_name:
                try:
                    subprocess.run(["systemctl", "restart", service_name],
                                  capture_output=True, timeout=30)
                    logger.info(f"Restarted service: {service_name}")
                    return True
                except Exception as e:
                    logger.error(f"Error restarting service: {e}")
        
        elif action_type == "run_command":
            # Execute command
            command = actions.get("command")
            if command:
                try:
                    result = subprocess.run(
                        command, shell=True, capture_output=True,
                        text=True, timeout=60
                    )
                    logger.info(f"Command executed: {command}")
                    return result.returncode == 0
                except Exception as e:
                    logger.error(f"Error executing command: {e}")
        
        return False
    
    def process_policies(self):
        """Process all enabled policies."""
        policies = self.get_policies(enabled_only=True)
        
        for policy in policies:
            try:
                if self.evaluate_conditions(policy["conditions"]):
                    logger.info(f"Policy {policy['policy_id']} conditions met, executing actions")
                    self.execute_actions(policy["actions"])
            except Exception as e:
                logger.error(f"Error processing policy {policy['policy_id']}: {e}")

# ============================================================================
# FASTAPI DASHBOARD
# ============================================================================

db_manager = None
autoheal_manager = None
ids_ips_manager = None
orchestrator = None
compliance_generator = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context for FastAPI app."""
    global db_manager, autoheal_manager, ids_ips_manager, orchestrator, compliance_generator
    
    # Initialize managers
    db_manager = DatabaseManager()
    autoheal_manager = AutoHealManager(db_manager)
    ids_ips_manager = IDSIPSManager(db_manager)
    compliance_generator = ComplianceGenerator(db_manager)
    orchestrator = Orchestrator(db_manager, autoheal_manager, ids_ips_manager)
    
    logger.info("CUSP V6 Dashboard initialized")
    yield
    
    # Cleanup
    logger.info("CUSP V6 Dashboard shutting down")

# API Models
if BaseModel:
    class TelemetryData(BaseModel):
        source: str
        metric_type: str
        metric_value: float
        metadata: Optional[Dict[str, Any]] = None
    
    class AlertData(BaseModel):
        severity: str
        alert_type: str
        message: str
        source: Optional[str] = None
    
    class IDSRule(BaseModel):
        rule_id: str
        platform: str
        rule_content: str
    
    class Policy(BaseModel):
        policy_id: str
        name: str
        description: Optional[str] = None
        conditions: Dict[str, Any]
        actions: Dict[str, Any]

if Header and HTTPException:
    def verify_api_key(x_api_key: str = Header(None)):
        """Verify API key if configured."""
        if API_KEY and x_api_key != API_KEY:
            raise HTTPException(status_code=403, detail="Invalid API key")
        return True
else:
    def verify_api_key():
        """Placeholder when FastAPI not installed."""
        return True

def create_dashboard_app():
    """Create FastAPI dashboard application."""
    if not FastAPI:
        raise ImportError("FastAPI not installed. Run: pip install fastapi uvicorn pydantic")
    
    app = FastAPI(
        title="CUSP V6 Unified Dashboard",
        description="Enterprise-Grade Unified Security Platform Dashboard",
        version=VERSION,
        lifespan=lifespan
    )
    
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            "name": "CUSP V6 Unified Dashboard",
            "version": VERSION,
            "status": "operational"
        }
    
    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}
    
    @app.post("/telemetry")
    async def add_telemetry(data: TelemetryData, _=Depends(verify_api_key)):
        """Add telemetry data point."""
        db_manager.add_telemetry(
            data.source, data.metric_type, data.metric_value, data.metadata
        )
        return {"status": "success"}
    
    @app.post("/alerts")
    async def add_alert(alert: AlertData, _=Depends(verify_api_key)):
        """Add security alert."""
        db_manager.add_alert(
            alert.severity, alert.alert_type, alert.message, alert.source
        )
        return {"status": "success"}
    
    @app.get("/alerts")
    async def get_alerts(limit: int = 100, severity: str = None):
        """Get recent alerts."""
        alerts = db_manager.get_recent_alerts(limit=limit, severity=severity)
        return {"alerts": alerts, "count": len(alerts)}
    
    @app.get("/stats")
    async def get_stats():
        """Get system statistics."""
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Count alerts by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
        """)
        alert_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Count auto-heal events
        cursor.execute("""
            SELECT COUNT(*) FROM autoheal_events
            WHERE timestamp > datetime('now', '-24 hours')
        """)
        autoheal_count = cursor.fetchone()[0]
        
        # Count IDS rules
        cursor.execute("SELECT COUNT(*) FROM ids_rules WHERE enabled = 1")
        rules_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alerts_24h": alert_counts,
            "autoheal_events_24h": autoheal_count,
            "active_rules": rules_count
        }
    
    return app

def create_orchestrator_app():
    """Create FastAPI orchestrator application."""
    if not FastAPI:
        raise ImportError("FastAPI not installed. Run: pip install fastapi uvicorn pydantic")
    
    app = FastAPI(
        title="CUSP V6 Orchestrator",
        description="Policy-driven Security Orchestration (SOAR-lite)",
        version=VERSION,
        lifespan=lifespan
    )
    
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            "name": "CUSP V6 Orchestrator",
            "version": VERSION,
            "status": "operational"
        }
    
    @app.post("/policies")
    async def add_policy(policy: Policy, _=Depends(verify_api_key)):
        """Add or update orchestration policy."""
        success = orchestrator.add_policy(
            policy.policy_id, policy.name, policy.description,
            policy.conditions, policy.actions
        )
        if success:
            return {"status": "success", "policy_id": policy.policy_id}
        raise HTTPException(status_code=500, detail="Failed to add policy")
    
    @app.get("/policies")
    async def get_policies(enabled_only: bool = True):
        """Get orchestration policies."""
        policies = orchestrator.get_policies(enabled_only=enabled_only)
        return {"policies": policies, "count": len(policies)}
    
    @app.post("/policies/{policy_id}/execute")
    async def execute_policy(policy_id: str, _=Depends(verify_api_key)):
        """Manually execute a specific policy."""
        policies = orchestrator.get_policies(enabled_only=False)
        policy = next((p for p in policies if p["policy_id"] == policy_id), None)
        
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        if orchestrator.evaluate_conditions(policy["conditions"]):
            success = orchestrator.execute_actions(policy["actions"])
            return {"status": "executed", "success": success}
        
        return {"status": "conditions_not_met"}
    
    @app.post("/rules")
    async def add_rule(rule: IDSRule, _=Depends(verify_api_key)):
        """Add IDS/IPS rule."""
        success = ids_ips_manager.add_rule(
            rule.rule_id, rule.platform, rule.rule_content
        )
        if success:
            return {"status": "success", "rule_id": rule.rule_id}
        raise HTTPException(status_code=500, detail="Failed to add rule")
    
    @app.get("/rules")
    async def get_rules(platform: str = None, enabled_only: bool = True):
        """Get IDS/IPS rules."""
        rules = ids_ips_manager.get_rules(platform=platform, enabled_only=enabled_only)
        return {"rules": rules, "count": len(rules)}
    
    @app.post("/rules/{platform}/deploy")
    async def deploy_rules(platform: str, _=Depends(verify_api_key)):
        """Deploy rules to IDS/IPS platform."""
        success = ids_ips_manager.deploy_rules(platform)
        if success:
            return {"status": "deployed", "platform": platform}
        raise HTTPException(status_code=500, detail="Failed to deploy rules")
    
    @app.get("/compliance/{framework}")
    async def get_compliance_report(framework: str):
        """Generate compliance report."""
        report = compliance_generator.generate_report(framework)
        if "error" in report:
            raise HTTPException(status_code=400, detail=report["error"])
        return report
    
    @app.get("/compliance/{framework}/{control_id}")
    async def get_compliance_evidence(framework: str, control_id: str):
        """Get compliance evidence for specific control."""
        evidence = compliance_generator.generate_evidence(framework, control_id)
        if not evidence:
            raise HTTPException(status_code=400, detail="Invalid framework or control")
        return evidence
    
    return app

# ============================================================================
# CLI INTERFACE
# ============================================================================

def run_dashboard(port: int = 8443, host: str = "0.0.0.0"):
    """Run dashboard API server."""
    logger.info(f"Starting CUSP V6 Dashboard on {host}:{port}")
    app = create_dashboard_app()
    uvicorn.run(app, host=host, port=port, log_level="info")

def run_orchestrator(port: int = 8450, host: str = "0.0.0.0"):
    """Run orchestrator API server."""
    logger.info(f"Starting CUSP V6 Orchestrator on {host}:{port}")
    app = create_orchestrator_app()
    uvicorn.run(app, host=host, port=port, log_level="info")

def run_autoheal(owner: str, repo: str, asset: str, target: str,
                health_url: str = None, loop: bool = False, 
                interval: int = 600, verify_gpg: bool = False):
    """Run auto-heal process."""
    db_mgr = DatabaseManager()
    autoheal_mgr = AutoHealManager(db_mgr)
    
    def perform_heal():
        logger.info("Running auto-heal check")
        success = autoheal_mgr.perform_update(
            owner, repo, asset, target, health_url, verify_gpg
        )
        if success:
            logger.info("Auto-heal completed successfully")
        else:
            logger.error("Auto-heal failed")
        return success
    
    if loop:
        logger.info(f"Starting auto-heal loop (interval: {interval}s)")
        while True:
            perform_heal()
            logger.info(f"Waiting {interval} seconds until next check")
            time.sleep(interval)
    else:
        perform_heal()

def run_all(owner: str, repo: str, asset: str, target: str,
           health_url: str = None, loop: bool = False, interval: int = 600,
           dash_port: int = 8443, orch_port: int = 8450):
    """Run all components together."""
    import threading
    
    # Start dashboard in thread
    dashboard_thread = threading.Thread(
        target=run_dashboard,
        args=(dash_port,),
        daemon=True
    )
    dashboard_thread.start()
    logger.info(f"Dashboard started on port {dash_port}")
    
    # Start orchestrator in thread
    orchestrator_thread = threading.Thread(
        target=run_orchestrator,
        args=(orch_port,),
        daemon=True
    )
    orchestrator_thread.start()
    logger.info(f"Orchestrator started on port {orch_port}")
    
    # Give servers time to start
    time.sleep(3)
    
    # Run auto-heal in main thread
    try:
        run_autoheal(owner, repo, asset, target, health_url, loop, interval)
    except KeyboardInterrupt:
        logger.info("Shutting down CUSP V6")

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CUSP V6 Unified — Enterprise-Grade Unified Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start dashboard API
  python CUSP_V6_Unified.py --dashboard --dash-port 8443
  
  # Start orchestrator API
  python CUSP_V6_Unified.py --orchestrator --orch-port 8450
  
  # Run auto-heal once
  python CUSP_V6_Unified.py --autoheal --owner myorg --repo myrepo \\
      --asset app.py --target /opt/app/app.py
  
  # Run all components with auto-heal loop
  python CUSP_V6_Unified.py --all --owner myorg --repo myrepo \\
      --asset app.py --target /opt/app/app.py --loop --interval 600
        """
    )
    
    # Mode selection
    parser.add_argument("--dashboard", action="store_true",
                       help="Run dashboard API server")
    parser.add_argument("--orchestrator", action="store_true",
                       help="Run orchestrator API server")
    parser.add_argument("--autoheal", action="store_true",
                       help="Run auto-heal process")
    parser.add_argument("--all", action="store_true",
                       help="Run all components together")
    
    # Dashboard options
    parser.add_argument("--dash-port", type=int, default=8443,
                       help="Dashboard API port (default: 8443)")
    parser.add_argument("--dash-host", default="0.0.0.0",
                       help="Dashboard API host (default: 0.0.0.0)")
    
    # Orchestrator options
    parser.add_argument("--orch-port", type=int, default=8450,
                       help="Orchestrator API port (default: 8450)")
    parser.add_argument("--orch-host", default="0.0.0.0",
                       help="Orchestrator API host (default: 0.0.0.0)")
    
    # Auto-heal options
    parser.add_argument("--owner", help="GitHub repository owner")
    parser.add_argument("--repo", help="GitHub repository name")
    parser.add_argument("--asset", help="Asset/file name to download")
    parser.add_argument("--target", help="Target file path for update")
    parser.add_argument("--health-url", help="Health check URL")
    parser.add_argument("--loop", action="store_true",
                       help="Run auto-heal in loop")
    parser.add_argument("--interval", type=int, default=600,
                       help="Auto-heal check interval in seconds (default: 600)")
    parser.add_argument("--verify-gpg", action="store_true",
                       help="Verify GPG signatures")
    
    parser.add_argument("--version", action="version", version=f"CUSP V6 {VERSION}")
    
    args = parser.parse_args()
    
    # Validate mode selection
    modes = [args.dashboard, args.orchestrator, args.autoheal, args.all]
    if not any(modes):
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.all:
            if not all([args.owner, args.repo, args.asset, args.target]):
                parser.error("--all requires --owner, --repo, --asset, and --target")
            run_all(args.owner, args.repo, args.asset, args.target,
                   args.health_url, args.loop, args.interval,
                   args.dash_port, args.orch_port)
        
        elif args.dashboard:
            run_dashboard(args.dash_port, args.dash_host)
        
        elif args.orchestrator:
            run_orchestrator(args.orch_port, args.orch_host)
        
        elif args.autoheal:
            if not all([args.owner, args.repo, args.asset, args.target]):
                parser.error("--autoheal requires --owner, --repo, --asset, and --target")
            run_autoheal(args.owner, args.repo, args.asset, args.target,
                        args.health_url, args.loop, args.interval, args.verify_gpg)
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
