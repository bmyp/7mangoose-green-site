# Yosse - CUSP V6 Unified Security Platform

Enterprise-grade unified security platform implementing next-generation cyber defence capabilities.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run comprehensive demo
python3 demo_cusp_v6.py

# Start dashboard API
python3 CUSP_V6_Unified.py --dashboard --dash-port 8443

# Run all components
python3 CUSP_V6_Unified.py --all --loop --interval 600
```

## Documentation

- **[CUSP_V6_README.md](CUSP_V6_README.md)** - Complete user guide and API documentation
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Technical implementation details
- **[production_examples.sh](production_examples.sh)** - Production deployment examples

## Features

- ✅ Auto-Heal / Self-Update with SHA-256 verification
- ✅ IDS/IPS Rule Manager (Suricata, Snort, Windows Defender)
- ✅ Unified Dashboard API (FastAPI + SQLite)
- ✅ Orchestrator (SOAR-lite policy engine)
- ✅ Compliance Generator (NIST CSF, ISO 27001, PCI DSS)

## Security

CodeQL validated: **0 vulnerabilities found** ✓

See [SECURITY.md](SECURITY.md) for security policy.