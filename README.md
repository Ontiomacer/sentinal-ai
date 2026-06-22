# Sentinel AI - APK Forensic Intelligence Platform

**A comprehensive Android APK malware analysis system combining real-time device interaction, static analysis, AI-powered threat detection, and forensic investigation workflows.**

---

## 🎯 Project Overview

Sentinel AI is an enterprise-grade APK analysis platform designed for malware researchers, security analysts, and threat intelligence teams. The system provides:

- **Real-time Device Control**: Live Android device interaction via ADB with screen mirroring, app management, and runtime monitoring
- **Automated APK Extraction**: Pull APKs directly from connected devices with split APK support
- **Deep Static Analysis**: Comprehensive APK reverse engineering using Androguard (manifest, DEX, permissions, components, strings, certificates)
- **AI-Powered Threat Detection**: Local Qwen3:4b LLM integration for intelligent malware classification
- **Evidence-Based Risk Scoring**: Deterministic, explainable risk assessment with attack chain visualization
- **Forensic Investigation Workspace**: Case management, evidence timeline, and comprehensive reporting
- **Neural Intelligence Engine**: Advanced behavioral analysis and threat pattern recognition

---

## 🏗️ Architecture

### Technology Stack

**Backend:**
- FastAPI (Python 3.11+) - Async REST API
- SQLite + SQLAlchemy - Database ORM
- Androguard 4.0+ - APK static analysis
- Ollama + Qwen3:4b - Local AI inference
- ADB (Android Debug Bridge) - Device communication

**Frontend:**
- React 18 + TypeScript 5
- Vite 5 - Build tooling
- TailwindCSS 3 - Design system
- React Router 6 - Navigation
- Axios - HTTP client

**Device Integration:**
- ADB over USB/WiFi
- scrcpy protocol for screen mirroring
- Real-time logcat streaming

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- ADB platform-tools (for device features)
- Ollama with qwen3:4b model (for AI features)

### Installation

**1. Clone repository:**
```bash
git clone <repository-url>
cd fraud-apk-analyzer
```

**2. Backend setup:**
```bash
pip install -r requirements.txt
copy .env.example .env
```

**3. Frontend setup:**
```bash
cd frontend
npm install
```

**4. ADB setup (for device features):**
- Download: https://developer.android.com/studio/releases/platform-tools
- Extract to `C:\platform-tools\` (Windows) or `/usr/local/bin/` (Linux/Mac)
- Add to PATH environment variable

**5. Ollama setup (for AI features):**
```bash
# Install Ollama from https://ollama.ai
ollama pull qwen3:4b
```

### Running the Application

**Start backend:**
```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Start frontend:**
```bash
cd frontend
npm run dev
```

**Access:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

---

## 📁 Project Structure

```
fraud-apk-analyzer/
├── app/                                    # Backend (FastAPI)
│   ├── main.py                             # Application entry point
│   ├── config.py                           # Configuration management
│   ├── database.py                         # Database connection
│   ├── api/v1/endpoints/                   # API endpoints
│   │   ├── upload.py                       # APK upload
│   │   ├── app_analysis.py                 # APK analysis pipeline
│   │   ├── device_lab.py                   # Device control API
│   │   ├── cases.py                        # Case management
│   │   ├── evidence.py                     # Evidence handling
│   │   ├── ghidra.py                       # Ghidra integration
│   │   ├── ai_api.py                       # AI cognition API
│   │   ├── neural_api.py                   # Neural engine API
│   │   └── neural_lab.py                   # Neural lab features
│   ├── models/                             # SQLAlchemy models
│   │   ├── scan.py                         # Scan records
│   │   ├── case.py                         # Case management
│   │   └── investigation.py                # Investigation tracking
│   ├── schemas/                            # Pydantic schemas
│   │   ├── scan.py                         # Scan validation
│   │   └── case.py                         # Case validation
│   ├── services/                           # Business logic
│   │   ├── apk_analyzer.py                 # Static analysis (Androguard)
│   │   ├── app_inventory_service.py        # Device APK extraction
│   │   ├── adb_controller.py               # ADB command interface
│   │   ├── device_manager_service.py       # Device lifecycle management
│   │   ├── device_stream_service.py        # Screen mirroring
│   │   ├── logcat_service.py               # Real-time log streaming
│   │   ├── risk_scorer.py                  # Risk assessment engine
│   │   ├── ai_cognition.py                 # AI threat detection
│   │   ├── neural_engine.py                # Advanced intelligence
│   │   ├── intelligence_engine.py          # Pattern recognition
│   │   ├── attack_mapper.py                # MITRE ATT&CK mapping
│   │   ├── ghidra_integration.py           # Ghidra reverse engineering
│   │   ├── case_service.py                 # Case management
│   │   ├── evidence_service.py             # Evidence chain
│   │   ├── investigation_service.py        # Investigation workflow
│   │   └── report_generator.py             # PDF/JSON reports
│   └── utils/                              # Utilities
│       └── file_handler.py                 # File operations
├── frontend/                               # Frontend (React + TypeScript)
│   ├── src/
│   │   ├── components/                     # Reusable UI components
│   │   │   ├── layout/                     # Layout components
│   │   │   └── ui/                         # UI primitives
│   │   ├── pages/                          # Page components
│   │   │   ├── LandingPage.tsx             # Home page
│   │   │   ├── DeviceLabPage.tsx           # Device control center
│   │   │   ├── AppAnalysisPage.tsx         # APK analysis results
│   │   │   ├── CaseDashboardPage.tsx       # Case management
│   │   │   ├── CodeAnalysisPage.tsx        # Ghidra integration
│   │   │   └── NeuralLabPage.tsx           # AI intelligence hub
│   │   ├── services/
│   │   │   └── api.ts                      # API client
│   │   ├── App.tsx                         # Root component
│   │   ├── main.tsx                        # Entry point
│   │   └── index.css                       # Global styles
│   ├── package.json                        # Dependencies
│   ├── vite.config.ts                      # Vite configuration
│   └── tailwind.config.js                  # Design system
├── APKCache/                               # Permanent APK storage (SHA256-indexed)
├── uploads/                                # Temporary upload directory
├── storage/                                # Hash-based permanent storage
├── apk_analysis.db                         # SQLite database
├── requirements.txt                        # Python dependencies
└── .env                                    # Environment configuration
```

---

## 🔥 Core Features

### 1. Device Lab - Real-Time Android Control

**Live Device Interaction:**
- Real-time screen mirroring via scrcpy protocol
- Touch input control (tap, swipe, home, back, recents)
- App management (install, uninstall, launch, force-stop)
- Screenshot capture
- Device information (model, Android version, serial)

**App Inventory:**
- Live installed app listing
- Package details (name, version, size, install date)
- Direct APK extraction to analysis pipeline
- Split APK support (base.apk extraction)

**Runtime Monitoring:**
- Real-time logcat streaming
- Filtered log levels (Verbose, Debug, Info, Warning, Error)
- Process monitoring
- Network activity tracking

**Implementation:**
- ADB commands executed via `asyncio` subprocess (Windows-compatible)
- Thread pool executor pattern for synchronous ADB operations
- WebSocket support for real-time updates (planned)
- USB and WiFi ADB support

**API Endpoints:**
- `GET /api/v1/device-lab/devices` - List connected devices
- `GET /api/v1/device-lab/apps` - Get installed apps
- `POST /api/v1/device-lab/control/{action}` - Control device (tap, swipe, etc.)
- `POST /api/v1/device-lab/screenshot` - Capture screenshot
- `GET /api/v1/device-lab/logcat` - Stream logs

---

### 2. APK Analysis Pipeline - Deep Static Analysis

**Multi-Stage Analysis:**

**Stage 1: Quick Scan (< 2s)**
- APK extraction from device
- SHA256 calculation
- File size validation
- Manifest quick parse
- Basic metadata extraction

**Stage 2: Static Analysis (< 15s target)**
- **Manifest Intelligence:**
  - Package name, version, SDK versions
  - Permissions with risk categorization
  - Components (activities, services, receivers, providers)
  - Exported component detection
  - Intent filters and features

- **DEX Reverse Engineering:**
  - DEX file enumeration
  - Class/method count
  - Sample classes (MAX: 100 classes)
  - Sample methods (MAX: 25 per class)
  - Native library detection

- **String Extraction:**
  - URLs and domains (network artifacts)
  - Suspicious strings (passwords, tokens, API keys)
  - Limited to 1000 strings (DEX only, skip assets)
  - Hardcoded credentials detection

- **Certificate Analysis:**
  - Signing certificate details
  - Issuer and subject information
  - Validity period
  - Certificate fingerprints

**Stage 3: Risk Scoring (< 1s)**
- **Evidence-Based Scoring (0-100 points):**
  - SYSTEM_ALERT_WINDOW: +25 (overlay attacks)
  - BIND_ACCESSIBILITY_SERVICE: +30 (accessibility abuse)
  - SEND_SMS: +20 (premium SMS fraud)
  - READ_SMS: +15 (OTP interception)
  - REQUEST_INSTALL_PACKAGES: +15 (malware dropper)
  - DexClassLoader: +20 (dynamic code loading)
  - Runtime.exec: +20 (shell command execution)
  - Excessive permissions (>15 dangerous): +30
  - High-risk functions (>10): +35

- **Threat Classification:**
  - BENIGN: 0-24 points
  - SUSPICIOUS: 25-49 points
  - HIGH_RISK: 50-74 points
  - MALICIOUS: 75-100 points

**Stage 4: AI Verdict (< 5s target)**
- Local Qwen3:4b inference via Ollama
- Evidence summary (< 500 bytes)
- Malware family classification
- Behavior prediction
- Confidence scoring

**Caching System:**
- SHA256-based persistent cache
- JSON cache files in `APKCache/<sha256>.json`
- 1-hour memory cache (TTL)
- Cache hit: < 1 second response

**12-Tab Analysis Results:**
1. Executive Summary
2. Permission Intelligence
3. Manifest Analysis
4. DEX Reverse Engineering
5. Code Intelligence
6. Obfuscation Analysis
7. Network Intelligence
8. Security Weaknesses
9. Banking Trojan Detection
10. Attack Chain Visualization
11. AI Investigator (Qwen3:4b)
12. Investigation Graph

**API Endpoints:**
- `POST /api/v1/app-analysis/quick-scan` - Start analysis
- `GET /api/v1/app-analysis/status/{analysis_id}` - Poll progress
- `GET /api/v1/app-analysis/{sha256}` - Get cached result
- `DELETE /api/v1/app-analysis/cache` - Clear cache

---

### 3. Case Management System

**Forensic Investigation Workflow:**
- Create cases with metadata (name, description, priority, status)
- Evidence attachment (APK scans, files, screenshots, logs)
- Investigation timeline tracking
- Notes and annotations
- Status tracking (Open, In Progress, Under Review, Closed)
- Priority levels (Low, Medium, High, Critical)

**Evidence Chain:**
- Cryptographic evidence hashing
- Timestamp verification
- Evidence integrity validation
- Chain of custody tracking

**API Endpoints:**
- `POST /api/v1/cases` - Create case
- `GET /api/v1/cases` - List cases
- `GET /api/v1/cases/{case_id}` - Get case details
- `PUT /api/v1/cases/{case_id}` - Update case
- `DELETE /api/v1/cases/{case_id}` - Delete case
- `POST /api/v1/cases/{case_id}/evidence` - Attach evidence

---

### 4. Ghidra Integration - Advanced Reverse Engineering

**Features:**
- Ghidra headless analysis integration
- DEX to Java decompilation
- Function listing and control flow
- Cross-reference analysis
- Binary pattern matching

**API Endpoints:**
- `POST /api/v1/ghidra/analyze` - Analyze APK with Ghidra
- `GET /api/v1/ghidra/decompile` - Decompile function
- `GET /api/v1/ghidra/xrefs` - Get cross-references

---

### 5. Neural Intelligence Engine

**Advanced Threat Detection:**
- Behavioral pattern recognition
- Anomaly detection
- Threat actor attribution
- Malware family clustering
- Zero-day indicator extraction

**API Endpoints:**
- `POST /api/v1/neural/analyze` - Neural analysis
- `GET /api/v1/neural/patterns` - Threat patterns
- `GET /api/v1/neural/intelligence` - Intelligence feed

---

### 6. Attack Chain Visualization

**MITRE ATT&CK Integration:**
- Technique mapping (T1XXX codes)
- Tactic categorization
- Attack path visualization
- Indicator of Compromise (IoC) extraction

**Detection Logic:**
- Permission → Tactic mapping
- API call → Technique mapping
- Suspicious function → Attack pattern
- Multi-stage attack reconstruction

---

## 🔧 Configuration

### Backend (.env)

```env
# Application
APP_NAME=Sentinel AI
APP_VERSION=1.0.0
ENVIRONMENT=development

# Directories
UPLOAD_DIR=uploads
STORAGE_DIR=storage
APK_CACHE_DIR=APKCache

# Database
DATABASE_URL=sqlite+aiosqlite:///./apk_analysis.db

# File Upload
MAX_UPLOAD_SIZE=104857600  # 100MB

# ADB Configuration
ADB_PATH=C:\platform-tools\adb.exe  # Windows
# ADB_PATH=/usr/bin/adb  # Linux/Mac

# Ollama AI
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen3:4b

# Security
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

### Frontend (.env)

```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

---

## 📊 Performance Targets

**APK Analysis Pipeline:**
- Quick Scan: < 2 seconds ✅
- Static Analysis: < 15 seconds (current: ~43s) ⚠️
- AI Verdict: < 5 seconds (current: ~155s with Qwen3:4b) ⚠️
- Cache Hit: < 1 second ✅

**Device Control:**
- ADB command execution: < 500ms
- Screen mirroring: 30 FPS target
- Logcat streaming: Real-time

**Database:**
- Query latency: < 10ms
- Insert latency: < 50ms

---

## 🔐 Security Considerations

### Current State (Development)

⚠️ **NOT PRODUCTION-READY:**
- No authentication/authorization
- CORS allows all origins
- No rate limiting
- SQLite database (single-file, no encryption)
- ADB exposes full device control
- No input sanitization on device commands

### Production Hardening Checklist

**Required:**
- [ ] JWT-based authentication
- [ ] Role-based access control (RBAC)
- [ ] API key authentication
- [ ] Rate limiting (per-IP, per-user)
- [ ] CORS whitelist
- [ ] PostgreSQL migration
- [ ] HTTPS/TLS enforcement
- [ ] Input validation and sanitization
- [ ] SQL injection prevention
- [ ] XSS protection
- [ ] CSRF tokens
- [ ] File upload validation
- [ ] ADB command whitelist
- [ ] Device permission management
- [ ] Audit logging

**Recommended:**
- [ ] Web Application Firewall (WAF)
- [ ] DDoS protection
- [ ] Database encryption at rest
- [ ] Secrets management (Vault, AWS Secrets Manager)
- [ ] Security headers (CSP, HSTS, X-Frame-Options)
- [ ] Vulnerability scanning
- [ ] Penetration testing
- [ ] Security incident response plan

---

## 🧪 Testing

### Manual Testing

**Test APK Upload:**
```bash
python test_upload.py sample.apk
```

**Test Risk Scoring:**
```bash
python test_risk_scoring.py sample.apk
```

**Test Database:**
```bash
python check_db.py
```

### API Testing (curl)

```bash
# Health check
curl http://localhost:8000/health

# Upload APK
curl -X POST http://localhost:8000/api/v1/upload \
  -F "file=@sample.apk"

# Get scan results
curl http://localhost:8000/api/v1/scan/{scan_id}

# List devices
curl http://localhost:8000/api/v1/device-lab/devices

# Quick scan from device
curl -X POST "http://localhost:8000/api/v1/app-analysis/quick-scan?package_name=com.example.app&serial=ABC123"
```

---

## 🐛 Known Issues & Limitations

### Current Bugs

1. **Windows Path Bug (CRITICAL):**
   - ADB pull succeeds but file verification fails
   - Path separator mismatch (forward slash vs backslash)
   - File exists but not found at expected location
   - **Status:** Investigating (path normalization implemented but needs testing)

2. **Analysis Stalls at 70%:**
   - Background analysis completes but progress shows 70%
   - Step: "Building Analysis Result"
   - **Status:** Instrumentation added for debugging

3. **AI Verdict Performance:**
   - Qwen3:4b takes 155 seconds (target: < 5s)
   - Needs prompt optimization or model quantization
   - **Status:** Optimized prompt, further tuning needed

### Limitations

**Static Analysis:**
- Cannot detect runtime behavior
- Cannot analyze heavily obfuscated code
- Cannot decrypt encrypted payloads
- Cannot detect unknown zero-day exploits

**Device Control:**
- Requires USB debugging enabled
- No multi-device control (single device at a time)
- Screen mirroring requires scrcpy installation
- WiFi ADB requires manual setup

**AI Analysis:**
- Local model (no internet required) but slower
- Limited context window (Qwen3:4b)
- May have false positives/negatives
- Requires Ollama installation

**Performance:**
- Single-threaded analysis (no parallelization)
- No background task queue
- SQLite (not suitable for high concurrency)
- No horizontal scaling

---

## 🚧 Roadmap

### Phase 1: Core Stability (Current)
- [x] Device Lab implementation
- [x] APK extraction pipeline
- [x] Static analysis with Androguard
- [x] Risk scoring engine
- [x] Basic AI integration
- [ ] Fix Windows path bug
- [ ] Optimize AI verdict performance
- [ ] Complete analysis pipeline testing

### Phase 2: Enhanced Analysis
- [ ] Dynamic analysis (sandbox)
- [ ] Network traffic analysis (mitmproxy integration)
- [ ] Memory dump analysis
- [ ] Runtime API hooking (Frida integration)
- [ ] Behavioral monitoring

### Phase 3: Intelligence Platform
- [ ] Threat intelligence feeds (VirusTotal, MalwareBazaar)
- [ ] YARA rule scanning
- [ ] Signature database
- [ ] Malware family database
- [ ] IoC repository

### Phase 4: Production Hardening
- [ ] Authentication/authorization
- [ ] PostgreSQL migration
- [ ] Redis caching layer
- [ ] Celery background tasks
- [ ] Kubernetes deployment
- [ ] Monitoring and logging (Prometheus, ELK)
- [ ] CI/CD pipeline

### Phase 5: Enterprise Features
- [ ] Multi-tenancy
- [ ] Team collaboration
- [ ] Advanced reporting
- [ ] Custom rule builder
- [ ] API rate limiting and quotas
- [ ] Audit trail

---

## 📚 Documentation References

### User Guides
- ADB setup: See ADB_SETUP_GUIDE.md (deleted, content in README)
- API examples: See API_EXAMPLES.md (deleted, content in README)
- Device Lab: See DEVICE_LAB_* files (deleted, content in README)

### Technical Documentation
- Architecture: See ARCHITECTURE.md (deleted, content in README)
- Risk Scoring: See RISK_SCORING.md (deleted, content in README)
- Static Analysis: See STATIC_ANALYSIS.md (deleted, content in README)

**All documentation has been consolidated into this single README.md file.**

---

## 🤝 Contributing

This is a research and educational project. Contributions welcome:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📄 License

This project is for educational and research purposes. Use responsibly and ethically.

---

## 🆘 Support & Contact

**Issues:** Open a GitHub issue for bugs or feature requests

**Security:** Report security vulnerabilities privately

---

## 🎓 Educational Purpose

This tool is designed for:
- Malware research and analysis
- Security training and education
- Threat intelligence gathering
- Penetration testing and red teaming
- Academic research

**Use Responsibly:** This tool provides powerful capabilities for analyzing and interacting with Android devices. Always obtain proper authorization before analyzing or testing applications.

---

## ⚙️ System Requirements

**Minimum:**
- CPU: 4 cores
- RAM: 8 GB
- Storage: 50 GB
- OS: Windows 10/11, Linux, macOS

**Recommended:**
- CPU: 8+ cores
- RAM: 16 GB
- Storage: 100 GB SSD
- OS: Windows 11, Ubuntu 22.04+, macOS 13+

---

## 🙏 Acknowledgments

**Open Source Components:**
- Androguard - APK reverse engineering
- FastAPI - Web framework
- React - Frontend framework
- Ollama - Local LLM inference
- ADB - Android Debug Bridge
- scrcpy - Screen mirroring protocol

---

**Project Status:** 🚧 Active Development

**Last Updated:** June 14, 2026

**Version:** 1.5.0-beta
