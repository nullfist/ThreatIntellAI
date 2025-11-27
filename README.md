# 🚀 ThreatIntellAI - School Cybersecurity Platform

<div align="center">

![ThreatIntellAI](https://img.shields.io/badge/ThreatIntellAI-School%20Security-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

**AI-Powered Threat Detection & Reporting for Educational Environments**

[Features](#-features) • [Quick Start](#-quick-start) • [API Documentation](#-api-documentation) • [Team](#-team)

</div>

## 🎯 Overview

**ThreatIntellAI** is a school-friendly cybersecurity platform that helps teachers, admin staff, and IT teams identify threats, understand risks, and respond — without needing technical knowledge.

> **MVP Mission**: Detect threats, explain them in simple language, and generate clear incident reports for schools.

---

## 🏗️ Project Structure

```
ThreatIntellAI/
│
├── 📄 app/
│   ├── 🚀 main.py                          # FastAPI application entry point
│   ├── 📁 routers/                         # API route handlers
│   ├── 🔧 services/                       # Business logic services
│   ├── 🏗️ models/                         # Data models & schemas
│   ├── ⚙️ utils/                          # Utility functions
│   ├── 🎨 templates/                      # Frontend HTML templates
│   ├── 🎨 static/                         # Frontend assets (CSS/JS)
│   ├── 💾 storage/                        # Data storage
│   └── __init__.py
│
├── 📋 requirements.txt                    # Python dependencies
├── 📖 README.md                           # This file
└── 🚫 .gitignore                         # Git ignore rules
```

## ✨ Features

### 🎯 Core MVP Features
- **IOC Scanner** - Upload/enter IP, URL, domain, file hash → get risk analysis
- **Log Analysis** - Manual upload of log files with pattern detection
- **AI Threat Explanation** - Converts technical data to school-friendly language
- **Incident Report Generator** - Auto-generates structured reports (PDF/HTML)
- **Web Dashboard** - Browser-based interface, no installation required

### 🔍 Threat Detection
- **Risk Classification**: Safe / Suspicious / Malicious
- **Threat Labels**: Malware, Phishing, C2, Botnet, Scam
- **Log Types**: auth.log, IIS, Firewall, Windows Event, Apache
- **Pattern Detection**: Failed logins, brute force, unknown users, port scans

### 📊 Professional Reporting
- **PDF & HTML Reports** with school branding
- **Executive summaries** and actionable recommendations
- **School-friendly language** for all audiences
- **Downloadable formats** for documentation

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation & Running

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/ThreatIntellAI.git
   cd ThreatIntellAI
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python -m app.main
   ```

4. **Access the platform**
   - **Web Dashboard**: http://localhost:8080
   - **API Documentation**: http://localhost:8080/docs
   - **Health Check**: http://localhost:8080/health

### For Development
```bash
# Run with auto-reload for development
python -m app.main
```

---

## 📚 API Documentation

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/ioc/scan` | Scan IOC (IP, URL, Domain, Hash) |
| `POST` | `/api/v1/logs/upload` | Upload and analyze log files |
| `POST` | `/api/v1/ai/explain` | AI-powered threat analysis |
| `POST` | `/api/v1/report/generate` | Generate PDF/HTML reports |
| `GET` | `/api/v1/ioc/scan-history` | Get scan history |

### Example API Usage

**Scan an IP Address:**
```bash
curl -X POST "http://localhost:8080/api/v1/ioc/scan" \
  -H "Content-Type: application/json" \
  -d '{"value": "192.168.1.100", "type": "ip"}'
```

**Generate a Report:**
```bash
curl -X POST "http://localhost:8080/api/v1/report/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "incident",
    "format": "pdf",
    "title": "Security Incident Report",
    "school_info": {
      "school_name": "Springfield Elementary"
    }
  }'
```

---

## 🎨 Frontend Pages

- **Dashboard** (`/`) - Main landing with quick actions
- **IOC Scanner** (`/upload/ioc`) - Threat indicator scanning
- **Log Analysis** (`/upload/logs`) - Security log upload & analysis
- **Results** (`/results`) - Analysis results display
- **History** (`/history`) - Scan history and previous results
- **Reports** (`/reports`) - Professional report generation

---

## 🏫 School Use Cases

### For Teachers & Staff
- **Check suspicious links/emails** before clicking
- **Understand security risks** in simple language
- **Generate incident reports** for documentation
- **No technical knowledge required**

### For IT Teams
- **Professional threat analysis**
- **Log pattern detection**
- **Incident documentation**
- **Compliance-ready reporting**

### For Administration
- **Security awareness tool**
- **Incident tracking**
- **Training and education resource**
- **Budget justification evidence**

---

## 🔧 Technical Details

### Built With
- **Backend**: FastAPI, Python 3.8+
- **Frontend**: HTML5, CSS3, JavaScript, Jinja2 Templates
- **PDF Generation**: ReportLab
- **Storage**: JSON files (no database required)
- **Deployment**: Local or cloud-ready

### Architecture
- **Modular Design** - Easy to maintain and extend
- **RESTful API** - Clean, documented endpoints
- **Mock Threat Intelligence** - No external API dependencies
- **School-Friendly** - No sensitive data or complex setup

### Security Features
- **Input validation** and error handling
- **File type verification** for uploads
- **No external dependencies** for threat data
- **Local storage** - Data stays within school control

---

## 👥 Team Development

### Current Team
- **Syed** - Backend Architecture & API Development
- **Sriraam** - AI Engine & Threat Intelligence
- **Frontend Team** - UI/UX & User Interface

### Development Status
- **✅ Backend**: 100% Complete
- **✅ Core Features**: 100% Complete
- **🔄 Frontend**: Foundation Complete - Ready for Polish
- **🚀 Deployment**: Ready for School Pilots

---

## 🌟 MVP Achievement

**ThreatIntellAI MVP successfully delivers:**
> A school-friendly cyber threat detection & reporting tool that helps teachers, admin staff, and IT teams identify threats, understand risks, and respond — without needing technical knowledge.

### What's Working Now
- ✅ Threat detection via IOC scanning
- ✅ Log analysis with pattern detection
- ✅ AI-powered school-friendly explanations
- ✅ Professional report generation
- ✅ Web-based dashboard interface
- ✅ No technical knowledge required

### Ready For
- 🏫 School pilot programs
- 👩‍🏫 Teacher training sessions
- 🛡️ IT team integration
- 📊 Further development and enhancement

---

## 📞 Support & Contribution

### For School IT Teams
- Deploy locally on school networks
- Customize for specific school needs
- Integrate with existing systems

### For Developers
- Modular architecture for easy extension
- Well-documented API endpoints
- Clean, maintainable codebase

### Getting Help
- Check API documentation at `/docs`
- Review code comments and structure
- Contact development team for support

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎯 Next Steps

1. **Frontend Polish** - Enhance user experience and mobile responsiveness
2. **School Pilots** - Deploy to pilot schools for feedback
3. **Feature Enhancement** - Add real threat intelligence APIs
4. **Scale Up** - Multi-school management and advanced features

---

<div align="center">

**Built with ❤️ for School Cybersecurity Education**

[⬆ Back to Top](#-threatintellai---school-cybersecurity-platform)

</div>