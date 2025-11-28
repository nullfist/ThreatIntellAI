# 🚀 ThreatIntellAI - School Cybersecurity Platform

<div align="center">

![ThreatIntellAI](https://img.shields.io/badge/ThreatIntellAI-School%20Security-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

**AI-Powered Threat Detection & Reporting for Educational Environments**

[Features](#-features) • [Quick Start](#-quick-start) • [API Documentation](#-api-documentation) • [Deployment](#-deployment)

</div>

## 🎯 Overview

**ThreatIntellAI** is a school-friendly cybersecurity platform that helps teachers, admin staff, and IT teams identify threats, understand risks, and respond — without needing technical knowledge.

> **"Making cybersecurity accessible for every school"**

---

## ✨ Features

### 🔍 **Threat Detection**
- **IOC Scanner**: IP, URL, Domain, Hash analysis
- **Log Analysis**: Upload auth.log, IIS, Firewall, Windows Event logs
- **Real Threat Intelligence**: VirusTotal & AbuseIPDB integration
- **Pattern Detection**: Brute force, unknown users, port scans, failed logins

### 🎓 **School-Focused**
- **AI Explanations**: Technical → School-friendly language conversion
- **Risk Classification**: Safe / Suspicious / Malicious with confidence scores
- **Actionable Recommendations**: Practical steps for school staff
- **No Technical Knowledge Required**: Designed for teachers and admin

### 📊 **Professional Reporting**
- **PDF & HTML Reports**: Professional incident documentation
- **School Branding**: Customizable templates
- **Executive Summaries**: Clear risk overviews
- **Downloadable Formats**: Easy sharing and documentation

### 🌐 **Web Dashboard**
- **Browser-Based**: No installation required
- **Responsive Design**: Works on computers, tablets, phones
- **Intuitive Interface**: Easy for all school staff to use
- **Real-time Results**: Immediate threat analysis

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation & Running

1. **Download & Setup**
   ```bash
   # Navigate to project directory
   cd ThreatIntellAI
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Run the application
   python -m app.main
   ```

2. **Access the Platform**
   - 🌐 **Web Dashboard**: http://localhost:8080
   - 📚 **API Documentation**: http://localhost:8080/docs
   - ❤️ **Health Check**: http://localhost:8080/health

### Optional: Real Threat Intelligence
Add API keys to `.env` file for real threat data:
```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

---

## 🏗️ Architecture

### Backend Stack
- **FastAPI** - Modern Python web framework
- **Uvicorn** - ASGI server for production
- **Pydantic** - Data validation & serialization
- **ReportLab** - Professional PDF generation

### Threat Intelligence
- **VirusTotal API** - Real-time threat intelligence
- **AbuseIPDB API** - IP reputation analysis  
- **Hybrid System** - Falls back to mock data if APIs unavailable
- **Rate Limiting** - Respects API usage limits

### Frontend
- **Jinja2 Templates** - Server-side rendering
- **Bootstrap 5** - Responsive UI framework
- **Vanilla JavaScript** - Lightweight interactivity
- **Custom CSS** - School-appropriate styling

---

## 📚 API Endpoints

### Core Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/ioc/scan` | Scan IOC (IP/URL/Domain/Hash) |
| `POST` | `/api/v1/logs/upload` | Upload & analyze log files |
| `POST` | `/api/v1/ai/explain` | AI threat analysis |
| `POST` | `/api/v1/report/generate` | Generate PDF/HTML reports |
| `GET` | `/api/v1/ioc/scan-history` | View scan history |

### Frontend Routes
| Page | Route | Description |
|------|-------|-------------|
| 🏠 Dashboard | `/` | Main dashboard with quick actions |
| 🔍 IOC Scanner | `/upload/ioc` | Threat indicator scanning |
| 📁 Log Analysis | `/upload/logs` | Security log upload & analysis |
| 📊 Results | `/results` | Analysis results display |
| 📜 History | `/history` | Scan history and previous results |
| 📄 Reports | `/reports` | Professional report generation |

---

## 🏫 School Use Cases

### For Teachers & Staff
- **Check suspicious links** before clicking
- **Understand security alerts** in simple language  
- **Document incidents** for IT follow-up
- **Learn cybersecurity** through practical use

### For IT Teams
- **Quick threat assessment** without deep analysis
- **Professional documentation** for incidents
- **Log analysis** for security monitoring
- **Training tool** for staff awareness

### For Administration
- **Security compliance** documentation
- **Incident reporting** standardization
- **Budget justification** for security needs
- **Staff training** and awareness programs

---

## 🔧 Technical Features

### Security
- ✅ Input validation and sanitization
- ✅ File type verification for uploads
- ✅ No external dependencies required
- ✅ Local data storage only

### Performance
- ⚡ Async/await for non-blocking operations
- ⚡ Automatic API fallback systems
- ⚡ Efficient memory usage
- ⚡ Fast response times

### Scalability
- 🏗️ Modular architecture
- 🏗️ Easy to extend with new features
- 🏗️ Database-ready structure
- 🏗️ Cloud deployment prepared

---

## 🎯 MVP Achievement

### ✅ **Complete & Working**
- **Threat Detection Engine** - IOC scanning & log analysis
- **AI Explanation System** - School-friendly threat explanations  
- **Professional Reporting** - PDF/HTML incident reports
- **Web Dashboard** - Browser-based interface
- **Real API Integration** - VirusTotal & AbuseIPDB

### ✅ **School-Ready**
- **No Technical Knowledge Required** - Teachers can use it immediately
- **Clear Risk Communication** - Simple Safe/Suspicious/Malicious ratings
- **Actionable Recommendations** - Practical steps for school staff
- **Professional Documentation** - Ready for compliance and reporting

---

## 🚀 Deployment

### Local School Network
```bash
# Run on school server
python -m app.main

# Access from school computers
http://your-server:8080
```

### Development
```bash
# Auto-reload for development
python -m app.main

# Test different ports if needed
python -m app.main --port 8080
```

### Production Ready
- No external dependencies required
- Single command deployment
- Works on Windows, Linux, macOS
- Minimal resource requirements

---

## 👥 Development Team

### Roles & Contributions
- **Syed** - Backend Architecture, API Development, System Integration
- **Sriraam** - AI Engine, Threat Intelligence, Risk Classification

### Development Timeline
- **Week 1-2**: Core IOC Scanner & AI Engine ✅
- **Week 3**: Log Analysis & Enhanced AI ✅  
- **Week 4**: Professional Report Generator ✅
- **Week 5**: Web Dashboard & Frontend ✅
- **Week 5+**: Real API Integration & Polish ✅

---

## 🌟 What Makes ThreatIntellAI Special

### 🎓 **Education-First Design**
- Language tailored for school environments
- Learning-focused explanations
- Age-appropriate content
- Teacher-friendly interface

### 🛡️ **Real Security Value**
- Actual threat detection capabilities
- Professional-grade reporting
- Actionable security insights
- Compliance-ready documentation

### 💻 **Technical Excellence**
- Modern tech stack
- Clean, maintainable code
- Scalable architecture
- Production-ready deployment

---

## 📞 Support & Next Steps

### Immediate Next Steps
1. **School Pilot Programs** - Deploy to test schools
2. **User Training** - Create teacher training materials  
3. **Feedback Collection** - Improve based on real usage
4. **Feature Enhancement** - Add requested school features

### For Developers
- Modular codebase for easy extension
- Comprehensive API documentation
- Clean separation of concerns
- Well-commented source code

### Getting Started
```bash
# 1. Clone and setup
cd ThreatIntellAI
pip install -r requirements.txt

# 2. Run the application  
python -m app.main

# 3. Access and test
# Open http://localhost:8080
# Try scanning a test IOC or uploading sample logs
```

---

<div align="center">

## 🎉 Ready for School Deployment!

**ThreatIntellAI is production-ready and can provide immediate cybersecurity value to schools.**

[🏠 Dashboard](http://localhost:8080) • [📚 API Docs](http://localhost:8080/docs) • [🔍 Scan Threats](http://localhost:8080/upload/ioc)

**Built with ❤️ for School Cybersecurity Education**

---
*Making cybersecurity accessible to everyone in education* 🎓

</div>
