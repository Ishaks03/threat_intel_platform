# Threat Intelligence Platform

A comprehensive **Threat Intelligence Correlation and IOC Validation Platform** built with Flask. This platform aggregates threat intelligence feeds, validates Indicators of Compromise (IOCs), correlates them against logs, and generates AI-powered threat briefings.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

### 🔍 IOC Management
- **Multi-source IOC ingestion** from popular threat feeds (URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar)
- **IOC types supported**: IP addresses, domains, URLs, file hashes (MD5/SHA1/SHA256), email addresses
- **Manual IOC submission** with validation
- **False positive tracking** and management
- **IOC enrichment** via VirusTotal and AbuseIPDB APIs

### 🔗 Log Correlation
- **Automated correlation** of IOCs against various log sources:
  - Firewall logs
  - DNS query logs
  - Proxy/web logs
  - Authentication logs
  - File hash logs
- **Real-time threat detection** with configurable correlation rules

### 📊 Threat Scoring
- **Intelligent scoring algorithm** considering:
  - IOC confidence levels
  - Threat type severity (C2, ransomware, phishing, etc.)
  - Feed reliability ratings
  - IOC recency
  - Known malware family attribution
  - Suspicious indicators (ports, TLDs)
- **Threat levels**: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL

### 🤖 AI-Powered Briefings
- **Daily threat briefings** using Google Gemini AI
- **IOC investigation reports** with context and recommendations
- **Executive summaries** for security teams

### 📈 Dashboard & Reporting
- **Interactive web dashboard** with real-time statistics
- **Threat distribution visualizations**
- **Export capabilities**: CSV, TXT formats
- **Correlation report generation**

### ⏰ Automated Scheduling
- **Scheduled feed updates** (configurable intervals)
- **Automated correlation runs**
- **Daily briefing generation**

## Architecture

```
threat_intel_platform/
├── app.py                 # Flask application entry point
├── scheduler.py           # APScheduler job definitions
├── requirements.txt       # Python dependencies
├── core/
│   ├── feed_manager.py       # Threat feed ingestion
│   ├── ioc_parser.py         # IOC parsing and normalization
│   ├── ioc_validator.py      # IOC validation and FP detection
│   ├── log_correlator.py     # Log correlation engine
│   ├── threat_scorer.py      # Threat scoring algorithm
│   ├── enrichment_engine.py  # VT/AbuseIPDB enrichment
│   ├── ai_briefing_generator.py  # Gemini AI briefings
│   └── report_builder.py     # Report generation
├── database/
│   ├── db_manager.py         # SQLite database operations
│   └── schema.sql            # Database schema
├── data/
│   ├── demo/                 # Demo IOC dataset
│   └── logs/                 # Simulated log files
├── static/
│   ├── script.js             # Frontend JavaScript
│   └── style.css             # Styling
└── templates/
    └── index.html            # Dashboard template
```

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Ishaks03/threat_intel_platform.git
   cd threat_intel_platform
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables** (optional, for full functionality)
   
   Create a `.env` file in the project root:
   ```env
   # Google Gemini API for AI briefings
   GEMINI_API_KEY=your_gemini_api_key
   
   # VirusTotal API for IOC enrichment
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   
   # AbuseIPDB API for IP reputation
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   
   # Flask configuration
   FLASK_DEBUG=false
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Access the dashboard**
   
   Open your browser and navigate to: `http://localhost:5000`

## API Endpoints

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard` | Get dashboard statistics |
| GET | `/api/health` | Health check |
| GET | `/api/config` | Platform configuration status |

### IOC Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/iocs` | Get paginated IOCs with filters |
| GET | `/api/iocs/<id>` | Get specific IOC by ID |
| POST | `/api/iocs/search` | Search for IOC by value |
| POST | `/api/iocs/manual` | Add manual IOC |
| POST | `/api/iocs/<id>/fp` | Mark IOC as false positive |

### Threat Feeds
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/feeds/status` | Get feed status |
| POST | `/api/feeds/refresh` | Refresh threat feeds |

### Correlation
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/correlations` | Get correlation results |
| POST | `/api/correlate` | Run manual correlation |
| POST | `/api/correlations/<id>/reviewed` | Mark correlation as reviewed |

### Enrichment
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/enrich` | Enrich IOCs with external data |
| GET | `/api/enrich/status` | Get enrichment statistics |

### AI Briefings
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/briefing/daily` | Generate daily threat briefing |
| POST | `/api/briefing/ioc` | Generate IOC investigation report |

### Export & Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/export/csv` | Export IOCs as CSV |
| GET | `/api/export/txt` | Export IOC values as text |
| GET | `/api/reports` | List all reports |
| GET | `/api/reports/<id>` | Get specific report |

### Demo
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/demo/load` | Load demo dataset |
| GET | `/api/demo/reset` | Reset and reload demo data |

## Database Schema

The platform uses SQLite with the following tables:

- **iocs**: Stores all indicators of compromise
- **correlations**: Matches between IOCs and log entries
- **feed_status**: Tracks threat feed health
- **reports**: Generated correlation and briefing reports

## Usage Examples

### Load Demo Data
```bash
curl http://localhost:5000/api/demo/load
```

### Search for an IOC
```bash
curl -X POST http://localhost:5000/api/iocs/search \
  -H "Content-Type: application/json" \
  -d '{"value": "192.168.1.100"}'
```

### Add Manual IOC
```bash
curl -X POST http://localhost:5000/api/iocs/manual \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_value": "malicious-domain.xyz",
    "ioc_type": "domain",
    "threat_type": "phishing",
    "severity": "High"
  }'
```

### Run Correlation
```bash
curl -X POST http://localhost:5000/api/correlate
```

### Generate Daily Briefing
```bash
curl -X POST http://localhost:5000/api/briefing/daily
```

## Threat Scoring Algorithm

The platform uses a sophisticated scoring algorithm (0-100 scale):

| Factor | Points |
|--------|--------|
| Base confidence | 0-50 |
| C2/Ransomware threat | +25 |
| Phishing/Malware threat | +20 |
| High-reliability feed | +5 |
| Suspicious port detected | +10 |
| Very recent IOC (<24h) | +10 |
| Known dangerous malware family | +10-20 |
| Low confidence penalty | -5 |

**Threat Level Mapping:**
- **CRITICAL**: 90-100
- **HIGH**: 70-89
- **MEDIUM**: 50-69
- **LOW**: 30-49
- **INFORMATIONAL**: 0-29

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [URLhaus](https://urlhaus.abuse.ch/) - Malicious URL database
- [ThreatFox](https://threatfox.abuse.ch/) - IOC sharing platform
- [Feodo Tracker](https://feodotracker.abuse.ch/) - Botnet C2 tracking
- [MalwareBazaar](https://bazaar.abuse.ch/) - Malware sample sharing
- [VirusTotal](https://www.virustotal.com/) - File and URL analysis
- [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation database
- [Google Gemini](https://ai.google.dev/) - AI-powered briefings

---

**Built with ❤️ for the cybersecurity community**
