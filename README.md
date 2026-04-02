# CyberShield - AI-Powered Cybersecurity Scanner

<div align="center">

![CyberShield](https://img.shields.io/badge/CyberShield-Vulnerability%20Scanner-667eea)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![AI](https://img.shields.io/badge/AI-Groq%2BOpenRouter-ff6b6b)

**CyberShield** is an advanced, AI-powered vulnerability scanner that combines multiple scanning techniques with intelligent analysis powered by Groq and OpenRouter AI.

</div>

## Features

### Scanning Capabilities
- **Port Scanning**: Fast and comprehensive port scanning using nmap
- **Service Detection**: Identify running services and versions
- **Vulnerability Assessment**: Check for common security issues
- **CVE Database Integration**: Match services against known vulnerabilities
- **Deep Vulnerability Scanning**: Advanced web vulnerability detection
- **SSL/TLS Analysis**: Certificate and cipher suite checking

### AI-Powered Analysis
- **Groq AI Integration**: Uses Qwen-32B model for intelligent analysis
- **OpenRouter AI Integration**: Support for Claude, Gemini, and other models
- **Real-time Recommendations**: AI-generated remediation plans
- **Interactive Assistant**: Chat with security AI expert
- **Risk Assessment**: Intelligent risk scoring and prioritization
- **Executive Reports**: Professional security assessment reports

### Scan Modes
- **Quick Scan**: Fast port scanning and service detection
- **Full Scan**: Comprehensive vulnerability assessment
- **Deep Scan**: Advanced AI-powered analysis with deep vulnerability checks

### Modern Web Interface
- **Dark Theme UI**: Professional cybersecurity aesthetic
- **Real-time Progress**: Live scanning progress with detailed steps
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Interactive Charts**: Visual risk assessment and statistics
- **Export Options**: HTML and JSON report generation

## Installation

### Prerequisites
- Python 3.8+
- pip package manager
- Groq API Key (free at [console.groq.com](https://console.groq.com))
- OpenRouter API Key (free at [openrouter.ai](https://openrouter.ai))
- Nmap (optional, for advanced port scanning)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/your-repo/cybershield.git
cd cybershield

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env and add your API keys

# Run the application
python app.py
```

### Access the Application

Open your browser and navigate to:
```
http://localhost:5000
```

## Configuration

Create a `.env` file in the project root:

```env
# Groq API Key (recommended for speed)
GROQ_API_KEY=your_groq_api_key_here

# OpenRouter API Key (alternative)
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Flask Configuration
SECRET_KEY=your-secret-key
DEBUG=True
PORT=5000

# Optional: NVD API Key for CVE lookups
NVD_API_KEY=your_nvd_api_key_here
```

## API Endpoints

### Scan Endpoints
- `POST /scan` - Start a new scan
- `GET /scan/status/<scan_id>` - Get scan status
- `GET /scan/results/<scan_id>` - Get scan results

### AI Endpoints
- `GET /ai/status` - Check AI assistant status
- `POST /ai/analyze` - Get AI analysis for scan results
- `POST /ai/ask` - Ask AI assistant a question
- `POST /ai/remediation` - Get AI-generated remediation plan
- `POST /ai/chat` - Interactive chat with AI assistant

### Report Endpoints
- `POST /report/generate` - Generate PDF/JSON report

### Provider Endpoints
- `GET /api/providers` - List available AI providers
- `POST /api/provider/set` - Set active AI provider

## Project Structure

```
cybershield/
├── app.py                    # Main Flask application
├── requirements.txt           # Python dependencies
├── .env.example              # Environment variables template
├── templates/
│   └── index.html            # Main HTML template
├── static/
│   ├── style.css             # Stylesheet
│   └── script.js             # JavaScript
├── utils/
│   ├── ai_client.py          # Multi-provider AI client
│   ├── ai_assistant.py       # AI assistant functionality
│   ├── port_scanner.py       # Port scanning utilities
│   ├── vulnerability_checker.py # Vulnerability detection
│   ├── cve_lookup.py         # CVE database integration
│   └── report_generator.py   # Report generation
└── scanners/
    └── fast_scanner.py       # Deep vulnerability scanner
```

########################################
###from CyberShield featurea:
- Multiple scan modes (ultra, quick, standard)
- CLI interface support
- Advanced vulnerability detectors (SQLi, XSS, path traversal)
- Database support for scan history
- Rich console output
- HTML/JSON reporting
- Modern dark-themed UI
- Groq AI integration
- CVE lookup from NVD
- Interactive AI chat assistant
- Risk assessment
- Security features

## Troubleshooting

### Common Issues

**"nmap not found" errors**: Install nmap or the scanner will use fallback methods.

**AI features not working**: 
1. Check that you have set GROQ_API_KEY or OPENROUTER_API_KEY in .env
2. Verify your API key is valid and has available credits

**Scan timeouts**: 
1. Use Quick Scan mode for faster results
2. Check network connectivity
3. Ensure target is reachable

### Debug Mode

Run with Flask debug mode enabled:
```bash
FLASK_DEBUG=True python app.py
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

CyberShield is designed for authorized security testing only. Unauthorized scanning of systems you don't own or have permission to test may be illegal. Always obtain proper authorization before scanning any target.

---

<div align="center">

**CyberShield** - Protecting systems with AI-powered security intelligence

</div>
