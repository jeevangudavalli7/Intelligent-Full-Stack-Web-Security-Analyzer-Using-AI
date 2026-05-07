# Intelligent Full-Stack Web Security Analyzer Using AI

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/React-18-blue.svg" alt="React">
  <img src="https://img.shields.io/badge/FastAPI-0.104+-green.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

An AI-powered full-stack web vulnerability scanner that combines traditional security scanning with machine learning for intelligent vulnerability detection and false positive elimination.

## Features

### 🔍 Vulnerability Scanning
- **SQL Injection Scanner** - Detects SQL injection vulnerabilities
- **XSS Scanner** - Identifies cross-site scripting vulnerabilities  
- **CSRF Scanner** - Finds cross-site request forgery issues
- **Custom Scans** - Full, quick, or specific vulnerability type scans

### 🤖 Machine Learning
- **Vulnerability Classification** - ML-powered detection to reduce false positives
- **Confidence Scoring** - Each finding includes ML confidence percentage
- **Risk Analysis** - Automated risk scoring and prioritization
- **Feature Importance** - Understand what makes a finding significant

### 📝 NLP Reports
- **Natural Language Summaries** - AI-generated human-readable reports
- **Multiple Formats** - JSON, HTML, and NLP-enhanced reports
- **Actionable Recommendations** - Prioritized remediation guidance
- **Executive Summaries** - High-level overviews for stakeholders

### 🏗️ Architecture
- **RESTful API** - Full programmatic access via API
- **Async Processing** - Non-blocking scans using Celery
- **Real-time Updates** - WebSocket support for live progress
- **Scalable** - Kubernetes-ready deployment manifests

## Tech Stack

### Backend
- **FastAPI** - Modern async Python web framework
- **SQLAlchemy** - Database ORM
- **PostgreSQL** - Primary database
- **Redis** - Task queue (Celery)
- **scikit-learn** - ML classification

### Frontend
- **React 18** - UI framework
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Recharts** - Data visualization

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Docker & Docker Compose (optional)

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/jeevangudavalli7/Intelligent-Full-Stack-Web-Security-Analyzer-Using-AI
cd security-analyzer

# Copy environment file
cp backend/.env.example backend/.env

# Start all services
docker-compose up -d

# Access the application
# Frontend: http://localhost:5173
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Manual Setup

#### Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start the server
uvicorn main:app --reload
```

#### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

## Usage

### Web Interface

1. Open http://localhost:5173 in your browser
2. Login with default credentials: `admin` / `password`
3. Enter a URL to scan
4. View results and generate reports

### API Usage

```bash
# Get access token
curl -X POST "http://localhost:8000/api/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=password"

# Create a scan
curl -X POST "http://localhost:8000/api/scans/" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "scan_type": "full"}'
```

## Project Structure

```
.
├── backend/
│   ├── api/
│   │   └── routes/         # API endpoints
│   ├── scanner/             # Vulnerability scanners
│   ├── ml/                 # ML pipeline & models
│   ├── nlp/                # NLP report generation
│   ├── db/                 # Database models & schema
│   ├── main.py             # FastAPI application
│   ├── config.py           # Configuration
│   └── celery_app.py       # Celery configuration
├── frontend/
│   ├── src/
│   │   ├── api/            # API client
│   │   ├── components/    # Reusable UI components
│   │   ├── hooks/          # Custom React hooks
│   │   ├── tabs/           # Main application tabs
│   │   ├── App.jsx         # Main app component
│   │   └── main.jsx        # Entry point
│   ├── package.json
│   └── vite.config.js
├── k8s/                    # Kubernetes manifests
├── docker-compose.yml
└── README.md
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT secret key | Auto-generated |
| `DATABASE_URL` | PostgreSQL connection | postgresql://... |
| `REDIS_URL` | Redis connection | redis://localhost:6379/0 |
| `ML_CONFIDENCE_THRESHOLD` | ML confidence threshold | 0.75 |
| `SCAN_TIMEOUT` | Max scan duration (seconds) | 300 |

## Deployment

### Docker Compose (Development)
```bash
docker-compose up -d
```

### Kubernetes (Production)
```bash
# Apply manifests
kubectl apply -f k8s/

# Check status
kubectl get pods -l app=security-analyzer
```

## API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Security Considerations

⚠️ **Important**: 
- Change `SECRET_KEY` in production
- Use strong database passwords
- Enable HTTPS in production
- Configure CORS for your domain
- Implement rate limiting

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Built with FastAPI, React, and scikit-learn
- Inspired by OWASP testing guide
- ML model trained on publicly available vulnerability datasets

