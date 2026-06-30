# 🛡️ AegisHealth — HIPAA Compliance Checker & Deployment Platform

A web platform that automatically checks healthcare websites for HIPAA compliance and blocks non-compliant code from reaching production.

## What It Does
- Paste any URL → get instant HIPAA compliance score (0-100)
- Color coded results: Red = critical, Yellow = warning, Green = good
- 28 automated HIPAA technical safeguard checks
- Deployment gate — code must pass all checks before going live
- Full audit log of every scan and deployment

## Tech Stack
- **Frontend:** React 19 + Vite + Tailwind CSS
- **Backend:** Python 3.12 + FastAPI
- **Database:** PostgreSQL
- **DevOps:** Docker + GitHub Actions + AWS EC2
- **AI/ML:** Weighted scoring engine + OpenAI suggestions

## Team
- DevOps Lead — Backend, CI/CD, AWS, Docker
- Cybersecurity — HIPAA test cases, security module
- AI/ML — Scoring engine, analytics dashboard

## Setup

### 1. Backend
The backend includes a ready-to-use local env file at `backend/.env`. For a fresh setup, you can also copy `backend/.env.example`.

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Backend URL: `http://localhost:8000`
Database: local SQLite file at `backend/aegishealth.db`

### 2. Frontend
The frontend reads its API base URL from `frontend/.env`.

```bash
cd frontend
npm install
npm run dev
```

Frontend URL: `http://localhost:5173`

### 3. One-click start
To start both frontend and backend without Docker:

```bash
./start.command
```

## API Docs
Once the backend is running, visit: `http://localhost:8000/docs`
