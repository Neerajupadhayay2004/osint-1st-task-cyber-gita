<img width="1920" height="1080" alt="Screenshot_2026-05-14_15-34-19" src="https://github.com/user-attachments/assets/89103ffe-98b3-46cc-bdaa-6f09c75278d5" />
<img width="1920" height="1080" alt="Screenshot_2026-05-14_15-34-30" src="https://github.com/user-attachments/assets/d5a551b7-1d26-4690-9d4f-279307e0f0b3" />
<img width="1920" height="1080" alt="Screenshot_2026-05-14_15-35-30" src="https://github.com/user-attachments/assets/99d81dcc-b442-4a43-bc15-0aca1710bb16" />
<img width="1920" height="1080" alt="Screenshot_2026-05-14_15-48-28" src="https://github.com/user-attachments/assets/8742a120-4607-491f-9517-84329d2050d3" />

# 🛡️ OSINT Intelligence Gathering Platform

A powerful Python-based Open Source Intelligence (OSINT) and Cybersecurity Investigation Platform developed for ethical hacking, intelligence gathering, digital investigations, reconnaissance, and security analysis.

The platform combines multiple cybersecurity and OSINT functionalities into a single centralized system using modern web technologies and Python backend services.

---

# 🚀 Project Overview

The OSINT Intelligence Gathering Platform is designed to automate the collection and analysis of publicly available information from multiple online sources.

The application helps security researchers, cybersecurity students, ethical hackers, investigators, and analysts gather intelligence related to:

* Domains
* IP addresses
* Emails
* Usernames
* Websites
* Network information
* Security vulnerabilities

The backend is primarily built using **Python**, making the platform scalable, modular, and efficient for cybersecurity operations.

---

# 📂 Project Structure

```text
osint-1st-task-cyber-gita-main/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── datasets/
│   │   ├── ml/
│   │   ├── models/
│   │   ├── services/
│   │   └── main.py
│   │
│   ├── exports/
│   ├── osint_platform.db
│   ├── requirements.txt
│   ├── Procfile
│   └── render.yaml
│
├── src/
├── public/
├── supabase/
├── package.json
├── vite.config.ts
├── vercel.json
└── netlify.toml
```

---

# 🐍 Python Backend Architecture

The backend is developed using Python and structured into multiple modules for better maintainability and scalability.

## 📁 `app/api/`

Contains API route handlers and endpoint definitions.

### Responsibilities

* Handles incoming HTTP requests
* Processes user inputs
* Connects frontend with backend services
* Returns JSON responses

### Example Features

* Domain lookup API
* IP intelligence API
* Email validation API
* Username search API

---

## 📁 `app/core/`

Contains core backend configurations and utilities.

### Responsibilities

* Configuration management
* Security settings
* Authentication handling
* Environment variables
* Logging system

---

## 📁 `app/datasets/`

Stores cybersecurity and machine learning datasets.

### Usage

* Threat intelligence datasets
* Malicious IP lists
* Phishing detection datasets
* ML training data

---

## 📁 `app/ml/`

Machine Learning and AI-related modules.

### Possible Features

* Threat prediction
* Malicious URL detection
* Spam classification
* Anomaly detection
* AI-powered risk analysis

### Python Libraries Used

* Scikit-learn
* TensorFlow
* Pandas
* NumPy

---

## 📁 `app/models/`

Database models and schema definitions.

### Responsibilities

* User models
* Scan history models
* Report storage
* Investigation records

### Database Support

* SQLite
* MongoDB

---

## 📁 `app/services/`

Contains OSINT services and cybersecurity tools integration.

### Services Included

* WHOIS lookup
* DNS enumeration
* IP geolocation
* Port scanning
* Email intelligence
* Threat intelligence APIs
* Technology detection

---

## 📄 `main.py`

Main Python backend entry point.

### Responsibilities

* Starts the backend server
* Initializes APIs
* Connects services
* Loads configurations

### Example Run Command

```bash
python main.py
```

---

# ⚡ Backend Features

## 🌐 Domain Intelligence

* WHOIS Lookup
* DNS Records
* Subdomain Enumeration
* SSL Certificate Analysis

## 📡 IP Intelligence

* IP Geolocation
* Open Port Detection
* Reverse DNS
* ISP Detection

## 📧 Email Intelligence

* Email Validation
* Breach Checking
* Metadata Extraction

## 👤 Username Intelligence

* Username Tracking
* Social Media Presence Detection

## 🔐 Security Scanning

* Basic Vulnerability Detection
* Security Header Analysis
* Website Technology Detection

## 🤖 AI & ML Features

* Threat Detection
* Risk Prediction
* URL Classification
* Suspicious Activity Analysis

---

# 🧰 Python Technologies Used

## Backend Frameworks

* Python
* Flask / FastAPI
* SQLAlchemy

## Cybersecurity Libraries

* python-whois
* requests
* dnspython
* scapy
* socket
* shodan APIs

## Machine Learning

* TensorFlow
* Scikit-learn
* Pandas
* NumPy

## Database

* SQLite
* MongoDB

---

# 🔒 Security Features

The backend implements multiple security mechanisms:

* Input validation
* API protection
* Rate limiting
* Secure request handling
* Environment variable protection
* Secure authentication
* Error handling

---

# ⚙️ Installation Guide

## 1️⃣ Clone Repository

```bash
git clone https://github.com/your-username/osint-platform.git
```

---

## 2️⃣ Navigate to Backend

```bash
cd backend
```

---

## 3️⃣ Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## 4️⃣ Run Backend Server

```bash
python app/main.py
```

---

# 📦 Example Requirements

```txt
flask
fastapi
uvicorn
requests
python-whois
dnspython
scapy
pandas
numpy
scikit-learn
tensorflow
sqlalchemy
```

---

# 🌍 Frontend Integration

The backend connects with a frontend developed using:

* React.js
* TypeScript
* Tailwind CSS
* Vite

The frontend communicates with Python APIs to display intelligence reports and cybersecurity analytics.

---

# ☁️ Deployment Support

Deployment configurations available for:

* [Vercel](https://vercel.com?utm_source=chatgpt.com)
* [Netlify](https://www.netlify.com?utm_source=chatgpt.com)
* [Render](https://render.com?utm_source=chatgpt.com)
* [Cloudflare Workers](https://workers.cloudflare.com?utm_source=chatgpt.com)

Files detected:

* `vercel.json`
* `netlify.toml`
* `render.yaml`
* `wrangler.jsonc`

---

# 📊 Possible Workflow

```text
User Request
      ↓
Frontend Dashboard
      ↓
Python Backend APIs
      ↓
OSINT Services & Security Tools
      ↓
Data Processing & ML Analysis
      ↓
Database Storage
      ↓
Results & Reports
```

---

# 🚧 Future Improvements

* Dark Web Monitoring
* Real-Time Alerts
* AI Threat Detection
* Advanced Vulnerability Scanner
* PDF Report Generation
* Mobile App Integration
* Multi-user Collaboration
* Threat Intelligence Dashboard

---

# 📚 Learning Outcomes

This project demonstrates practical implementation of:

* Python backend development
* Cybersecurity fundamentals
* OSINT methodologies
* Ethical hacking concepts
* Machine learning integration
* Full-stack web development
* API development
* Security analysis

---

# ⚠️ Ethical Usage Disclaimer

This platform is intended strictly for:

* Educational purposes
* Ethical hacking
* Cybersecurity learning
* Authorized security testing
* Research and development

Unauthorized access, illegal scanning, or malicious activities are strictly prohibited.

---

# 👨‍💻 Developer

## Neeraj Upadhayay

### Roles

* Full Stack Developer
* Cybersecurity Researcher
* OSINT Developer
* Python Backend Developer

### Skills

* Python
* React.js
* TypeScript
* Cybersecurity
* Linux
* API Development
* Machine Learning

### GitHub

[Neeraj29118 GitHub](https://github.com/Neeraj29118?utm_source=chatgpt.com)

### LinkedIn

[Neeraj Upadhayay LinkedIn](https://www.linkedin.com/in/neeraj-upadhayay-2nd-a0958a246?utm_source=chatgpt.com)

---

# ⭐ Support

If this project helped in learning cybersecurity or OSINT concepts, consider starring the repository on GitHub.

---

# 🛡️ References

* [OWASP](https://owasp.org?utm_source=chatgpt.com)
* [Python Official Website](https://www.python.org?utm_source=chatgpt.com)
* [Flask Framework](https://flask.palletsprojects.com?utm_source=chatgpt.com)
* [FastAPI](https://fastapi.tiangolo.com?utm_source=chatgpt.com)
* [Scikit-learn](https://scikit-learn.org?utm_source=chatgpt.com)
* [TensorFlow](https://www.tensorflow.org?utm_source=chatgpt.com)
* [Nmap](https://nmap.org?utm_source=chatgpt.com)
* [Wireshark](https://www.wireshark.org?utm_source=chatgpt.com)
