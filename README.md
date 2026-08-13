# ThreatLens AI

## AI-Powered Cybersecurity Incident Investigation and Threat Analysis System

## Overview

ThreatLens AI is an AI-powered cybersecurity incident investigation system designed to analyze security logs and identify potential threats. The system combines machine learning, rule-based threat detection, Indicator of Compromise (IOC) extraction, MITRE ATT&CK mapping, risk assessment, and automated security report generation.

The goal of ThreatLens AI is to help security analysts investigate security incidents more efficiently by transforming raw security logs into structured and understandable security findings.

---

## Problem Statement

Security logs contain valuable information about suspicious activities and potential cyber attacks, but manually analyzing large volumes of logs can be time-consuming and difficult.

ThreatLens AI addresses this problem by providing an automated investigation workflow that can:

- Process uploaded security log files
- Parse security events
- Detect suspicious activities
- Extract Indicators of Compromise (IOCs)
- Classify threats using machine learning
- Map detected threats to MITRE ATT&CK techniques
- Calculate an overall risk assessment
- Generate investigation reports

---

## Objectives

The main objectives of ThreatLens AI are:

1. Automate the initial analysis of security logs.
2. Detect common cybersecurity threats and suspicious activities.
3. Extract useful Indicators of Compromise from security evidence.
4. Use machine learning for threat classification.
5. Map detected attacks to MITRE ATT&CK techniques.
6. Provide a centralized dashboard for security investigation.
7. Generate structured security investigation reports.

---

## Key Features

### 1. Security Evidence Upload

The system allows users to upload supported security evidence files, including:

- `.log`
- `.txt`
- `.json`
- `.csv`
- `.xml`
- `.evtx`

### 2. Log Parsing

ThreatLens AI processes uploaded logs and extracts useful information such as:

- Timestamps
- Hostnames
- Usernames
- Process names
- Security events

### 3. IOC Extraction

The system extracts potential Indicators of Compromise from security evidence, including suspicious IP addresses and other relevant security indicators.

### 4. Rule-Based Threat Detection

ThreatLens AI uses pattern and rule-based detection to identify suspicious activities such as:

- Failed Login Attempts
- SSH Attacks
- Successful Login Events
- Privilege Escalation Attempts
- Unauthorized Access
- Brute Force Attacks
- SQL Injection Attempts
- Cross-Site Scripting (XSS)
- Web Scanning
- Malware Indicators
- Suspicious Commands

### 5. Machine Learning Threat Classification

The system uses a machine learning pipeline based on:

- TF-IDF Vectorization
- Unigram and Bigram features
- Random Forest Classifier

The model analyzes security log text and classifies observed activity into predefined threat categories.

The project also uses confidence scores to support the interpretation of machine learning predictions.

### 6. MITRE ATT&CK Mapping

Detected threats are mapped to relevant MITRE ATT&CK techniques to provide additional context about attacker behavior.

Examples include:

- **T1110** - Brute Force
- **T1078** - Valid Accounts
- **T1059** - Command and Scripting Interpreter
- **T1190** - Exploit Public-Facing Application

### 7. Risk Assessment

ThreatLens AI evaluates detected security activity and provides an overall risk assessment based on the identified threats and indicators.

The dashboard presents information such as:

- Total log events
- Total IOCs
- Total detected threats
- Risk score
- Severity level
- MITRE ATT&CK mappings

### 8. Security Dashboard

The web-based dashboard provides a centralized view of the investigation results, including:

- Threat statistics
- IOC information
- Risk analytics
- Threat activity
- MITRE ATT&CK mappings
- AI analysis
- Incident information

### 9. Automated PDF Reports

ThreatLens AI can generate structured PDF investigation reports containing relevant findings from the security analysis.

---

## System Workflow

```text
Security Evidence
       |
       v
File Upload
       |
       v
Log Parsing
       |
       +----------------------+
       |                      |
       v                      v
IOC Extraction          Threat Detection
                              |
                              v
                     Machine Learning
                     Threat Classification
                              |
                              v
                     MITRE ATT&CK Mapping
                              |
                              v
                       Risk Assessment
                              |
                              v
                     Investigation Dashboard
                              |
                              v
                       PDF Report
```

---

## Technology Stack

### Programming Language

- Python

### Backend

- Flask

### Machine Learning

- Scikit-learn
- TF-IDF Vectorizer
- Random Forest Classifier

### Data Processing

- Pandas

### Frontend

- HTML
- CSS
- JavaScript
- Chart.js

### Report Generation

- ReportLab

### Threat Framework

- MITRE ATT&CK

### Dataset

- LogHub Security Log Dataset
- Custom Security Test Logs

---

## Machine Learning Methodology

ThreatLens AI uses a text-based machine learning pipeline for security threat classification.

### ML Workflow

```text
Security Logs
     |
     v
Text Preprocessing
     |
     v
TF-IDF Vectorization
     |
     v
Unigram + Bigram Features
     |
     v
Random Forest Classifier
     |
     v
Threat Classification
     |
     v
Confidence Score
```

### TF-IDF

TF-IDF (Term Frequency-Inverse Document Frequency) converts security log text into numerical feature vectors that can be processed by the machine learning model.

The system uses unigram and bigram features to capture individual terms as well as combinations of terms occurring in security logs.

### Random Forest

The resulting TF-IDF feature vectors are provided to a Random Forest classifier for threat classification.

The classifier identifies predefined security activity categories based on patterns learned from the training data.

---

## Dataset

ThreatLens AI uses security log data for machine learning, analysis, and system testing.

The project incorporates data derived from LogHub, including security logs from:

- Linux
- OpenSSH
- Apache
- Windows

Additional custom security logs are used to test specific attack scenarios such as:

- Brute Force
- SSH Attacks
- SQL Injection
- XSS Attempts
- Privilege Escalation
- Suspicious Activities

The dataset is processed and prepared for use by the machine learning and rule-based analysis components.

---

## Backend Architecture

The Flask backend coordinates the different components of ThreatLens AI.

### Main Backend Components

| File / Module | Purpose |
|---|---|
| `app.py` | Flask application, routes, uploads, dashboard and application flow |
| `analyzer/threat_detector.py` | Rule-based threat detection |
| `analyzer/train_model.py` | Machine learning model training |
| `ai/ai_analyzer.py` | AI-based threat analysis and classification |
| `report_generator.py` | Automated PDF report generation |
| `mitre/attack_data.json` | MITRE ATT&CK technique mappings |

### Backend Workflow

```text
User
 |
 v
Flask Web Application
 |
 v
File Upload
 |
 v
Log Parser
 |
 +----------------------+
 |                      |
 v                      v
IOC Extraction     Threat Detection
                         |
                         v
                  ML Classification
                         |
                         v
                  MITRE ATT&CK
                         |
                         v
                   Risk Analysis
                         |
                         v
                Investigation Dashboard
                         |
                         v
                    PDF Report
```

---

## Project Structure

```text
AI-Security-Incident-Investigator/
│
├── ai/
│   ├── ai_analyzer.py
│   ├── threat_model.pkl
│   └── multiclass_threat_model.pkl
│
├── analyzer/
│   ├── train_model.py
│   └── threat_detector.py
│
├── datasets/
│   ├── security_logs.csv
│   └── enhanced_security_logs.csv
│
├── logs/
│
├── mitre/
│   └── attack_data.json
│
├── reports/
│
├── static/
│   └── index.css
│
├── templates/
│   ├── index.html
│   └── dashboard.html
│
├── uploads/
│
├── app.py
├── report_generator.py
├── requirements.txt
└── README.md
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/zamanraima48-blip/ThreatLens-AI.git
```

### 2. Enter the Project Directory

```bash
cd ThreatLens-AI
```

### 3. Create a Virtual Environment

```bash
python3 -m venv venv
```

### 4. Activate the Virtual Environment

For Linux / Kali Linux:

```bash
source venv/bin/activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Application

Start the Flask application using:

```bash
python app.py
```

After starting the application, open the local Flask address displayed in the terminal using a web browser.

The application provides a web interface through which security evidence can be uploaded and analyzed.

---

## Usage

### Step 1: Upload Security Evidence

Upload a supported security log or evidence file through the ThreatLens AI interface.

### Step 2: Log Processing

The system parses the uploaded evidence and extracts relevant security information.

### Step 3: IOC Extraction

Potential Indicators of Compromise, including suspicious IP addresses, are extracted from the evidence.

### Step 4: Threat Detection

Rule-based detection identifies suspicious activities and attack patterns.

### Step 5: Machine Learning Analysis

The machine learning model classifies security activity into predefined threat categories.

### Step 6: MITRE ATT&CK Mapping

Detected threats are mapped to relevant MITRE ATT&CK techniques.

### Step 7: Risk Assessment

The system calculates an overall risk assessment and assigns a severity level.

### Step 8: Dashboard Analysis

The investigation results are displayed through the ThreatLens AI dashboard.

### Step 9: Report Generation

A structured PDF investigation report can be generated from the analysis results.

---

## Testing

ThreatLens AI was tested using different security log scenarios, including:

- Failed Login Attempts
- SSH Attack Patterns
- Brute Force Attacks
- Privilege Escalation Attempts
- Unauthorized Access
- SQL Injection Attempts
- Cross-Site Scripting (XSS)
- Web Scanning Activity
- Suspicious Commands
- Malware Indicators

Testing was performed using security datasets and custom security test logs.

---

## Limitations

Although ThreatLens AI provides automated security investigation capabilities, it has several limitations:

- Detection performance depends on the quality and coverage of the available training data.
- Machine learning predictions may produce false positives or false negatives.
- Rare attack categories may have limited training examples.
- Previously unseen attack techniques may not always be detected.
- The system is designed to assist security analysts rather than completely replace human investigation.
- Different log formats may require additional parsing rules.
- The current system is primarily designed for security log and evidence analysis rather than complete real-time enterprise monitoring.

---

## Future Enhancements

Future versions of ThreatLens AI may include:

- Real-time log monitoring
- SIEM platform integration
- Threat intelligence API integration
- Automated incident response
- Advanced anomaly detection
- Larger and more diverse security datasets
- Deep learning-based threat classification
- Docker-based deployment
- Cloud deployment
- Role-based access control
- Advanced IOC enrichment
- Improved real-time visualization

---

## Security Considerations

ThreatLens AI should only be used with security evidence that the user is authorized to analyze.

Security logs may contain sensitive information such as IP addresses, usernames, hostnames, and authentication events. Appropriate access controls and secure deployment practices should be applied when using the system in a production environment.

---

## Project Status

ThreatLens AI is an AI-assisted cybersecurity incident investigation project.

The current implementation focuses on:

- Security evidence upload
- Security log parsing
- IOC extraction
- Rule-based threat detection
- Machine learning threat classification
- MITRE ATT&CK mapping
- Risk assessment
- Security dashboard
- Automated PDF report generation

---

## GitHub Repository

The complete source code, project files, and documentation are available at:

**https://github.com/zamanraima48-blip/ThreatLens-AI**

---

## Author

**Raima Zaman**

Computer Science Student

---

## License

This project is developed for educational and research purposes.
