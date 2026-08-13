# ThreatLens AI

AI-Powered Cybersecurity Incident Investigation and Threat Analysis System

## Overview

ThreatLens AI is an AI-powered cybersecurity incident investigation system designed to analyze security logs and identify potential threats. The system combines machine learning, rule-based threat detection, Indicator of Compromise (IOC) extraction, MITRE ATT&CK mapping, risk assessment, and automated security report generation.

The goal of ThreatLens AI is to help security analysts investigate security incidents more efficiently by transforming raw security logs into structured and understandable security findings.

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

## Objectives

The main objectives of ThreatLens AI are:

1. Automate the initial analysis of security logs.
2. Detect common cybersecurity threats and suspicious activities.
3. Extract useful Indicators of Compromise from security evidence.
4. Use machine learning for threat classification.
5. Map detected attacks to MITRE ATT&CK techniques.
6. Provide a centralized dashboard for security investigation.
7. Generate structured security investigation reports.

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
- N-gram features
- Random Forest Classifier

The model analyzes security log text and classifies observed activity into threat categories.

The project also uses confidence scores to support the interpretation of machine learning predictions.

### 6. MITRE ATT&CK Mapping

Detected threats are mapped to relevant MITRE ATT&CK techniques to provide additional context about attacker behavior.

Examples include:

- T1110 - Brute Force
- T1078 - Valid Accounts
- T1059 - Command and Scripting Interpreter
- T1190 - Exploit Public-Facing Application

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
