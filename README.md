# Security Log Analyzer & Security Dashboard

A Python-based security log analyzer that processes authentication and system events, detects potentially suspicious activity, and displays the results through an interactive Streamlit dashboard.

## Features

- Parses security logs using Python and pandas
- Detects brute-force login attempts
- Detects successful logins after repeated failures
- Identifies unfamiliar IP addresses
- Detects after-hours logins
- Identifies excessive user activity
- Provides an interactive dashboard with security metrics and filters

## Technologies

- Python
- pandas
- Streamlit

## Project Structure

```text
security-log-analyzer/
├── logs_security.log
├── main.py
├── parser.py
├── detector.py
└── dashboard.py
```

## How It Works

```text
Security Log
     ↓
Log Parser
     ↓
Pandas DataFrame
     ↓
Detection Rules
     ↓
Security Alerts
     ↓
Streamlit Dashboard
```

## Run the Project

Install the required packages:

```bash
pip install pandas streamlit
```

Run the dashboard:

```bash
streamlit run dashboard.py
```

## Data

The project uses synthetic security logs created for testing and demonstration purposes.
