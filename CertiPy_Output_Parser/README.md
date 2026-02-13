# Certipy JSON Viewer

A Flask-based web application for viewing and analyzing Certipy JSON output files. This tool helps visualize and assess Active Directory Certificate Services (AD CS) configurations and identify potential vulnerabilities.

## Features

- **SQLite Database Storage**: Store multiple Certipy assessment projects
- **File Upload Interface**: Easy-to-use web form for uploading JSON files
- **Vulnerability Detection**: Automatically detects ESC1, ESC2, ESC3, ESC4, ESC8 and ESC15 vulnerabilities
- **Detailed Analysis**: Comprehensive view of certificate templates, permissions, and flags
- **Imported Data Management**: View, search, and delete projects

## Installation

### Prerequisites

- Python 3.7+
- pip

### Setup

1. Install Flask:
```bash
pip install flask
```

2. Run the application:
```bash
python app.py
```

3. Open your browser and navigate to:
```
http://localhost:8000
```

## Usage

### 1. Generate Certipy JSON Output

First, run Certipy to enumerate certificate templates in your target Active Directory environment:

```bash
certipy find -u user@domain.local -p password -dc-ip 10.10.10.10
```

This will generate a JSON file (e.g., `20240210123456_Certipy.json`)

### 2. Upload to the Viewer

1. Navigate to the "Upload Project" page
2. Enter a descriptive project name (e.g., "Indishell Lab")
3. Select the Certipy JSON file
4. Click "Upload Project"

### 3. View Analysis

1. Go to "View Projects" to see all uploaded assessments
2. Click "View Analysis" on any project to see:
   - Certificate template details
   - Enrollment and private key flags
   - Extended Key Usage (EKU) information
   - Access Control Lists (ACLs)
   - Detected vulnerabilities

## Vulnerability Detection

The tool automatically detects the following AD CS vulnerabilities:

- **ESC1**: Domain Escalation via Enrollee-Supplied Subject + Client Authentication
- **ESC2**: Any Purpose EKU allows certificates for any purpose
- **ESC3**: Enrollment Agent template abuse
- **ESC4**: Vulnerable ACL permissions (WriteDacl/WriteOwner for low-privileged users)
- **ESC8**: Web Enrollment Endpoint is Enabled and no Channel Binding enabled
- **ESC15**: Enrollee-Supplied Subject + Template Schema version 1



## Database Schema

The application uses a simple SQLite database with one table:

```sql
CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT NOT NULL UNIQUE,
    json_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Credits

- **Certipy**: https://github.com/ly4k/Certipy
- SpecterOps for AD CS reearch
- Dominic Sir, Matt Johnson bhai ji, Zero cool, Code Breaker ICA
- Ashwath, Andy, Marcus and Soroush sir
- RGO members: Konsta, Noman, Owais, Sina, Aleseendro, Samarth, Roshan
- Partner in crime: Karan and Manoj
