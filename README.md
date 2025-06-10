# Cerberus

## 📌 Project Description
**Cerberus** is a Python-based tool designed to scan directories for files matching predefined Indicators of Compromise (IOCs). It allows users to create or load an IOC file containing filenames, file sizes, hashes (MD5, SHA1, SHA256), and specific strings to detect malicious or suspicious files within a given directory and subdirectories.

## Features
- Create or load an IOC file in JSON format.
- Scan directories and subdirectories for matching IOCs.
- Conduct a fast scan with premade IOC files.
- Query file information directly from VirusTotal and MalwareBazaar.
- Identify files based on:
  - Filenames
  - File sizes
  - Cryptographic hashes (MD5, SHA1, SHA256)
  - Specific strings within file content
- Generate a JSON report with detected matches.

## Installation

To install and set up **Cerberus**, follow these steps:

1. **Clone the repository**  
   ```bash
   git clone https://github.com/TheCr1sis/cerberus.git
   cd cerberus
   ```

2. **Set up a virtual environment (optional but recommended)**  
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use: venv\Scripts\activate
   ```

3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To start the **Cerberus** web application, run the following command:

```bash
python main.py
```

This will start a local web server on **http://127.0.0.1:5555/**. Open your browser and navigate to this address to access the tool.

### Available Functionalities:
- **Create IOC File:** Create a new IOC file with your custom IOCs.
- **Manual Scan:** Upload an IOC file and specify a directory for scanning.
- **Fast Scan:** Quickly scan using preloaded IOC files.
- **Upload Scan Results:** Load previously scanned results.
- **Online Lookup:** Check file details against online malware databases such as VirusTotal & MalwareBazaar (for in-app threat intelligence lookups it is recommended to get your VirusTotal and Malwarebazaar API keys)

## Testing

A testing folder **target** is included in this repository, containing various files and subdirectories that you can use to test the Cerberus functionality. You can specify the testing folder as the scan directory when prompted.

## JSON Output Format
The tool generates a JSON report containing details of matched files. Example output:

```json
[
  {
    "filepath": "/path/to/malicious.exe",
    "filename": "malicious.exe",
    "size": 45678,
    "hashes": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha1": "7c4a8d09ca3762af61e59520943dc26494f8941b",
      "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5d5c6a9e732f6d29b34b1af7a1"
    },
    "matched": ["Filename", "SHA256"]
  }
]
```

