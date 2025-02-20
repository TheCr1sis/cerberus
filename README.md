# IOC-Checker

## 📌 Project Description
**IOC-Checker** is a Python-based tool designed to scan directories for files matching predefined Indicators of Compromise (IOCs). It allows to create or load an IOC file containing filenames, file sizes, hashes (MD5, SHA1, SHA256), and specific strings to detect malicious or suspicious files within a given directory and subdirectories.

## Features
- Create or load an IOC file in JSON format.
- Scan directories and subdirectories for matching IOCs.
- Identify files based on:
  - Filenames
  - File sizes
  - Cryptographic hashes (MD5, SHA1, SHA256)
  - Specific strings within file content
- Generate a JSON report with detected matches.

## Installation
To use **IOC-Checker**, ensure you have Python installed on your system. Then, clone this repository and install the necessary modules.

## Usage
Run the script using Python and follow the on-screen prompts.

```bash
python main.py
```

## Testing

A testing folder **target** is included in this repository, containing various files and subdirectories that you can use to test the IOC-Checker's functionality. You can specify the testing folder as the scan directory when prompted.

### Example Run
```
Do you have an existing IOC file? (yes/no): yes
Enter the full path to your IOC JSON file: iocs.json
Enter directory to scan: /path/to/directory
Analyze subfolders? (yes/no): yes

Scan Summary:
Total Matches: 1
===========================================
File Path: /path/to/malicious.exe
Filename: malicious.exe
Size: 45678 bytes
MD5: 5d41402abc4b2a76b9719d911017c592
SHA1: 7c4a8d09ca3762af61e59520943dc26494f8941b
SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5d5c6a9e732f6d29b34b1af7a1
Matched Criteria: Filename, SHA256
===========================================
Results saved to: scan_results.json
```

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
