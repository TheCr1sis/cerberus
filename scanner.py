import os
import json
import hashlib
from datetime import datetime

# Load IOCs from file
def load_iocs(ioc_file):
    with open(ioc_file, "r") as f:
        return json.load(f)

# Get file hashes
def get_file_hashes(filepath):
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            for algo in hashes.values():
                algo.update(chunk)
    return {name: algo.hexdigest() for name, algo in hashes.items()}

# Save scan results to a JSON file
def save_scan_results(results):
    timestamp = datetime.now().strftime("%Y-%m-%dT%H%M%S")
    filename = f"{timestamp}_scan_results"
    file_path = os.path.join("results", f"{filename}.json")

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    return filename

# Scan directories for files with matching IOCs
def scan_directory(directory, iocs, check_subfolders, ioc_filename):
    matches = []
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_size = os.path.getsize(filepath)
            file_hashes = get_file_hashes(filepath)
            matched_attributes = []
            matched_strings = []

            if filename in iocs.get("filenames", []):
                matched_attributes.append("Filename")

            if file_size in iocs.get("filesizes", []):
                matched_attributes.append("File Size")

            for hash_type, hash_list in iocs.get("hashes", {}).items():
                if file_hashes[hash_type] in hash_list:
                    matched_attributes.append(hash_type.upper())

            try:
                with open(filepath, "rb") as f:
                    file_content = f.read().decode(errors="ignore")
                    matched_strings = [s for s in iocs.get("strings", []) if s in file_content]
            except Exception:
                pass

            if matched_attributes or matched_strings:
                match_entry = {
                    "filepath": filepath,
                    "filename": filename,
                    "size": file_size,
                    "hashes": file_hashes,
                    "matched": matched_attributes,
                    "associated_ioc_file": ioc_filename
                }

                if matched_strings:
                    match_entry["matched_strings"] = matched_strings[:3]
                    matched_attributes.append("Strings")

                matches.append(match_entry)

        if not check_subfolders:
            break

    # Save results to a JSON file inside "results" folder
    saved_filename = save_scan_results(matches)
    print(f"Scan results saved to {saved_filename}")

    return {"matches": matches, "filename": saved_filename, "ioc_filename": ioc_filename}