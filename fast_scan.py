import json
import os
import hashlib
from datetime import datetime
from scanner import is_archive, extract_archive
import shutil

# Paths to precomputed hashes
FAST_SCAN_HASHES = {
    "md5": "fast_scan/md5_hashes.txt",
    "sha1": "fast_scan/sha1_hashes.txt",
    "sha256": "fast_scan/sha256_hashes.txt"
}

# Load hashes from fast scan files
def load_fast_scan_hashes():
    missing_files = []

    for hash_type, file_path in FAST_SCAN_HASHES.items():
        if not os.path.exists(file_path):
            missing_files.append(file_path)

    if missing_files:
        raise FileNotFoundError(
            f"Missing hash files: {', '.join(missing_files)}. "
            f"Please ensure all hash files exist in the fast_scan folder."
        )

    hash_dict = {"md5": set(), "sha1": set(), "sha256": set()}
    for hash_type, file_path in FAST_SCAN_HASHES.items():
        with open(file_path, "r") as f:
            hash_dict[hash_type] = set(line.strip() for line in f if line.strip())

    return hash_dict

# Function to compute file hashes
def compute_hashes(file_path):
    hashes = {"md5": None, "sha1": None, "sha256": None}

    try:
        with open(file_path, "rb") as f:
            data = f.read()
            hashes["md5"] = hashlib.md5(data).hexdigest()
            hashes["sha1"] = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        print(f"Error hashing {file_path}: {e}")

    return hashes

# Fast scan function
def fast_scan(directory, check_subfolders, archive_path=None, is_recursive=False):
    fast_scan_hashes = load_fast_scan_hashes()
    results = []

    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)

            if is_archive(file_path):
                extracted_dir = extract_archive(file_path)
                if extracted_dir:
                    archive_context = file_path if archive_path is None else archive_path
                    results.extend(fast_scan(extracted_dir,check_subfolders,archive_path=archive_context,is_recursive=True)["results"])
                    shutil.rmtree(extracted_dir, ignore_errors=True)
                continue

            file_hashes = compute_hashes(file_path)
            matched = [
                hash_type.upper()
                for hash_type, hash_value in file_hashes.items()
                if hash_value in fast_scan_hashes[hash_type]
            ]

            if matched:
                display_path = os.path.join(archive_path, filename) if archive_path else file_path
                results.append({
                    "filepath": display_path,
                    "filename": filename,
                    "size": os.path.getsize(file_path),
                    "hashes": file_hashes,
                    "matched": matched,
                    "archive_source": archive_path if archive_path else None
                })

        if not check_subfolders:
            break

    # Save results for top-level scan to a results folder
    if not is_recursive:
        timestamp = datetime.now().strftime("%Y-%m-%dT%H%M%S")
        results_dir = "results"
        os.makedirs(results_dir, exist_ok=True)
        results_file = os.path.join(results_dir, f"fast_scan_{timestamp}.json")

        with open(results_file, "w") as f:
            json.dump(results, f, indent=4)

        print(f"Fast scan results saved to {results_file}")
        return {"results": results, "filename": results_file}

    return {"results": results, "filename": None}