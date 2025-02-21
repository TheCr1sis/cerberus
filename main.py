from flask import Flask, render_template, request, jsonify
import os
import json
from scanner import load_iocs, scan_directory
from fast_scan import fast_scan
from dotenv import load_dotenv, set_key
from api_queries import query_virustotal, query_malwarebazaar

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
RESULTS_FOLDER = "results"
FAST_SCAN_FOLDER = "fast_scan"
ENV_FILE = ".env"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)
os.makedirs(FAST_SCAN_FOLDER, exist_ok=True)


# Function to create .env file with default values if it doesn't exist
def create_env_file():
    if not os.path.exists(ENV_FILE):
        # If the .env file doesn't exist, create it with default values
        with open(ENV_FILE, "w") as env_file:
            env_file.write("VT_API_KEY=\n")
            env_file.write("FF_AUTH_KEY=\n")

# Function to reload the .env file into the environment
def reload_env():
    load_dotenv(dotenv_path=ENV_FILE, override=True)

create_env_file()

load_dotenv()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/create_ioc")
def create_ioc():
    return render_template("create_ioc.html")

@app.route("/online_lookup")
def online_lookup():
    return render_template("online_lookup.html")


# Route for handling IOC file upload
@app.route("/upload", methods=["POST"])
def upload_ioc():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if not file.filename.endswith(".json"):
        return jsonify({"error": "Invalid file format. Please upload a JSON file"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    return jsonify({"message": "File uploaded successfully", "file_path": file_path})


# Route for creating new IOC file
@app.route("/create_ioc", methods=["POST"])
def save_ioc():
    data = request.json
    filename = data.get("filename")
    ioc_data = data.get("data")

    if not filename:
        return jsonify({"error": "Enter IOC file name"}), 400

    if not ioc_data:
        return jsonify({"error": "Invalid input"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, f"{filename}.json")
    with open(file_path, "w") as f:
        json.dump(ioc_data, f, indent=4)

    return jsonify({"message": "IOC file created successfully", "file_path": file_path, "success": True})


# Route for handling results file upload and reading its contents
@app.route("/upload_scan_results", methods=["POST"])
def upload_scan_results():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if not file.filename.endswith(".json"):
        return jsonify({"error": "Invalid file format. Please upload a JSON file"}), 400

    file_path = os.path.join(RESULTS_FOLDER, file.filename)
    file.save(file_path)

    # Read and return the JSON content
    try:
        with open(file_path, "r") as f:
            scan_results = json.load(f)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400

    return jsonify({"message": "File uploaded successfully", "file_path": file_path, "results": scan_results})


# Scanning route
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    ioc_file = data.get("ioc_file")
    directory = data.get("directory")
    check_subfolders = data.get("check_subfolders", False)
    ioc_filename = data.get("ioc_filename")

    iocs = load_iocs(ioc_file)
    results = scan_directory(directory, iocs, check_subfolders, ioc_filename)

    return jsonify({
        "results": results["matches"],
        "filename": results["filename"],
        "ioc_filename": results["ioc_filename"]
    })


# Get list of IOC files and results files for future display in box views
@app.route("/list_files")
def list_files():
    ioc_files = [f for f in os.listdir(UPLOAD_FOLDER) if f.endswith(".json")]

    result_files = [
        {"name": f, "mtime": os.path.getmtime(os.path.join(RESULTS_FOLDER, f))}
        for f in os.listdir(RESULTS_FOLDER) if f.endswith(".json")
    ]

    # Sort result files by modification time (newest first)
    result_files.sort(key=lambda x: x["mtime"], reverse=True)

    # Return IOCs and sorted results files
    return jsonify({
        "ioc_files": ioc_files,
        "result_files": [f["name"] for f in result_files]
    })


# Open IOC files on a new webpage
@app.route("/view_ioc/<filename>")
def view_ioc(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(file_path):
        return "File not found", 404

    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    return f"<pre>{content}</pre>"


# Load info from results file into a table on main page
@app.route("/load_results/<filename>")
def load_results(filename):
    file_path = os.path.join(RESULTS_FOLDER, filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    try:
        content_json = json.loads(content)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format in results file"}), 400

    ioc_filename = None
    if content_json:
        ioc_filename = content_json[0].get("associated_ioc_file", None)

    return jsonify({"filename": filename, "content": content_json, "ioc_filename": ioc_filename})


# Route for handling "fast scan" option and scanning files with already existing IOC files in "fast_scan" folder
@app.route("/fast_scan", methods=["POST"])
def fast_scan_route():
    data = request.json
    directory = data.get("directory")
    check_subfolders = data.get("check_subfolders", False)
    ioc_filename = "N/A"

    if not directory or not os.path.exists(directory):
        return jsonify({"error": "Invalid directory path"}), 400

    results = fast_scan(directory, check_subfolders)

    return jsonify({
        "results": results["results"],
        "filename": results["filename"],
        "ioc_filename": ioc_filename
    })


# API route for online lookup
@app.route("/api_lookup", methods=["POST"])
def api_lookup():
    reload_env()
    data = request.json
    hash_value = data.get("hash")
    services = data.get("services", [])

    if not hash_value:
        return jsonify({"error": "No hash provided"}), 400

    # Check if the necessary API keys are set for the selected services
    missing_keys = []

    # Check for VirusTotal API key
    if "virustotal" in services and not os.getenv("VT_API_KEY"):
        missing_keys.append("VirusTotal")

    # Check for MalwareBazaar API key
    if "malwarebazaar" in services and not os.getenv("MB_AUTH_KEY"):
        missing_keys.append("MalwareBazaar")

    # If any API keys are missing, return an error message
    if missing_keys:
        missing_keys_str = ", ".join(missing_keys)
        return jsonify({"error": f"Missing API key(s) for: {missing_keys_str}"}), 400

    vt_results = None
    mb_results = None

    if "virustotal" in services:
        vt_results = query_virustotal(hash_value)
        if 'error' in vt_results:
            return jsonify({"error": "No VirusTotal data found. Check your API key."}), 400

    if "malwarebazaar" in services:
        mb_results = query_malwarebazaar(hash_value)
        if 'query_status' in mb_results and mb_results['query_status'] == 'wrong_auth_key':
            return jsonify({"error": "No MalwareBazaar data found. Check your API key."}), 400

    return jsonify({
        "virustotal": vt_results if vt_results else None,
        "malwarebazaar": mb_results if mb_results else None
    })


# Route to read API keys from .env file
@app.route("/api/get-keys", methods=["GET"])
def get_keys():
    reload_env()
    vt_api_key = os.getenv("VT_API_KEY", "")
    mb_auth_key = os.getenv("MB_AUTH_KEY", "")
    return jsonify({"vtApiKey": vt_api_key, "mbAuthKey": mb_auth_key})


# Route to save new API keys to the .env file
@app.route("/api/save-keys", methods=["POST"])
def save_keys():
    data = request.get_json()
    vt_api_key = data.get("vtApiKey")
    mb_auth_key = data.get("mbAuthKey")

    # Save API keys to the .env file
    set_key(".env", "VT_API_KEY", vt_api_key)
    set_key(".env", "MB_AUTH_KEY", mb_auth_key)

    reload_env()

    return jsonify({"message": "API keys saved successfully!"})


if __name__ == "__main__":
    app.run(debug=True, port=5555)