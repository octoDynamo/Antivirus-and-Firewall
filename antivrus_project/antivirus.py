import os
import hashlib
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

# Logging setup
logging.basicConfig(
    filename="antivirus.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Load malware signatures
def load_signatures():
    """Load malware signatures from a file."""
    try:
        with open("signatures.txt", "r") as f:
            return set(f.read().splitlines())  # Use a set for faster lookups
    except FileNotFoundError:
        logging.error("signatures.txt not found!")
        return set()

# Calculate MD5 hash of a file
def calculate_hash(file_path):
    """Calculate the MD5 hash of a given file."""
    hasher = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None

# Heuristic Analysis
def heuristic_analysis(file_path):
    """
    Perform heuristic analysis to identify suspicious files based on rules.
    Scans for:
    - Suspicious keywords in file name
    - Dangerous extensions
    - Abnormal file sizes
    - Embedded malicious patterns in content
    """
    suspicious_keywords = ["hack", "trojan", "virus", "malware", "keylogger"]
    dangerous_extensions = [".exe", ".bat", ".vbs", ".scr", ".dll", ".ps1"]
    suspicious_patterns = [b"eval(", b"exec(", b"cmd.exe", b"powershell", b"import os"]
    suspicious = False
    reasons = []

    # Check file name for suspicious keywords
    file_name = os.path.basename(file_path).lower()
    if any(keyword in file_name for keyword in suspicious_keywords):
        suspicious = True
        reasons.append("Suspicious keyword in file name")

    # Check file extension for dangerous types
    _, file_extension = os.path.splitext(file_name)
    if file_extension in dangerous_extensions:
        suspicious = True
        reasons.append("Dangerous file extension")

    # Check file size for anomalies
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            suspicious = True
            reasons.append("File size is zero (empty file)")
        elif file_size > 50 * 1024 * 1024:  # Example: Flag files larger than 50MB
            suspicious = True
            reasons.append("File size is unusually large")
    except Exception as e:
        logging.error(f"Error analyzing file size for {file_path}: {e}")

    # Scan file content for malicious patterns
    try:
        with open(file_path, "rb") as f:
            content = f.read(4096)  # Read the first 4KB for patterns
            if any(pattern in content for pattern in suspicious_patterns):
                suspicious = True
                reasons.append("Malicious content pattern detected")
    except Exception as e:
        logging.error(f"Error analyzing content of {file_path}: {e}")

    return suspicious, reasons

# Scan a single file
def scan_file(file_path, signatures):
    """Scan a single file using both signature and heuristic analysis."""
    results = {"file": file_path, "malware": False, "suspicious": False, "reasons": []}

    # Check for signature-based malware
    file_hash = calculate_hash(file_path)
    if file_hash and file_hash in signatures:
        results["malware"] = True
        logging.info(f"Malware detected (signature match): {file_path}")
        return results

    # Perform heuristic analysis
    suspicious, reasons = heuristic_analysis(file_path)
    if suspicious:
        results["suspicious"] = True
        results["reasons"] = reasons
        logging.info(f"Suspicious file detected: {file_path} - Reasons: {', '.join(reasons)}")
    return results

# Quarantine detected files
def quarantine_files(files):
    """Move detected malware files to a quarantine folder."""
    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    for file in files:
        try:
            shutil.move(file, quarantine_dir)
            logging.info(f"Quarantined: {file}")
        except Exception as e:
            logging.error(f"Failed to quarantine {file}: {e}")

# Scan all files in a directory
def scan_files(directory, signatures):
    """Scan all files in a directory using multithreading."""
    malware_found = []
    suspicious_files = []

    def worker(file_path):
        result = scan_file(file_path, signatures)
        if result["malware"]:
            malware_found.append(file_path)
        elif result["suspicious"]:
            suspicious_files.append({"file": file_path, "reasons": result["reasons"]})

    with ThreadPoolExecutor() as executor:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                executor.submit(worker, file_path)

    return malware_found, suspicious_files

# Main Program
def main():
    directory_to_scan = "./test_files"  # Directory containing files to scan
    print("Starting antivirus scan...")
    logging.info("Antivirus scan started")

    signatures = load_signatures()
    if not signatures:
        print("No malware signatures loaded. Proceeding with heuristic analysis only.")
        logging.warning("No malware signatures loaded.")

    malware_found, suspicious_files = scan_files(directory_to_scan, signatures)

    # Process malware
    if malware_found:
        print("\nMalware detected in the following files:")
        for file in malware_found:
            print(file)
        quarantine_files(malware_found)
    else:
        print("\nNo malware detected.")

    # Process suspicious files
    if suspicious_files:
        print("\nSuspicious files detected (heuristic analysis):")
        for entry in suspicious_files:
            print(f"{entry['file']} - Reasons: {', '.join(entry['reasons'])}")
    else:
        print("\nNo suspicious files detected.")

    logging.info("Antivirus scan completed")

if __name__ == "__main__":
    main()
