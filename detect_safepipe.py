import re
import os

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|key|pwd|password)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\/+=]{40}['\"]?",
    "Generic API Key": r"(?i)(api_key|apikey|secret|token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-]{16,45}['\"]?",
    "Slack Token": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}"
}

def scan_file(file_path):
    """Scan a file for potential secrets."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for secret_name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings.append((secret_name, matches))
    except Exception as e:
        print(f"[!] Could not read file {file_path}: {e}")
    return findings

def scan_directory(directory_path):
    """Recursively scan all files in a directory."""
    results = {}
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            findings = scan_file(file_path)
            if findings:
                results[file_path] = findings
    return results

if __name__ == "__main__":
    target_path = input("Enter file or directory path to scan: ").strip()

    if os.path.isfile(target_path):
        findings = scan_file(target_path)
        if findings:
            print("\n[!] Secrets found:")
            for secret_type, matches in findings:
                print(f" - {secret_type}: {matches}")
        else:
            print("\n[+] No secrets found.")
    elif os.path.isdir(target_path):
        results = scan_directory(target_path)
        if results:
            print("\n[!] Secrets found:")
            for file_path, matches in results.items():
                print(f"\nFile: {file_path}")
                for secret_type, found in matches:
                    print(f" - {secret_type}: {found}")
        else:
            print("\n[+] No secrets found.")
    else:
        print("[!] Invalid path.")
