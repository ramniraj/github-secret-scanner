import requests
import re
import os
from getpass import getpass

# Add your GitHub Token here or prompt securely
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or getpass("Enter your GitHub Token: ")

# GitHub API headers
headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

# Regex patterns for secret detection
secret_patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Generic API Key": r"[a-zA-Z0-9]{32,45}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+",
    "Email/Password": r"[a-zA-Z0-9_.+-]+@{domain}:[^\s]+",
    "S3 URL": r"https?://s3\.amazonaws\.com/[^\s\"']+"
}

# Risk score weights
risk_weights = {
    "AWS Access Key": 10,
    "Slack Token": 7,
    "Google API Key": 6,
    "Generic API Key": 5,
    "JWT Token": 4,
    "Email/Password": 9,
    "S3 URL": 3
}

def get_repos(org_name):
    repos = []
    url = f"https://api.github.com/orgs/{org_name}/repos?per_page=10&type=public"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        for repo in response.json():
            repos.append(repo['full_name'])
    return repos

def get_files(repo_name):
    files = []
    url = f"https://api.github.com/repos/{repo_name}/git/trees/HEAD?recursive=1"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        tree = response.json().get("tree", [])
        for item in tree:
            if item["type"] == "blob" and any(item["path"].endswith(ext) for ext in ['.py', '.js', '.env', '.txt', '.json', '.yaml']):
                files.append(item["path"])
    return files

def scan_file(repo_name, file_path, domain):
    url = f"https://raw.githubusercontent.com/{repo_name}/HEAD/{file_path}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return []
        findings = []
        lines = response.text.splitlines()
        for idx, line in enumerate(lines, start=1):
            for secret_type, pattern in secret_patterns.items():
                pattern = pattern.replace("{domain}", domain)
                matches = re.findall(pattern, line)
                if matches:
                    findings.append({
                        "repo": repo_name,
                        "file": file_path,
                        "line": idx,
                        "type": secret_type,
                        "match": matches
                    })
        return findings
    except Exception as e:
        print(f"Error reading file: {file_path}")
        return []

def main():
    org_name = input("Enter the target GitHub organization name: ").strip()
    domain = input("Enter the target domain (e.g., example.com): ").strip()
    total_findings = []
    total_risk_score = 0

    print(f"\nScanning organization: {org_name}...\n")
    repos = get_repos(org_name)

    for repo in repos:
        files = get_files(repo)
        for file_path in files:
            findings = scan_file(repo, file_path, domain)
            total_findings.extend(findings)

    print("\n=== Secret Scan Results ===\n")
    if not total_findings:
        print("No secrets found.")
    else:
        for f in total_findings:
            risk_score = risk_weights.get(f['type'], 1) * len(f['match'])
            total_risk_score += risk_score
            print(f"Repo: {f['repo']}")
            print(f"File: {f['file']}")
            print(f"Line: {f['line']}")
            print(f"Type: {f['type']}")
            print(f"Matched: {f['match']}")
            print(f"Risk Score for this secret: {risk_score}")
            print("-" * 40)

        print(f"\nTotal Secrets Detected: {len(total_findings)}")
        print(f"Overall Risk Score: {total_risk_score}")

if __name__ == "__main__":
    main()
