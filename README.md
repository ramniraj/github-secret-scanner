# GitHub Secret Scanner 🔐

This Python script scans public GitHub repositories belonging to a specified organization to detect hardcoded secrets such as API keys, tokens, passwords, and sensitive URLs.

---

## 🚀 Features

- Scans public repositories from a given GitHub organization
- Detects secrets using customizable regular expressions:
  - AWS Access Keys
  - Slack Tokens
  - Google API Keys
  - Generic API Keys / Tokens
  - Email/Password pairs for a target domain
  - S3 Bucket URLs
- Displays:
  - Repo Name
  - File Path
  - Line Number
  - Matched Secret
  - Type of Secret
  - Risk Score

---

## 🔧 Requirements

- Python 3.x
- GitHub Personal Access Token (PAT)

---

## 🛠️ Usage

```bash
python3 github_secret_scanner.py
