# LOGAC (Logic & Access Security Scanner)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Beta-orange)

LOGAC is an automated security testing framework for web applications focused on detecting **access control** and **business logic** vulnerabilities.

## ✨ Key Features

- **🕷️ Smart Web Crawler**: Crawls and maps entire web applications
- **🔐 User Role Mapping**: Detects and maps different user roles
- **🎯 Privilege Escalation Testing**: Detects IDOR and privilege escalation vulnerabilities
- **📊 Response Comparator**: Compares server responses across different user roles
- **📝 Report Generator**: Generates comprehensive comparative reports

## 🚀 Installation

1. Clone this repository:
```bash
git clone https://github.com/Andiansyah23/logac.git
cd logac
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Prepare wordlists:
```bash
mkdir data
# Add your wordlists to the data folder
```

## 📖 Usage

Run the tool with the command:

```bash
python main.py
```

The tool will prompt for:
- Target host (example: http://example.com)
- Login mode (manual or auto/brute force)

### Important File Structure

```
logac/
├── main.py              # Main entry point
├── crawler.py           # Crawler module
├── auth_tester.py       # Authentication testing module
├── data/
│   ├── wordlist.txt     # Wordlist for directory brute-forcing
│   ├── usernames.txt    # Username list for brute force
│   └── passwords.txt    # Password list for brute force
└── reports/             # Folder for storing reports
```

## 🎯 Example Usage

```bash
$ python main.py
Enter target host (e.g., http://example.com): http://testapp.com
[*] Brute forcing login directories...
[+] Login form found:
    URL: http://testapp.com/login
    Action: /login
    Method: POST
[?] Login mode: 1. Manual 2. Auto (brute): 2
[*] Trying admin:admin
[*] Trying admin:password
...
[+] Report saved to data/report_testapp_com.html
```

## 📊 Sample Report

LOGAC generates HTML reports containing:
- List of discovered directories
- Login attempt results
- Brute force status
- OTP testing results

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only. Please obtain written permission before testing any systems you don't own.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for full details.

## 🤝 Contributing

Contributions are always welcome! Please create issues or pull requests for:
- Bug reports
- Feature suggestions
- Documentation improvements

---

Built with ❤️ for the Indonesian cybersecurity community
