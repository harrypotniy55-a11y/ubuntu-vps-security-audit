# 🛡️ Ubuntu VPS Security Audit

**A lightweight, non-invasive security audit script for Ubuntu VPS.**

Run a basic security audit directly from GitHub without cloning the repository or installing additional software.

The script reviews system users, SSH access, network connections, services, scheduled tasks, Docker, package integrity and selected temporary directories.

> This tool provides a preliminary security review. It is not a malware scanner, intrusion detection system, or guarantee that a server has not been compromised.

## ✨ Features

The audit includes 18 sections:

| # | Check | Description |
|---|---|---|
| 1 | Users and privileges | UID 0 accounts and sudo group |
| 2 | SSH configuration | SSH port and authentication settings |
| 3 | SSH keys | authorized_keys files and public key fingerprints |
| 4 | Successful SSH logins | Login history and interactive IP confirmation |
| 5 | Failed SSH logins | Failed authentication attempts |
| 6 | Fail2ban | Service and SSH jail status |
| 7 | Network ports | Listening ports and established connections |
| 8 | Processes | Running processes sorted by CPU usage |
| 9 | Systemd services | Failed and enabled services |
| 10 | Systemd timers | Scheduled systemd tasks |
| 11 | Cron | System and root scheduled tasks |
| 12 | Recently modified files | Selected sensitive system directories |
| 13 | Docker | Containers and images |
| 14 | Package integrity | `dpkg -V` verification |
| 15 | Kernel modules | Loaded kernel modules |
| 16 | System errors | Recent system journal errors |
| 17 | Temporary directories | Executable files in `/tmp`, `/var/tmp` and `/dev/shm` |
| 18 | Final summary | Warnings and audit limitations |

## 🚀 Quick Start

No installation or repository cloning required.

Run the following command as `root` on your Ubuntu VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/harrypotniy55-a11y/ubuntu-vps-security-audit/main/server-audit.sh)
```

If you are logged in as a regular user, switch to root first:

```bash
sudo -i
```

Then run the command above.

## 📋 Audit Results

The script uses three result categories:

- `[WARNING]` — an event or item requires manual review.
- `[AUDIT LIMITATION]` — some information was unavailable or a check could not be completed.
- `[INFO]` — informational output that does not automatically indicate a security issue.

The final summary displays one of these outcomes:

- **WARNINGS DETECTED** — review the reported findings.
- **AUDIT INCOMPLETE** — some checks had data or execution limitations.
- **NO WARNINGS DETECTED** — the automated checks did not flag any findings.

An unfamiliar IP address is not automatically evidence of a compromise. The script asks the user to confirm successful SSH login addresses.

## 📄 Audit Report

The report is saved to:

```text
/root/audit-report.txt
```

View it with:

```bash
less /root/audit-report.txt
```

## 🔒 Non-invasive Operation

The script does not modify:

- SSH configuration;
- firewall rules;
- Fail2ban settings;
- systemd services;
- Docker containers;
- network configuration;
- installed system packages.

It creates a local report and a temporary file, which is removed when the script exits.

## ⚠️ Limitations

This is a preliminary audit tool, not a complete incident response or forensic solution.

It does not guarantee detection of:

- rootkits or hidden malware;
- every type of server compromise;
- malicious code inside legitimate processes;
- changes not recorded in the available logs;
- issues requiring external network scanning.

Modified package files, unfamiliar IP addresses, executable files in temporary directories and failed services require manual review. They do not necessarily indicate a compromise.

## 🖥️ Requirements

- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS
- Bash
- Root privileges
- `curl` for direct execution from GitHub

Most commands used by the script are included with a standard Ubuntu installation. Missing tools are reported as audit limitations where applicable.

## 📦 Local Execution

If the script is already on your server:

```bash
chmod +x server-audit.sh
sudo ./server-audit.sh
```

## 🌐 Documentation

- [Русская документация](README_RU.md)

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 👤 Author

**harrypotniy55-a11y**

GitHub: https://github.com/harrypotniy55-a11y

---

If you find this project useful, consider giving it a ⭐.
