# linux-soc-log-reference-
A concept map of 51 Linux # Linux Security Log Reference

A concept map of every log source a SOC or purple team analyst touches during investigation — what it is, where it lives, and why it matters.

**51 log sources · 9 categories · Debian + RHEL family**

---

## Table of Contents

- [Core System & Auth](#core-system--auth)
- [Security & Audit](#security--audit)
- [Network & Services](#network--services)
- [Application & Web](#application--web)
- [Packages, Boot & Jobs](#packages-boot--jobs)
- [Containers & Virtualization](#containers--virtualization)
- [Niche & Distro-Specific](#niche--distro-specific)
- [Forensic Artifacts (Not Logs, but IR-Critical)](#forensic-artifacts-not-logs-but-ir-critical)

---

## Core System & Auth

| # | Log Source | Location | Description | Analyst Angle |
|---|-----------|----------|--------------|----------------|
| 01 | Auth log | Debian/Ubuntu system logs | SSH logins, sudo usage, PAM authentication success/failure, user account changes | Watch for SSH brute force patterns, sudo privilege abuse, unexpected new user creation |
| 02 | Secure log | RHEL/CentOS/Fedora system logs | RPM-family equivalent of the auth log — SSH, sudo, and PAM events | Check this instead of the auth log on RHEL-based systems |
| 03 | Syslog | Debian/Ubuntu system logs | General system and daemon activity — the catch-all for non-kernel messages | Good first stop for service failures and daemon crashes before narrowing down |
| 04 | Messages log | RHEL family system logs | General system messages, equivalent to syslog on RPM-based systems | First place to check for general anomalies on RHEL/CentOS |
| 05 | systemd journal | systemd-journald binary log | Unified log for kernel, services, and boot — supplements or replaces flat log files on modern distros | The single source of truth on systemd systems — can be filtered per service or kernel-only |
| 06 | Kernel log | System kernel log | Kernel-level events — driver loads, hardware activity, USB, kernel panics, module load/unload | Malicious kernel module loading is a classic rootkit indicator, alongside unexpected USB or hardware tampering |
| 07 | Boot log | System boot log | Service start and stop sequence recorded during system boot | Unexpected reboots or services failing to start can indicate persistence tampering |
| 08 | Login / session history | Login history records | Successful logins/logouts, failed logins, and per-user last login tracking | Core artifacts for reconstructing a brute-force timeline or spotting logins from unusual times or sources |
| 09 | Cron log | RHEL cron log / within syslog on Debian | Scheduled job execution history | Cron-based persistence is a well-known technique — look for unexpected new entries or jobs running as root |
| 10 | Mail log | Mail transfer agent log | Mail transfer agent activity (Postfix, Sendmail) | Can reveal spam relay abuse or phishing infrastructure on a compromised host |

## Security & Audit

| # | Log Source | Location | Description | Analyst Angle |
|---|-----------|----------|--------------|----------------|
| 11 | Auditd log | Audit subsystem log | Detailed syscall-level auditing — file access, execution, privilege use — once rules are configured | The closest Linux equivalent to Sysmon; essential for tracking privilege escalation and file integrity |
| 12 | Audit rule status | Auditd rule engine (live state) | Shows exactly what is currently being audited on the system | Confirm sensitive paths like the shadow file and sudoers file actually have watch rules — otherwise auditd is blind |
| 13 | Sudo log | Embedded in auth/secure log | Every sudo command executed, by whom, and the result | Key source for spotting privilege escalation abuse and unauthorized sudo attempts |
| 14 | SELinux audit log | Audit subsystem log (AVC denials) | Policy violation events on RHEL/Fedora systems running SELinux | A denial is often a strong signal of an exploitation attempt or misconfigured malware |
| 15 | AppArmor log | Syslog or kernel log | Policy denial events on Debian/Ubuntu systems running AppArmor | Serves the same purpose as SELinux AVC — a process attempting something its profile forbids |
| 16 | Fail2ban log | Fail2ban log file | IP ban and unban events from the brute-force protection jail | Confirms active brute-force activity and correlates well against the auth log |
| 17 | Process accounting log | Process accounting log | Records every command executed system-wide, along with user and resource usage | Useful for reconstructing exactly what ran on a compromised box, even after shell history is cleared |
| 18 | Shell history | Per-user shell history files | Command history for interactive shell sessions | Often the first thing attackers clear — its absence, when expected, is itself an indicator of compromise |

## Network & Services

| # | Log Source | Location | Description | Analyst Angle |
|---|-----------|----------|--------------|----------------|
| 19 | SSH daemon log | Embedded in auth/secure log | Connection details, authentication method, key fingerprints, and disconnect reasons | Watch for root login attempts, key-based auth abuse, and unusual source geolocations |
| 20 | Firewall log (iptables) | Kernel log via logging rule | Packets matching an explicit logging rule | Requires a logging rule configured up front; confirms blocked or allowed traffic per rule |
| 21 | UFW firewall log | Ubuntu UFW log | Allow/block decisions from the Uncomplicated Firewall | A simple audit trail for blocked inbound scan or connection attempts |
| 22 | Firewalld log | systemd journal (firewalld service, RHEL/CentOS) | Zone changes and rich rule matches | Watch for rule or zone tampering, such as an attacker opening a port for a reverse shell |
| 23 | Network Manager log | systemd journal (NetworkManager service) | Interface up/down events, new connection profiles, Wi-Fi association | Rogue interfaces or unexpected Wi-Fi association can indicate a rogue access point or exfiltration channel |
| 24 | DHCP client log | systemd journal (DHCP client service) | IP lease requests and renewals | Useful for spotting rogue DHCP servers or unexpected lease changes |
| 25 | DNS server log | BIND server log | Query log, zone transfers, resolution errors | Can reveal DNS tunneling, zone transfer abuse, or DGA-style lookups from internal hosts |
| 26 | NTP / Chrony log | systemd journal (chronyd service) | Time synchronization events | Time desync attacks can break Kerberos auth and confuse timelines during incident response |
| 27 | VPN log | OpenVPN log or WireGuard service unit | Tunnel establishment and client certificate authentication | Look for unauthorized connections, certificate abuse, or unexpected client IPs |
| 28 | Samba (SMB) log | Samba daemon log | SMB share access and authentication events | Relevant to SMB-based lateral movement and unauthorized share access |

## Application & Web

| # | Log Source | Location | Description | Analyst Angle |
|---|-----------|----------|--------------|----------------|
| 29 | Apache access log | Apache access log | Every HTTP request — source IP, URL, status code, user-agent | Reveals web shell uploads, injection attempts in URL parameters, and directory brute-forcing |
| 30 | Apache error log | Apache error log | Server-side errors, PHP errors, module failures | Exploitation attempts often surface as application errors here first |
| 31 | Nginx access/error log | Nginx log directory | Same purpose as Apache logs, for Nginx-served applications | Watch for web shell activity, injection attempts, and abnormal request spikes indicating denial of service |
| 32 | MySQL / MariaDB log | MySQL error log | Connection errors, slow queries, and general query activity if enabled | Can surface SQL injection attempts and unauthorized database connection attempts |
| 33 | PostgreSQL log | PostgreSQL log directory | Connection, query, and error logging | Useful for spotting failed authentication attempts and abnormal query patterns |
| 34 | PHP-FPM / PHP error log | PHP-FPM log | PHP runtime errors and warnings | Web shell execution often triggers fatal PHP errors that show up here |
| 35 | FTP log | vsftpd log | FTP login, upload, and download activity | Watch for anonymous FTP abuse and credential brute-forcing |

## Packages, Boot & Jobs

| # | Log Source | Location | Description | Analyst Angle |
|---|-----------|----------|--------------|----------------|
| 36 | dpkg log | Debian/Ubuntu package log | Package install, remove, and upgrade history | Unauthorized package installs can indicate backdoor tooling or supply-chain tampering |
| 37 | APT history log | APT history log | Full package install/upgrade command history | Good for building an incident timeline of exactly which tools were staged |
| 38 | YUM / DNF log | RHEL/Fedora package log | Package transaction history | Serves the same purpose as the dpkg log for RPM-based systems |
| 39 | Systemd boot log | systemd journal (current/previous boot) | Full log of the current or previous boot sequence | Security tooling like auditd or fail2ban failing to start at boot is a red flag for tampering |
| 40 | Systemd unit status | Live systemd state | Which services are currently active, failed, or masked | An attacker disabling security services often shows up as a failed or inactive unit here |
| 41 | At / batch job log | atd entries within syslog | One-time scheduled job execution | Less common than cron, but still used for one-shot persistence or delayed payload execution |

## Containers & Virtualization

| # | Log Source | Location | Description | Analyst Angle |
|---|-----------|----------|--------------|----------------|
| 42 | Docker daemon log | systemd journal (docker service) | Container create/start/stop events and image pull activity | Watch for unauthorized container spin-up, especially privileged containers that risk breakout |
| 43 | Docker container log | Per-container stdout/stderr | Standard output and error of the container's main process | Can surface app-level compromise, crypto-miner processes, or reverse shell output |
| 44 | Kubernetes audit log | Kubernetes audit log | API server request auditing — who did what, to which resource | Key for spotting unauthorized exec calls or RBAC privilege escalation |
| 45 | Libvirt / KVM log | Libvirt QEMU log directory | VM start, stop, and configuration change events | Watch for unauthorized VM creation or resource abuse such as cryptomining VMs |

## Niche & Distro-Specific

| # | Log Source | Location | Description | Analyst Angle |
|---|-----------|----------|--------------|----------------|
| 46 | Xorg / display log | Xorg log | GUI and display server startup and error events | Rarely security-relevant, but useful in physical-access investigations |
| 47 | Snap package log | systemd journal (snapd service, Ubuntu) | Snap package install and refresh events | Sandboxed, but still a software supply-chain vector worth tracking |
| 48 | Flatpak log | Flatpak events within the systemd journal | Flatpak application install and run events | Similar risk profile to Snap — worth tracking in hardened environments |
| 49 | Cloud-init log | Cloud-init log | First-boot provisioning script execution on cloud instances | A real cloud attack vector — malicious user-data or metadata injection at instance launch |
| 50 | Rsyslog / syslog-ng config | Rsyslog configuration file | Not a log itself — defines where logs get forwarded, e.g. to a SIEM | An attacker disabling log forwarding blinds the SIEM; always confirm forwarding is active |
| 51 | Core dump log | Application crash dump log | Application crash dumps | A crash from a buffer overflow or memory corruption attempt can leave shellcode evidence in the dump |

## Forensic Artifacts (Not Logs, but IR-Critical)

- Account and privilege baseline files (passwd, shadow, group)
- Privilege escalation paths (sudoers configuration)
- SSH key-based persistence backdoors (authorized keys files)
- Full cron persistence surface (crontab, cron.d, cron spool)
- Common malware staging directories (temp directories)
- Recently modified files — quick triage sweep for the last 24 hours
- Listening ports/processes — live sockets tied to webshell or backdoor listeners
- Running process tree — for identifying injected or hidden processes
- Binary hashing — for IOC matching against known-bad hashes

---

*Reference compiled for SOC / DFIR / blue team workflows. Verify exact paths against your target distro.* log sources for SOC and DFIR analysts
