# 🦖 Velociraptor Threat Hunting & Incident Response Lab

A hands-on cybersecurity homelab simulating real-world attack techniques on both **Linux and Windows** targets, and detecting them using **Velociraptor DFIR** with custom and built-in VQL artifacts.

---

## 📋 Table of Contents

- [Project Report](#-project-report)
- [Lab Environment](#-lab-environment)
- [Target 1 — Linux (robertserver)](#-target-1--linux-robertserver)
  - [Reverse Shell](#1-reverse-shell-netcat)
  - [Cron Job Persistence](#2-cron-job-persistence)
  - [Systemd Service Persistence](#3-systemd-service-persistence)
  - [Stealthy Systemd Persistence](#4-stealthy-systemd-persistence)
  - [Hidden Malicious Files](#5-hidden-malicious-files)
  - [SSH Brute Force](#6-ssh-brute-force)
  - [Custom Artifacts & Detections](#custom-artifacts--detections-linux)
- [Target 2 — Windows (DESKTOP-VEL359P)](#-target-2--windows-desktop-vel359p)
  - [Brute Force Attack](#1-brute-force-attack)
  - [Scheduled Task Persistence](#2-scheduled-task-persistence)
  - [Registry Run Key Persistence](#3-registry-run-key-persistence-hkcu--hklm)
  - [Suspicious File Drop](#4-suspicious-file-drop)
  - [PowerShell Script Block Logging](#5-powershell-script-block-logging)
- [Remediation Summary](#remediation-summary)
- [Folder Structure](#-folder-structure)
- [Tools Used](#-tools-used)

---

## 📄 Project Report

### Objective
The goal of this project was to build a realistic, isolated homelab environment to simulate common attacker techniques against both Linux and Windows endpoints, and then detect, investigate, and remediate those techniques using **Velociraptor** — an open-source DFIR and endpoint monitoring platform.

### Scope
The lab covers **11 attack scenarios** across two targets:
- **Linux (Ubuntu 24.04)** — robertserver
- **Windows (Windows 11 LTSC)** — DESKTOP-VEL359P

All attacks were carried out from a **Kali Linux** attacker machine, or simulated locally on the target machine itself.

### MITRE ATT&CK Mapping

| # | Technique | MITRE ID | Target |
|---|-----------|----------|--------|
| 1 | Command & Control — Reverse Shell via Netcat | T1059.004 | Linux |
| 2 | Persistence — Cron Job | T1053.003 | Linux |
| 3 | Persistence — Systemd Service | T1543.002 | Linux |
| 4 | Persistence — Masquerading (Stealthy Systemd) | T1036.004 | Linux |
| 5 | Defense Evasion — Hidden Files & Directories | T1564.001 | Linux |
| 6 | Credential Access — Brute Force SSH | T1110.001 | Linux |
| 7 | Credential Access — Brute Force (Windows Login) | T1110.001 | Windows |
| 8 | Persistence — Scheduled Task | T1053.005 | Windows |
| 9 | Persistence — Registry Run Keys (HKCU & HKLM) | T1547.001 | Windows |
| 10 | Execution — Malicious File Drop | T1105 | Windows |
| 11 | Execution — Encoded PowerShell Commands | T1059.001 | Windows |

### Key Findings

- **Custom VQL artifacts** were successfully authored to detect Linux-specific persistence techniques (cron, systemd) that are not covered by Velociraptor's default artifact library.
- Velociraptor's **`Generic.Client.VQL`** and **`Windows.System.TaskScheduler`** artifacts effectively identified Windows-based persistence mechanisms.
- **PowerShell Script Block Logging** (Event ID 4104) proved to be a powerful detection control, capturing and decoding obfuscated and encoded PowerShell commands in real time.
- The **stealthy systemd persistence** technique (using a legitimate-looking service name with suppressed output) was successfully flagged by the custom `Custom.Linux.Systemd.SuspiciousPersistence` artifact, demonstrating the value of behavior-based detection over name-based detection.
- Brute force attacks from Kali Linux were detected on **both targets** through log analysis and Velociraptor artifact collection.

### Conclusion
This lab demonstrates a practical, end-to-end threat detection workflow — from attack simulation through to artifact-based detection and remediation — using only open-source tools in a self-contained virtual environment. The project highlights both offensive and defensive skill sets relevant to SOC analyst, threat hunter, and incident responder roles.

---

## 🖥️ Lab Environment

The lab runs entirely in **Oracle VirtualBox** with three virtual machines:

| VM | Role | OS |
|----|------|----|
| `DESKTOP-VEL359P` | Velociraptor Server + Windows Target | Windows 11 LTSC |
| `robertserver` | Linux Target / Victim Machine | Ubuntu 24.04 |
| `robertnile@kali` | Attacker Machine | Kali Linux |

Both target machines are enrolled as Velociraptor clients, with the server monitoring all activity in real time.

![Both clients online](screenshots/setup/both_clients_online.png)

---

## 🐧 Target 1 — Linux (robertserver)

### 1. Reverse Shell (Netcat)

The attacker sets up a netcat listener on the target machine, then connects from Kali to establish a reverse shell on port **4444**.

**Target listens on port 4444:**

![NC process listening](screenshots/linux/reverse_shell/nc_process.png)

**Kali attacker connects:**

![Kali attack on 192.168.122.7](screenshots/linux/reverse_shell/kali_attack_on_192_168_122_7.png)

**Connection established on the target side:**

![Kali connected on server](screenshots/linux/reverse_shell/kali_connected_on_c.png)

**Full reverse shell gained — whoami, hostname, ip a:**

![Gained reverse shell](screenshots/linux/reverse_shell/Gained_reverse_shell_on_robertnile.png)

---

### 2. Cron Job Persistence

A malicious cron job is added to the target's crontab, writing `hacked` to `/tmp/persist.txt` every minute.

**Crontab editor with malicious entry:**

![Created a simple cron task](screenshots/linux/persistence/cron/created_a_simple_cron_task.png)

**Cron job running and confirmed:**

![Created a cron job](screenshots/linux/persistence/cron/created_a_cron_job.png)

---

### 3. Systemd Service Persistence

A fake malicious systemd service (`persist.service`) is created and enabled to run at boot.

```ini
[Unit]
Description=Persistence Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'echo hacked_systemd >> /tmp/systemd_persist.txt'

[Install]
WantedBy=multi-user.target
```

![Created a fake malicious service](screenshots/linux/persistence/systemd/Created_a_fake_malicious_service.png)

---

### 4. Stealthy Systemd Persistence

A more advanced technique using a legitimately-named service (`systemd-update-notifier.service`) to blend in with real system services. Runs as root with suppressed output.

```ini
[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do echo "hacked_systemd" >> /tmp/.systemd_persist.log 2>/dev/null; sleep 60; done'
Restart=always
StandardOutput=null
StandardError=null
Nice=19
IOSchedulingClass=idle
```

![Created stealthy systemd persistence](screenshots/linux/persistence/systemd/created_stealthy_systemd_persistence.png)

---

### 5. Hidden Malicious Files

Suspicious files are planted inside a hidden directory `/tmp/.hidden/` to simulate a dropped malware stage.

| File | Simulated Purpose |
|------|------------------|
| `backdoor.elf` | Binary backdoor |
| `creds.txt` | Stolen credentials |
| `payload.sh` | Malicious shell script |

![Created suspicious hidden files](screenshots/linux/file_hunt/Created_suspicous_hidden_files.png)

---

### 6. SSH Brute Force

The Kali attacker performs an SSH brute force attack against the target. Raw brute force logs are visible in `/var/log/auth.log`.

![SSH brute force logs](screenshots/linux/brute_force/ssh_bruteforce_logs.png)

---

### Custom Artifacts & Detections (Linux)

#### Artifacts Created

**`Custom.Linux.Systemd.Persistence`** — scans `/etc/systemd/system/*.service` and returns all service metadata including file hashes.

![Created artifact to detect systemd persistence](screenshots/linux/artifacts/created_artifact_to_detect_systemd_persistence.png)

**`Custom.Linux.Systemd.SuspiciousPersistence`** — filters for services with suspicious names, shell-based `ExecStart` commands, or recent modification timestamps. Excludes known-good services.

![Created artifact to detect suspicious systemd persistence](screenshots/linux/artifacts/created_artifact_to_detect_suspecious_systemd_persistence.png)

**`Custom.Linux.BruteForce.SSH`** — parses `/var/log/auth.log` and counts failed authentication attempts.

![Created SSH brute force artifact](screenshots/linux/artifacts/created_ssh_bruteforce_artifact.png)

**`Custom.Linux.BruteForce.SSHh`** — enhanced version grouping failed logins by source IP and target user.

![Created custom brute force artifact](screenshots/linux/artifacts/created_custom_bruteforce_artifact.png)

**`Custom.Linux.ReverseShell.Detection`** — queries running processes and network connections to find active `nc` listeners and reverse shell sessions.

![Created artifact to monitor nc](screenshots/linux/artifacts/created_a_custom_artifart_to_monitor_nc.png)

---

#### Detections

**✅ Reverse Shell Detected**

Netcat process caught by `Custom.Process.Monitor` — PID 3206, command `nc -lvnp 4444`:

![Collected suspicious nc activity](screenshots/linux/detections/collected_suspicious_nc_activity.png)

Active connection confirmed via `Linux.Network.NetstatEnriched` — ESTABLISHED on port 4444, call chain `systemd → sshd → bash → nc`:

![Kali connected to netcat enriched](screenshots/linux/detections/kali_connected_to_netcat__nc__1.png)

Confirmed again via `Linux.Network.Netstat/TCP4` — nc process PID 2228:

![Kali connected to netcat netstat](screenshots/linux/detections/kali_connected_to_netcat__nc__2.png)

Reverse shell `bash -i` caught by `Custom.Linux.ReverseShell.Detection`:

![Custom query for active reverse shell](screenshots/linux/detections/Created_a_custom_query_to_show_active_reverse_shell.png)

NetstatEnriched showing `bash -i` ESTABLISHED connection:

![Reverse shell connection proof](screenshots/linux/detections/reverse_shell_connection_proof.png)

---

**✅ Cron Persistence Detected**

`Linux.Sys.Crontab` reveals the malicious cron entry in `/var/spool/cron/crontabs/robertnile`:

![Detected Linux cron persistence](screenshots/linux/detections/Detected_Linux_cron_persistence.png)

---

**✅ Systemd Persistence Detected**

`Custom.Linux.Systemd.Persistence` finds `persist.service` with its full hash:

![Detected systemd persistence](screenshots/linux/detections/Detected_systemd_persistence.png)

![Detected systemd persistence 2](screenshots/linux/detections/Detected_systemd_persistence_2.png)

---

**✅ Stealthy Systemd Persistence Detected**

`Custom.Linux.Systemd.SuspiciousPersistence` flags `systemd-update-notifier.service` — matched suspicious patterns despite its legitimate-looking name:

![Detected suspicious systemd persistence](screenshots/linux/detections/detected_the_suspicious_systemd_persistence.png)

---

**✅ Hidden Files Detected**

`Custom.Linux.FileHunt` discovers all three planted files inside `/tmp/.hidden/`:

![Identified suspicious hidden files](screenshots/linux/detections/identified_suspicious_hidden_files.png)

---

**✅ SSH Brute Force Detected**

`Custom.Linux.BruteForce.SSHh` identifies **160 failed login attempts** from `192.168.122.3` against user `robertnile`:

![Brute force detection](screenshots/linux/detections/bruteforce_detection.png)

---

## 🪟 Target 2 — Windows (DESKTOP-VEL359P)

### 1. Brute Force Attack

A brute force attack is simulated using a PowerShell loop with `net use` and a wrong password, generating multiple **Event ID 4625** (failed logon) entries in the Windows Security log.

**Brute force initiated via PowerShell:**

![Brute force attack initiated](screenshots/windows/brute_force/bruteforce_attack_initaited_.png)

**Event Viewer showing Event ID 4625 failures:**

![Event Viewer showing failed login](screenshots/windows/brute_force/Event_Viewer_showing_failed_login.png)

**Velociraptor detects brute force from Kali (192.168.122.3) and local sources:**

![Brute force detected from Kali and others](screenshots/windows/brute_force/bruteforce_attack_detected_from_kali_and_others_.png)

---

### 2. Scheduled Task Persistence

A malicious scheduled task (`UpdaterService`) is created to run `powershell.exe -ExecutionPolicy Bypass` every 5 minutes.

**Task created and verified:**

![Created a scheduled task persistence](screenshots/windows/persistence/scheduled_task/created_a_sheduled_task_persistance.png)

**Velociraptor `Windows.System.TaskScheduler` detects `\UpdaterService`:**

![Detected the scheduled task persistence](screenshots/windows/persistence/scheduled_task/Detected_the_scheduled_task_persistance.png)

**Remediation — task successfully deleted:**

![Remediation of scheduled task persistence](screenshots/windows/persistence/scheduled_task/remediation_of_schedule_task_persistance.png)

---

### 3. Registry Run Key Persistence (HKCU & HKLM)

Malicious entries are added to both the **current user** (`HKCU`) and **local machine** (`HKLM`) registry Run keys to execute a hidden PowerShell payload on every login.

**HKCU Run key created — `WindowsHealthMonitor`:**

![Created HKCU registry run key](screenshots/windows/persistence/registry/created_HKCU_registry_run_key.png)

**HKLM Run key created — `SystemHealthMonitor`:**

![Created HKLM registry run key](screenshots/windows/persistence/registry/created_HKLM_registry_run_key.png)

**Registry Editor confirming HKCU entry:**

![Evidence of HKCU registry run key executed](screenshots/windows/persistence/registry/Evidence_of_HKCU_registry_run_key_was_executed.png)

**Registry Editor confirming HKLM entry:**

![Evidence of HKLM registry run key executed](screenshots/windows/persistence/registry/Evidence_of_HKLM_registry_run_key_executed.png)

**Persistence confirmed after reboot — persist.txt contains repeated `hacked_runkey` entries:**

![Registry run key persists after reboot](screenshots/windows/persistence/registry/registry_run_key_persist_after_system_reboot.png)

**Velociraptor detects both HKCU and HKLM malicious run keys:**

![Registry run key detected](screenshots/windows/persistence/registry/registry_run_key_detected.png)

---

### 4. Suspicious File Drop

Malicious files are planted in `C:\Temp\malware\` to simulate a dropped payload stage.

| File | Simulated Purpose |
|------|------------------|
| `payload.ps1` | Malicious PowerShell script |
| `passwords.txt` | Stolen credentials |

**Files created via PowerShell:**

![Created a suspicious file](screenshots/windows/file_hunt/created_a_suspicious_file.png)

**Velociraptor `Windows.Search.FileFinder` detects both files with MD5/SHA1/SHA256 hashes:**

![Detected the suspicious file](screenshots/windows/file_hunt/Detected_the_suspicious_file.png)

---

### 5. PowerShell Script Block Logging

**Script Block Logging** is enabled to capture all executed PowerShell commands including obfuscated and encoded payloads.

**Enabling Script Block Logging:**

![Enabled script block logging](screenshots/windows/powershell/enabled_script_block_logging.png)

**Velociraptor captures Event ID 4104 logs including encoded commands and `IEX` download cradles:**

![Script blocking captures and decodes encoded commands](screenshots/windows/powershell/script_blocking_captures_and_decodes_encoded_commands.png)

**Full decoded script block log collected — 9 events captured:**

![Remediation confirmed](screenshots/windows/powershell/remediation_confirmed.png)

---

##  Remediation Summary

### Linux Remediations

| Attack | Remediation |
|--------|-------------|
| **Reverse Shell** | Kill the `nc` process (`kill <PID>`). Block outbound connections on unused ports using `ufw`. Restrict `nc` usage with AppArmor or remove it entirely. |
| **Cron Persistence** | Remove the malicious cron entry with `crontab -e`. Audit all user crontabs regularly using `Linux.Sys.Crontab`. Restrict cron access via `/etc/cron.allow`. |
| **Systemd Persistence** | Disable and remove the service: `sudo systemctl disable persist.service && sudo rm /etc/systemd/system/persist.service && sudo systemctl daemon-reload`. Audit all service files regularly. |
| **Stealthy Systemd Persistence** | Same as above — identify via behavior-based detection (shell loops, suppressed output, root user). Remove the service file and reload the daemon. |
| **Hidden Malicious Files** | Delete the hidden directory: `sudo rm -rf /tmp/.hidden`. Regularly hunt for hidden files in `/tmp` and home directories using `Custom.Linux.FileHunt`. |
| **SSH Brute Force** | Install and configure `fail2ban` to auto-ban IPs after repeated failures. Disable password-based SSH login and enforce key-based authentication only (`PasswordAuthentication no` in `sshd_config`). |

---

### Windows Remediations

| Attack | Remediation |
|--------|-------------|
| **Brute Force** | Enable account lockout policy (lock after 5 failed attempts). Use Windows Firewall to restrict SMB/RDP access. Monitor Event ID 4625 continuously via Velociraptor or SIEM. |
| **Scheduled Task Persistence** | Delete the task: `schtasks /delete /tn "UpdaterService" /f`. Audit all scheduled tasks using `Windows.System.TaskScheduler`. Restrict task creation to administrators only via Group Policy. |
| **Registry Run Key (HKCU)** | Delete the key: `Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsHealthMonitor"`. Audit Run keys regularly using Velociraptor `Generic.Client.VQL`. |
| **Registry Run Key (HKLM)** | Delete the key: `Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SystemHealthMonitor"`. Restrict HKLM write access to SYSTEM/Administrators only. |
| **Suspicious File Drop** | Delete `C:\Temp\malware\`. Enable Windows Defender real-time protection. Hunt for suspicious files periodically using `Windows.Search.FileFinder` with hash verification. |
| **Encoded PowerShell** | Keep Script Block Logging enabled (Event ID 4104). Enforce PowerShell Constrained Language Mode via Group Policy. Block execution of unsigned scripts with an execution policy of `AllSigned`. |

---

## 📁 Folder Structure

```
velociraptor-lab/
│
├── README.md
│
└── screenshots/
    ├── setup/
    │   └── both_clients_online.png
    │
    ├── linux/
    │   ├── reverse_shell/
    │   │   ├── nc_process.png
    │   │   ├── kali_attack_on_192_168_122_7.png
    │   │   ├── kali_connected_on_c.png
    │   │   └── Gained_reverse_shell_on_robertnile.png
    │   ├── persistence/
    │   │   ├── cron/
    │   │   │   ├── created_a_simple_cron_task.png
    │   │   │   └── created_a_cron_job.png
    │   │   └── systemd/
    │   │       ├── Created_a_fake_malicious_service.png
    │   │       └── created_stealthy_systemd_persistence.png
    │   ├── file_hunt/
    │   │   └── Created_suspicous_hidden_files.png
    │   ├── brute_force/
    │   │   └── ssh_bruteforce_logs.png
    │   ├── artifacts/
    │   │   ├── created_artifact_to_detect_systemd_persistence.png
    │   │   ├── created_artifact_to_detect_suspecious_systemd_persistence.png
    │   │   ├── created_ssh_bruteforce_artifact.png
    │   │   ├── created_custom_bruteforce_artifact.png
    │   │   └── created_a_custom_artifart_to_monitor_nc.png
    │   └── detections/
    │       ├── Detected_Linux_cron_persistence.png
    │       ├── Detected_systemd_persistence.png
    │       ├── Detected_systemd_persistence_2.png
    │       ├── detected_the_suspicious_systemd_persistence.png
    │       ├── identified_suspicious_hidden_files.png
    │       ├── bruteforce_detection.png
    │       ├── collected_suspicious_nc_activity.png
    │       ├── Created_a_custom_query_to_show_active_reverse_shell.png
    │       ├── kali_connected_to_netcat__nc__1.png
    │       ├── kali_connected_to_netcat__nc__2.png
    │       └── reverse_shell_connection_proof.png
    │
    └── windows/
        ├── brute_force/
        │   ├── bruteforce_attack_initaited_.png
        │   ├── Event_Viewer_showing_failed_login.png
        │   └── bruteforce_attack_detected_from_kali_and_others_.png
        ├── persistence/
        │   ├── scheduled_task/
        │   │   ├── created_a_sheduled_task_persistance.png
        │   │   ├── Detected_the_scheduled_task_persistance.png
        │   │   └── remediation_of_schedule_task_persistance.png
        │   └── registry/
        │       ├── created_HKCU_registry_run_key.png
        │       ├── created_HKLM_registry_run_key.png
        │       ├── Evidence_of_HKCU_registry_run_key_was_executed.png
        │       ├── Evidence_of_HKLM_registry_run_key_executed.png
        │       ├── registry_run_key_persist_after_system_reboot.png
        │       └── registry_run_key_detected.png
        ├── file_hunt/
        │   ├── created_a_suspicious_file.png
        │   └── Detected_the_suspicious_file.png
        └── powershell/
            ├── enabled_script_block_logging.png
            ├── script_blocking_captures_and_decodes_encoded_commands.png
            └── remediation_confirmed.png
```

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| [Velociraptor](https://docs.velociraptor.app/) | DFIR platform & endpoint visibility |
| VQL (Velociraptor Query Language) | Custom artifact authoring |
| Netcat (`nc`) | Reverse shell simulation (Linux) |
| PowerShell | Attack simulation & persistence (Windows) |
| Kali Linux | Attack platform |
| Oracle VirtualBox | Homelab virtualization |

---

> **Disclaimer:** This lab is built entirely in an isolated VirtualBox environment for educational purposes only. All attack techniques demonstrated are simulated against machines I own.
