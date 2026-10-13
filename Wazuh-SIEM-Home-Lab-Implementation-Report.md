# Wazuh SIEM Home Lab (VirtualBox)

A hands-on SOC lab where I built a Wazuh SIEM server on Ubuntu Server 22.04 LTS, enrolled a Windows 11 endpoint as an agent, and reviewed the telemetry it produced in the Wazuh dashboard.

> **Status:** SIEM server installed and healthy, Windows 11 agent active and reporting. Attack simulation from Kali (Phase 4) is the next stage and will be added to this repo with results.

---

## 1. Objectives

- Deploy a working SIEM (Wazuh manager, indexer and dashboard) in an isolated lab.
- Onboard a Windows endpoint as a Wazuh agent and confirm events arrive.
- Review alerts and understand what each rule means before attacking anything.
- Next: generate attack activity from Kali and map the detections to MITRE ATT&CK.

## 2. Lab Environment

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox on a Windows 11 host (Dell laptop) |
| SIEM VM | `Wazuh-SIEM`: Ubuntu Server 22.04.5 LTS (amd64), **8 GB RAM, 3 vCPU**, 50 GB VDI, VMSVGA, 16 MB video |
| SIEM hostname / IP | `wazuh-server` / `10.0.2.6` |
| Network | VirtualBox **NAT Network `labnet`** (10.0.2.0/24) shared by all lab VMs |
| Endpoint (agent) | `win11-client`, Windows 11 Pro (build 10.0.26200.9457), `10.0.2.15`, Wazuh agent **v4.9.2** |
| Other lab VMs on the network | Kali Linux, Metasploitable2 (`10.0.2.4`) |
| Related lab | VMware lab with Windows Server 2025 DC (`homelab.local`), Windows 11 client, Kali, Splunk |

### Topology

```
                 labnet (10.0.2.0/24, VirtualBox NAT Network)

   +--------+      +--------------------+      +-----------------+
   |  Kali  |      | Windows 11 Pro     |      | Metasploitable2 |
   |        |      | win11-client       |      | 10.0.2.4        |
   +--------+      | 10.0.2.15 (agent)  |      +-----------------+
                   +---------+----------+
                             | events (agent v4.9.2)
                             v
                   +---------------------------+
                   | Wazuh SIEM  10.0.2.6      |
                   | manager + indexer +       |
                   | dashboard (Ubuntu 22.04)  |
                   +---------------------------+
```

## 3. Phase 1: Building the SIEM VM

### 3.1 VM settings

1. Created a VM named `Wazuh-SIEM`, type Linux / Ubuntu (64-bit).
2. **8192 MB RAM** and **3 processors**, a 50 GB VDI on a SATA (AHCI) controller.
3. Attached `ubuntu-22.04.5-live-server-amd64.iso` to the IDE optical drive.
4. Boot order for installation: Optical first, then Hard Disk. UEFI off (BIOS mode).
5. After installation, removed the ISO so the VM boots from the new system.
6. Moved the adapter to the NAT Network `labnet` so the SIEM and endpoints can talk to each other.

### 3.2 Ubuntu Server installation choices

| Screen | Choice |
|---|---|
| Language / keyboard | English / English (US) |
| Installer update | Continue without updating |
| Install type | Ubuntu Server (not minimized), no third-party drivers |
| Network | DHCP via NAT, confirmed an IP was assigned |
| Storage | Use an entire disk, LVM, no LUKS encryption (avoids a passphrase prompt on every lab boot) |
| SSH | Install OpenSSH server |
| Hostname | `wazuh-server` |

### 3.3 Storage note

The guided LVM layout only allocates about half of the volume group to `/` (about 24 GB of 48 GB). Wazuh's indexer grows with log volume, so extend the root volume and confirm:

```bash
sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
df -h /
```

## 4. Troubleshooting Log

Real problems I hit while building this, and what fixed them.

### Issue 1: Installer or installed system?
- **Symptom:** A wall of kernel messages (`vmwgfx`, `e1000`, `enp0s3: renamed from eth0`) and nothing else for a while.
- **Finding:** It was the boot log of the live installer, not an installed system. The `vmwgfx ... *ERROR* Failed to send host log message` line is a harmless VirtualBox graphics message.
- **Lesson:** Check the VM's Storage and Boot Order to know what it is actually booting.

### Issue 2: "Could not read from the boot medium"
- **Cause:** The first installation had not completed, so the virtual disk was empty.
- **Fix:** Re-attached the ISO, put Optical first and ran the installer again.

### Issue 3: Installer crashed (`apply_autoinstall_config`)
- **Likely cause:** I had switched the VM to a bridged Wi-Fi adapter during setup. Bridged mode on a Wi-Fi adapter often gives the guest no working connectivity, and the installer stalled on a network/package step.
- **Fix:** Set the adapter back to NAT, re-attached the ISO and re-ran the installer without changing VM settings while it ran. The second attempt completed.

### Issue 4: Wrong GRUB entry
- The GRUB menu defaulted to *Ubuntu Server with the HWE kernel*. I selected the standard **Try or Install Ubuntu Server** entry after the failed install.

## 5. Phase 2: Wazuh All-in-One Installation (Completed)

Installed with the official Wazuh installer script in all-in-one mode. The installer log shows each component finishing in order:

| Step | Result |
|---|---|
| Configuration files and certificates (root, admin, indexer, Filebeat, dashboard) | Generated |
| Wazuh indexer | Installed, started, cluster security initialized (about 6 minutes) |
| Wazuh manager | Installed, started, vulnerability detection configured |
| Filebeat | Installed and started |
| Wazuh dashboard | Installed, started, web application initialized |
| Final status | `Installation finished` |

The dashboard is reachable at `https://10.0.2.6` from the Windows 11 VM (self-signed certificate, so the browser shows "Not secure").

*Evidence: `screenshots/02-wazuh-install-finished.png` (credentials cropped out), `screenshots/01-dashboard-overview.png`*

## 6. Phase 3: Agent Onboarding (Completed)

Deployed the Wazuh agent on the Windows 11 VM using the dashboard's "Deploy new agent" wizard.

| Field | Value |
|---|---|
| Agent ID / name | 001 / `win11-client` |
| IP | 10.0.2.15 |
| OS | Microsoft Windows 11 Pro 10.0.26200.9457 |
| Version | v4.9.2 |
| Group | default |
| Status | **Active** (0 disconnected, 0 pending, 0 never connected) |

*Evidence: `screenshots/03-agent-active.png`, `screenshots/04-dashboard-agent-view.png`*

## 7. First Telemetry Review (Baseline)

Before attacking anything I reviewed what a freshly built lab already produces. In the 24-hour overview the dashboard showed:

| Severity | Rule levels | Alerts |
|---|---|---|
| Critical | 15+ | 0 |
| High | 12-14 | 0 |
| Medium | 7-11 | 8 |
| Low | 0-6 | 27 |

The Threat Hunting view listed **35 hits** over the last 24 hours, all from the Wazuh server itself (`wazuh-server`):

| Rule ID | Level | Description | Meaning |
|---|---|---|---|
| 502 | 3 | Wazuh server started | Service restart (VM resumed or rebooted) |
| 5501 / 5502 | 3 | PAM: login session opened / closed | Console and SSH logins |
| 5402 | 3 | Successful sudo to ROOT executed | Admin commands I ran during setup |
| 510 | 7 | Host-based anomaly detection event (rootcheck) | Rootcheck findings on a new host; the level-7 events appear to account for the medium-severity count |

**Analyst note:** This is the baseline. These alerts come from my own setup activity, so I will compare future attack alerts against it. The level-7 rootcheck events should be opened individually to confirm they are benign on a fresh Ubuntu install before I treat them as noise.

*Evidence: `screenshots/05-threat-hunting-events.png`*

## 8. Phase 4: Attack Simulation (Next)

Attacks run from Kali against lab machines only. Each test ends with a detection check and an ATT&CK mapping.

| # | Activity | Source | Expected telemetry | ATT&CK |
|---|---|---|---|---|
| 1 | Nmap scan of Metasploitable2 (captured earlier as `meta2-scan.txt`) | Kali | Packet capture in Wireshark | T1046 Network Service Discovery |
| 2 | Nmap against Windows 11, firewall on vs off (`win11-fw-on.txt`, `win11-fw-off.txt`) | Kali | Firewall / connection events on the agent | T1046 |
| 3 | Failed and successful logons | Windows 11 | Authentication events (4625 / 4624) | T1110 Brute Force |
| 4 | File integrity changes | Linux agent | Wazuh FIM alerts | T1565 Data Manipulation |

For each test: what I ran, which rule fired (ID and level), what a Tier 1 analyst would do next, and what the SIEM did not catch.

- [ ] Enroll a Linux agent
- [ ] Add Sysmon on Windows for richer process and network telemetry
- [ ] Run the tests above and record results

## 9. Skills Demonstrated

- Virtualization: VirtualBox VM design, NAT Network vs bridged vs NAT, boot order and storage troubleshooting
- Linux administration: Ubuntu Server install, LVM, service management
- SIEM operations: Wazuh all-in-one deployment, agent enrollment, alert review and baselining
- Detection and analysis: Nmap, Wireshark, MITRE ATT&CK mapping
- Documentation: reproducible steps and a troubleshooting log

## 10. Next Steps

- Forward Windows Event Logs and Sysmon data, then compare Wazuh and Splunk detections on the same events
- Write custom Wazuh rules and test them with Kali traffic
- Use TryHackMe SOC Level 1 scenarios for alert triage practice

## 11. Security Notes

- All credentials were generated for an isolated lab and are not published here.
- The lab uses private addresses on a VirtualBox NAT Network and is not exposed to the internet.
- All scans and attacks run inside a lab I own, against intentionally vulnerable machines. Do not run these tools against systems you do not have permission to test.

## Author

**Atogbo O. Anthony** | IT Support Specialist moving into cybersecurity (SOC / Security Analyst)
GitHub: [aanthony-sec](https://github.com/aanthony-sec) | LinkedIn: [atogbo-anthony](https://linkedin.com/in/atogbo-anthony-457116300)
