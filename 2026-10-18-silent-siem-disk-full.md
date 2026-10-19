[Back to the main report](../README.md)

# Wazuh SIEM Home Lab: Troubleshooting a Silent SIEM (Disk-Full Incident)

**Date:** 18 October 2026
**Author:** Atogbo O. Anthony ([@aanthony-sec](https://github.com/aanthony-sec))
**Environment:** VirtualBox, NAT Network `labnet` (10.0.2.0/24)

## Summary

My Wazuh dashboard showed an **Active** Windows agent but **zero alerts in 24 hours**. A healthy SIEM with a connected endpoint should never be that quiet, so I treated it as an incident and traced it from the dashboard back to the root cause: **the Wazuh server's disk was 100% full**, caused by leftover temporary files from the vulnerability-detection feed updater. After clearing the space and restarting services, alerts flowed again and the dashboard showed real detections for my test activity.

This write-up documents the method, the evidence at each step, and the fix.

## Lab architecture

![Lab architecture](../screenshots/2026-10-18-disk-full/01-lab-architecture.png)

| Host | Role | Address |
|---|---|---|
| wazuh-server | Wazuh all-in-one (manager, indexer, Filebeat, dashboard) on Ubuntu Server 22.04 | 10.0.2.6 |
| win11-client | Windows 11 endpoint with Wazuh agent v4.9.2 | 10.0.2.15 |
| Kali Linux | Attacker machine (attack simulation is the next phase) | labnet |
| Metasploitable2 | Intentionally vulnerable scan target | 10.0.2.4 |

## Troubleshooting timeline

### 1. Symptom: Active agent, no alerts
- Dashboard: 1 agent Active, **0 alerts** across all severities in the last 24 hours.
- Threat Hunting → Events returned "No results".

![Dashboard with an active agent and zero alerts](../screenshots/2026-10-18-disk-full/02-symptom-zero-alerts.jpg)
*Figure 1. Agent Active, zero alerts in the last 24 hours.*

### 2. Generate known test events on the endpoint
- `net user testuser /add` first failed with **"Access is denied"** because PowerShell was not elevated. That was my mistake, not a SIEM fault, and it was worth ruling out. No event had been created.
- Re-ran from an **elevated** PowerShell: user created and deleted successfully.
- Confirmed Windows itself logged the activity:
  ```powershell
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4726} -MaxEvents 5
  ```
  Result: **4720** (user account created) and **4726** (user account deleted) were present. Windows auditing was fine, so the gap was downstream.

![PowerShell showing events 4720 and 4726](../screenshots/2026-10-18-disk-full/03-windows-logged-events.jpg)
*Figure 2. Windows logged the account creation and deletion.*

### 3. Verify the agent
- `sudo /var/ossec/bin/agent_control -l` showed `win11-client` (ID 001) **Active**.
- Agent `ossec.log` showed it connected to `10.0.2.6:1514` and completed its scans.
- Confirmed in `ossec.conf` that the **Security**, System and Application event channels were configured.

Conclusion: the endpoint was healthy and sending data. The fault was on the server.

### 4. Check the server's alert output
```bash
sudo ls -lh /var/ossec/logs/alerts/
```
Both `alerts.json` and `alerts.log` were **0 bytes**. The manager was producing no alerts at all, which ruled out Filebeat and the dashboard as the primary cause.

![alerts.json and alerts.log at 0 bytes](../screenshots/2026-10-18-disk-full/04-alert-files-empty.jpg)
*Figure 3. Empty alert files on the Wazuh server.*

### 5. Look for errors
- `wazuh-control status` failed with a **stale `start-script-lock`** error, left over from an interrupted start/stop.
- `ps aux` showed the Wazuh daemons running, so this was a symptom, not the root cause.
- `ossec.log` contained **"database or disk is full"** errors.

### 6. Root cause: disk full
```bash
df -h /
```
| Filesystem | Size | Used | Avail | Use% |
|---|---|---|---|---|
| /dev/mapper/ubuntu--vg-ubuntu--lv | 24G | 24G | 0 | **100%** |

With no free space, the manager could not write alerts or update its SQLite databases.

![Wazuh log showing database or disk is full, and df showing 100%](../screenshots/2026-10-18-disk-full/05-disk-full-errors.jpg)
*Figure 4. Manager errors and the root volume at 100%.*

### 7. Find what was using the space
```bash
sudo du -xh / --max-depth=3 2>/dev/null | sort -rh | head -n 20
sudo du -xh /var/ossec/queue --max-depth=2 2>/dev/null | sort -rh | head -n 10
```
| Path | Size |
|---|---|
| `/var/ossec/queue` | **13 GB** |
| `/var/ossec/queue/vd_updater/tmp` | **7.3 GB** (temporary download area) |
| `/var/ossec/queue/vd/feed` | 5.6 GB (vulnerability content feed) |

The vulnerability-detection updater had downloaded the CVE feed, failed to finish, and left its temp files behind.

![du output showing 13 GB in the Wazuh queue](../screenshots/2026-10-18-disk-full/06-where-the-space-went.jpg)
*Figure 5. Where the space went.*

### 8. Fix
Only the disposable temp directory was cleared. Agent databases and counters were left untouched.
```bash
sudo systemctl stop wazuh-manager
sudo rm -rf /var/ossec/queue/vd_updater/tmp/*
sudo rm -f /var/ossec/var/start-script-lock
sudo systemctl start wazuh-manager
sudo systemctl restart wazuh-indexer filebeat wazuh-dashboard
```
Result: `/` went from **100%** to **73% used (6.1 GB free)**, and `wazuh-control status` showed all core daemons running (`analysisd`, `remoted`, `db`, `syscheckd`, `logcollector`, `modulesd`, `authd`, `apid`). The remaining "not running" entries (clusterd, maild, agentlessd, integratord, dbd, csyslogd) are optional features that are off by default.

![Commands used for the fix and alerts.json at 58K](../screenshots/2026-10-18-disk-full/07-fix-and-recovery.jpg)
*Figure 6. The fix and the first sign of recovery.*

### 9. Verification
- `alerts.json` grew from 0 to **58 KB** and `alerts.log` to **97 KB**.
- Dashboard (last 24 h): **19 low** and **4 medium** severity alerts.
- Threat Hunting → Events: **27 hits** for `win11-client`.
- Disk usage held steady at **73%** about 20 minutes after the restart.

![Dashboard with 19 low and 4 medium alerts](../screenshots/2026-10-18-disk-full/08-dashboard-alerts-back.jpg)
*Figure 7. Alerts are back on the dashboard.*

![Threat Hunting list of 27 events](../screenshots/2026-10-18-disk-full/09-events-detected.jpg)
*Figure 8. Threat Hunting events for win11-client.*

## What the alerts showed

| Test action | Wazuh detections (rule level) |
|---|---|
| `net user testuser5 /add` | User account enabled or created (8), User account changed (8), Users Group Changed (5), Domain Users Group Changed (5) |
| `net user testuser5 /delete` | User account disabled or deleted (8) |
| Lock/unlock screen | Windows Logon Success (3) |

One command raised several alerts because Windows logs account creation, group membership and attribute changes as separate events.

I also inspected **rule 60111** ("User account disabled or deleted", `0580-win-security_rules.xml`). It triggers on Windows Event IDs 630, 629, 4725 and 4726 and is chained to parent rule 60103 via `if_sid`. It carries GDPR, HIPAA, TSC and GPG 13 compliance tags.

## Lessons learned

1. **Silence is a signal.** An Active agent with zero alerts is a failure to investigate, not good news.
2. **Isolate layer by layer:** endpoint logging, agent, manager output, indexer, dashboard. Each check ruled out a layer.
3. **Check the basics first.** An un-elevated PowerShell and a typo caused two false starts.
4. **Disk capacity is a security control.** If the SIEM cannot write, it cannot detect. Vulnerability detection needs room to download and unpack its feed.
5. **Delete only what is safe to delete.** I confirmed that `vd_updater/tmp` is disposable before removing anything under `/var/ossec`.

## Next steps

- [ ] **Extend the root volume.** `df` shows a 24 GB logical volume, so check `lsblk` and `vgs` for unallocated space and run `lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv`. The disk is not at a safe margin for vulnerability detection.
- [ ] **Add disk-usage monitoring** so a full disk is caught before the SIEM goes silent.
- [ ] **Install Sysmon (v15.22)** on `win11-client` with the SwiftOnSecurity configuration (already downloaded and extracted), add the `Microsoft-Windows-Sysmon/Operational` event channel to `ossec.conf`, and confirm Sysmon events in Threat Hunting.
- [ ] **Kali attack simulation** (Nmap scan against Metasploitable2 and Windows 11) with detections mapped to MITRE ATT&CK, starting with T1046 (Network Service Discovery).

## Tools

Wazuh 4.x (manager, indexer, dashboard, Filebeat), Windows 11, Ubuntu Server 22.04, Kali Linux, Metasploitable2, VirtualBox, PowerShell, Sysmon.
