# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Ismail-issa/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered
What looks like the user "employee" downloaded a tor installer. did something that resulted in many tor-related files being copied to the desktop and the creation of a file called ‘tor-shooping-list.txt on the desktop at 2025-10-27T09:48:04.8816594Z. 
These events began at: 2025-10-27T09:48:04.8816594Z.


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-10-28T03:00:12.231381Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
<img width="1094" height="676" alt="Screenshot 2025-10-28 at 14 20 28" src="https://github.com/user-attachments/assets/f004ba47-13f8-42d0-92fc-7a36c2fc6f49" />


```
<img width="1094" height="676" alt="Screenshot 2025-10-28 at 14 20 28" src="https://github.com/user-attachments/assets/e59ba04b-94e9-4fe7-b0ed-b8fb004b44fa" />

---

### 2. Searched the `DeviceProcessEvents` Table

Search the DeviceProcessEvent for any indication that user "threat-hunt-lab" actually opened the Tor browser. There was evidence that they did open it at 2025-10-28T03:01:30.7131111Z.
There were several other instances of Firefox.exe (Tor) as well as Tor.exe spawned afterwards.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1087" height="595" alt="Screenshot 2025-10-28 at 14 50 52" src="https://github.com/user-attachments/assets/58899890-4525-42fc-b222-5fca5962a7f6" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Search the DeviceProcessEvent for any indication that user "threat-hunt-lab" actually opened the Tor browser. There was evidence that they did open it at 2025-10-06T22:53:59.2778013Z.
There were several other instances of Firefox.exe (Tor) as well as Tor.exe spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor.browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1087" height="599" alt="Screenshot 2025-10-28 at 14 55 21" src="https://github.com/user-attachments/assets/6d0dfd25-609c-4001-aac5-358044f3b34b" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceProcessEvent for any indication that user "threat-hunt-lab" actually opened the Tor browser. There was evidence that they did open it at 2025-10-06T22:53:59.2778013Z.
There were several other instances of Firefox.exe (Tor) as well as Tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
<img width="1108" height="607" alt="Screenshot 2025-10-28 at 14 57 37" src="https://github.com/user-attachments/assets/37f4b0f5-5395-400c-819a-fcd44ec2243a" />

---

## Chronological Event Timeline 

2025-10-06
16:53:59 — Process Execution (Tor Browser)


User: employee

Event: firefox.exe (Tor Browser) started

Note: Path indicates Tor Browser directory (portable build).

Source: tor-process-creation.csv

16:55:35 — Network Connection (Tor)

User: employee

Process: tor.exe

Remote: 51.178.131.200:9001 (Tor relay port)

Path: c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe

Source: tor-usage.csv

2025-10-08
20:22:26 — Silent Install (Tor Browser)

User: murrellsh

Binary: tor-browser-windows-x86_64-portable-14.5.8.exe /S

Source: tor-install.csv

2025-10-13
23:58:39 — Silent Install (Tor Browser)


User: josephcompton


Binary: tor-browser-windows-x86_64-portable-14.5.8.exe /S


Source: tor-install.csv


2025-10-14
11:53:06 — Silent Install (Tor Browser)


User: employee


Binary: tor-browser-windows-x86_64-portable-14.5.8.exe /S


Source: tor-install.csv


2025-10-20
12:13:47 → 12:17:32 — Installs (Tor Browser)


User: userr28i26


Events: Multiple installer runs, both normal and silent:


tor-browser-windows-x86_64-portable-14.5.8.exe (several invocations)


Source: tor-install.csv


2025-10-06 → 2025-10-27 (Ongoing Usage Pattern)
Repeated Tor Browser executions (firefox.exe under the Tor Browser path) and Tor core launches (tor.exe) across users employee, josephcompton, murrellsh, userr28i26.


Multiple outbound connections on Tor ports (notably 9001, 9150) to various external IPs consistent with Tor relays/bridges.


Sources: tor-process-creation.csv, tor-usage.csv


2025-10-27 (Focused Activity by employee)
21:01:30 — Silent Install (Tor Browser)


User: employee


Binary: tor-browser-windows-x86_64-portable-14.5.8.exe /S


Source: tor-install.csv


21:04:08 — Network Connection (Tor)


User: employee


Process: tor.exe


Remote: 103.252.194.174:9001 (Tor relay port)


Path: c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe


Source: tor-usage.csv


21:11:22 — Artifact Creation


User: employee


File Created: C:\Users\employee\Desktop\tor-shopping-list.txt


Hash (SHA256): 4e1b4aa4abe7f31b0f688410636b0c5e9dcdf0a6e30eca3c430089fde68870e3


Also observed: tor-shopping-list.lnk in AppData\Roaming\Microsoft\Windows\…


Source: tor-download.csv


Up to 21:18:38 — Continued Tor Activity


Additional Tor Browser process starts and/or network connections recorded.


Sources: combined logs



Quantitative Highlights (Tor-Only)
Event window: 2025-10-06 16:53:59 → 2025-10-27 21:18:38


By event type (all users; deduped counts):


Tor Browser (Firefox) started: 140


Network connections (Tor-related): 62


Tor core process started (tor.exe): 8


Silent installer executions (/S): 5


Normal installer executions: 3


Tor-related file creations (incl. tor-shopping-list.txt): 11


Observed Tor ports: 9001, 9150 (plus some 443 activity)


Sample remote IPs seen: 103.252.194.174, 51.178.131.200, 46.4.66.178, 65.108.233.166, 88.99.142.177 (and others typical of Tor relays)


Users with Tor activity: employee, josephcompton, murrellsh, userr28i26

---

## Summary

Between Oct 6 and Oct 27, 2025, Tor Browser was installed (often silently), executed, and used to make outbound connections to Tor network relays on the workstation threat-hunt-lab by multiple user accounts. The pattern shows repeated use of Tor Browser (Firefox within the Tor directory) and Tor core (tor.exe) establishing connections on Tor-associated ports (9001/9150) to multiple external IPs consistent with Tor infrastructure.
On Oct 27, the user employee performed a silent installation of Tor Browser, initiated a Tor network connection to 103.252.194.174:9001, and created a desktop artifact tor-shopping-list.txt (with recorded SHA256), confirming active usage and file-level traces on that date.
Implication: Tor usage provides anonymity and can obfuscate destinations and content, which may bypass typical monitoring/controls. Even when there is a legitimate business need, Tor usage is high-risk without explicit authorization and compensating controls.

---

## Response Taken

TOR usage was confirmed on endpoint Threat-hunt-lab by the user employee. The device was isolated and the user's direct manager was notified.

---
