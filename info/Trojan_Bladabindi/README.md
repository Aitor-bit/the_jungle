# Analysis of Bladabindi njRAT

### Basic identification
* **Name:** Bladabindi / njRAT
* **Type:** Remote Access Trojan (RAT)
* **Architecture:** .NET Framework (MSIL)
* **Hash md5 .exe:** 4ec2b2398e5d286c3202064bb3cbb14b
* **Hash md5 uncompressed file:** c11324b04408d615e59d129f8a6be3ba

### Technical summary
Bladabindi is a persistent backdoor designed to grant full remote control over an infected host. It is known for using dynamic DNS services for Command and Control (C2) communication.

### Main capabilities
* **Spyware:** Keylogging (`[kl]`), screen capture (`[sc]`), and webcam access.
* **Data theft:** Extraction of browser passwords and system information.
* **Remote shell:** Execution of arbitrary commands and file management.

### Indicators of compromise
* **Network:** Connections to `soa7.zapto.org`
* **Registry:** Persistence via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
* **Filesystem:** Typically drops a copy named `server.exe` in `%TEMP%` or `%APPDATA%`.

### Mitre att&ck techniques
* Registry Run Keys / Startup Folder
* Keylogging
* Application Layer Protocol (C2)
* Replication through Removable Media
