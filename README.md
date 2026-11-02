# Case File 001: PCAP and OSINT Analysis of a Lumma Stealer Alert 📂

Source exercise: [Lumma in the Room-ah (2026-01-31)](https://www.malware-traffic-analysis.net/2026/01/31/index.html) on malware-traffic-analysis.net.
This repo contains my own analysis only. No PCAP and no malware are included, and all indicators are defanged.

## Summary📄

1. An IDS alert (ET MALWARE Lumma Stealer Victim Fingerprinting Activity) fired on 2026-01-27 at 23:05 UTC for traffic from 153[.]92[.]1[.]49 over TCP port 80.
2. In the associated PCAP, the only internal host talking to that IP was 10.1.21.58, identified as DESKTOP-ES9F3ML, logged in as `gwyatt` (Gabriel Wyatt) in the WIN11OFFICE domain.
3. That host sent repeated HTTP requests to `/api/set_agent` on whitepepper[.]su carrying an ID and token, consistent with the victim-fingerprinting check-in that triggered the alert.
4. The domain was 39 days old at the time and had used at least 9 different IPs since December 2025. VirusTotal lists 590 files that contact it, and ThreatFox lists URLs on it under Lumma Stealer.
5. Confidence: host identification is high. How the host was infected, and whether its malware matches the sample I studied, are not established by this capture.

## Tools and Terms🔨
 
Tools: Wireshark, VirusTotal, ThreatFox, URLhaus, crt.sh.
Every finding has a packet number or a source. 

Confidence labels: **Confirmed** (direct evidence), **Likely** (strong indirect evidence), **Inferred** (my reasoning, not proven).

## Phase 1: Triaging PCAP

| Question | Answer | Filter / method | Evidence | Confidence |
|---|---|---|---|---|
| Infected IP | 10.1.21.58 | `ip.addr == 153.92.1.49`, then Statistics > Conversations > IPv4 with "Limit to display filter" | Only internal host that talked to the alerted IP, at alert time (23:05 UTC) | Confirmed |
| MAC address | 00:21:5d:c8:0e:f2 | `dhcp` | DHCP Client MAC field, requested IP 10.1.21.58 | Confirmed |
| Hostname | DESKTOP-ES9F3ML | `dhcp` | DHCP option 12 (Host Name) | Confirmed |
| User account | gwyatt | `kerberos.CNameString` (added as a column) | Kerberos AS-REQ from 10.1.21.58 to the DC, starting at packet 214 and no trailing `$`, so a user account | Confirmed |
| Full name | Gabriel Wyatt | `samr`, then the DC's QueryUserInfo response | SAMR response, packet 28574, matches the `gwyatt` naming pattern | Confirmed |
| Alert domain | whitepepper[.]su | `ip.addr == 153.92.1.49 && http.request` | HTTP `Host:` header, packet 24500 | Confirmed |



