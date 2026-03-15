# BLUELIGHT — TTP Report (S0657)

**Threat Actor:** APT37 / InkySquid  
**Type:** Remote Access Trojan  
**Platform:** Windows  
**Risk Level:** Critical  
**TLP:** WHITE  

## Attack Chain Summary
1. Initial Access — Drive-by Compromise (T1189)
2. Execution — Client Exploitation (T1203)
3. Defense Evasion — Obfuscation (T1027)
4. C2 — Microsoft Graph API (T1071.001)
5. Discovery — System/Registry/File (T1082, T1012, T1083)
6. Collection — Screen Capture + Credentials (T1113, T1555.003)
7. Ingress Tool Transfer (T1105)
8. Exfiltration — OneDrive (T1567.002)

## Files
- 📄 [Full Report PDF](./BLUELIGHT_TTP_Report_v1.0.pdf)
- 🔍 [Detection Queries](./splunk_queries.md)

## Key IOCs
| Indicator | Value |
|-----------|-------|
| SHA-256 | 5c430e2770b59...  |
| Domain | jquery[.]services |
| XOR Key | 0xCF |
| CVEs | CVE-2020-1380, CVE-2021-26411 |

## References
- [MITRE ATT&CK S0657](https://attack.mitre.org/software/S0657/)
- [Volexity Report](https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/)
