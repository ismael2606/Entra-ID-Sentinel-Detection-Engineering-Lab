# Entra ID: Sentinel Detection Engineering Lab

## Architecture

Cloud-identity detection pipeline, all in Azure:

Attacker (Kali) → Entra ID tenant → Entra diagnostic settings →
Log Analytics workspace (`<sentinel-logger>`) → Microsoft Sentinel → KQL analytics rules → Incidents

- **Entra ID** — identity provider and attack surface; provides SigninLogs + AuditLogs.
- **Entra data connector / diagnostic settings** — forwards those logs to the workspace.
- **Log Analytics workspace** (`sentinel-logger`) — stores the log tables KQL queries.
- **Microsoft Sentinel** — the SIEM layer; analytics rules run KQL on a schedule and raise incidents.
- Region: `East US`.

**Pipeline verified before any attack:** a test sign-in was generated and confirmed to
appear in `SigninLogs` in Sentinel, proving end-to-end ingestion works. Evidence:

![](evidence/m1-logs-flowing.png)

## Setup

1. Log Analytics workspace `sentinel-logger` in region `East US`, resource group `sentinel-lab`.
2. Microsoft Sentinel enabled on that workspace (free trial available).
3. Entra data connector enabled → SigninLogs + AuditLogs → the workspace.
   (Under the hood: Entra ID → Diagnostic settings → send to Log Analytics.)
4. 5 test users created (P2-licensed): `ana`, `bobby`, `carolin`, `dave`, `erick`.
5. Verified: test sign-in appeared in SigninLogs (see screenshot above).
