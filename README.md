# Entra ID: Sentinel Detection Engineering Lab

## Architecture

Cloud-identity detection pipeline, all in Azure:

Attacker (Kali) → Entra ID tenant → Entra diagnostic settings →
Log Analytics workspace (`sentinel-logger`) → Microsoft Sentinel → KQL analytics rules → Incidents

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

## Detection 1 — Password Spray (MITRE ATT&CK T1110.003)

**The attack.** A password spray tries a few common passwords across many accounts to evade
per-account lockout. Simulated here via scripted authentication attempts against the Entra
token endpoint, across 5 test users (`attacks/password-spray.sh`), producing failed sign-ins
(`ResultType 50126`) in `SigninLogs`.

**The signal.** Many distinct users failing authentication from a single source in a short
window:

​```
kql
SigninLogs
| where ResultType != 0
| summarize FailedCount = count(),
            DistinctUsers = dcount(UserPrincipalName),
            Users = make_set(UserPrincipalName)
        by IPAddress, bin(TimeGenerated, 10m)
| where DistinctUsers >= 3
​```

**The detection.** A scheduled Sentinel analytics rule on the query above (full rule in
`detections/password-spray.kql`), mapped to T1110.003. Triggers when ≥3 distinct users fail
from one source in a 10-minute bin.

> **Note:** the rule's lookback window is set in the rule *configuration*, not the query —
> which is why there's no `ago()` in the committed KQL.

**Validation.**

| Test | Input | Expected | Result |
|---|---|---|---|
| Positive | spray (≥3 users fail, one source) | incident fires | ✅ fired (`evidence/m2-incident.png`) |
| Negative | single failed login (1 user) | no incident | ✅ 0 rows / no incident (`evidence/m2-negative-test.png`) |

The **negative test** is the important half: a single failed login logged in `SigninLogs`
(1 user) but returned **zero rows** against the rule query — the `≥3` threshold held, so no
incident fired. The detection discriminates a benign fat-fingered password from an actual
spray.
