# Password spray — reproduction
1. Run ` bash password-spray.sh` on your own tenant.
2. Wait ~5–15 min for Entra→Sentinel ingestion.
3. Confirm the failure cluster: run the signal query (see README).

**Note on method:** modern Entra blocks legacy auth, so this simulates spray *telemetry*
via the ROPC flow with security defaults adjusted for the lab. The detection logic is
independent of how the failures were generated — it keys on the SigninLogs failure pattern.
