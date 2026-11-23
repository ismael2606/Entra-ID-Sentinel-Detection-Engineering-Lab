# Illicit consent grant — reproduction (own tenant)
1. Register a test app; add delegated Graph permissions (e.g. User.Read, offline_access).
2. Register `https://localhost` as a redirect URI (Authentication → Add platform → Web).
3. Attempt user consent via the authorize URL (signed in as a test user).
4. Grant consent (admin-consent path used here — see finding below).
5. Confirm the "Consent to application" event in AuditLogs.

