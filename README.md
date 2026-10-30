# PII Sniffer

Local macOS guard for outbound uploads. Turn protection on to trust a local certificate and point the system HTTP(S) proxy at the app. Uploads are forwarded unchanged. Cleartext email, phone, card, address, and contact values are recorded in the activity list without storing the original value.

Pinned browser suites (Google, Apple, Microsoft, Mozilla, Brave) are bypassed by default so everyday browsing keeps working. The Services tab lists every host the proxy sees; Activity defaults to PII findings.
