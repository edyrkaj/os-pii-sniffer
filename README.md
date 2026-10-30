# PII Sniffer

Local macOS guard for outbound uploads. Turn protection on to trust a local certificate, point the system HTTP(S) proxy at the app, and mask cleartext email, phone, card, address, and contact values before they are forwarded.

The activity list stores redaction tokens only. It does not keep the original personal data.

Pinned browser suites (Google, Apple, Microsoft, Mozilla, Brave) are bypassed by default so everyday browsing keeps working. The Services tab lists every host the proxy sees; Activity defaults to PII findings.
