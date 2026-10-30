export type PiiType = "email" | "phone" | "card" | "address" | "contact";

export type TypeRule = {
  mask: boolean;
  alert: boolean;
};

export type Rules = Record<PiiType, TypeRule>;

export type Finding = {
  piiType: PiiType;
  fieldPath: string;
  action: "detected" | "allowed";
  token: string;
};

export type ActivityEvent = {
  id: string;
  timestamp: string;
  processName: string;
  method: string;
  host: string;
  path: string;
  action: "detected" | "allowed" | "skipped" | "clean";
  alert: boolean;
  seen: boolean;
  detail: string | null;
  findings: Finding[];
};

export type ServiceEvent = {
  host: string;
  processName: string;
  firstSeen: string;
  lastSeen: string;
  connectCount: number;
  scannedCount: number;
  piiCount: number;
  lastMode: string;
};

export type Snapshot = {
  protectionOn: boolean;
  certTrusted: boolean;
  proxyInstalled: boolean;
  port: number | null;
  notice: string | null;
  pendingRestore: boolean;
  rules: Rules;
  bypassHosts: string[];
  events: ActivityEvent[];
  services: ServiceEvent[];
};

export const PII_TYPES: { id: PiiType; label: string; hint: string }[] = [
  {
    id: "email",
    label: "Email",
    hint: "Cleartext addresses are reported. The upload is sent unchanged.",
  },
  {
    id: "phone",
    label: "Phone",
    hint: "Plausible phone numbers are reported. The upload is sent unchanged.",
  },
  {
    id: "card",
    label: "Credit card",
    hint: "Luhn-valid card numbers are reported. The upload is sent unchanged.",
  },
  {
    id: "address",
    label: "Address",
    hint: "Street addresses are experimental and are only reported.",
  },
  {
    id: "contact",
    label: "Contact",
    hint: "vCards and name-plus-email objects are reported, not rewritten.",
  },
];

export function previewSnapshot(): Snapshot {
  return {
    protectionOn: false,
    certTrusted: false,
    proxyInstalled: false,
    port: null,
    notice: null,
    pendingRestore: false,
    rules: {
      email: { mask: true, alert: true },
      phone: { mask: true, alert: true },
      card: { mask: true, alert: true },
      address: { mask: true, alert: false },
      contact: { mask: true, alert: true },
    },
    bypassHosts: ["*.google.com", "bank.example"],
    services: [
      {
        host: "api.example.com",
        processName: "curl",
        firstSeen: "2026-10-30T15:01:00Z",
        lastSeen: "2026-10-30T15:04:00Z",
        connectCount: 2,
        scannedCount: 1,
        piiCount: 1,
        lastMode: "inspected",
      },
      {
        host: "cdn.example.com",
        processName: "Safari",
        firstSeen: "2026-10-30T15:00:00Z",
        lastSeen: "2026-10-30T15:03:00Z",
        connectCount: 8,
        scannedCount: 0,
        piiCount: 0,
        lastMode: "tunneled",
      },
    ],
    events: [
      {
        id: "preview-alert",
        timestamp: "2026-10-30T15:04:00Z",
        processName: "curl",
        method: "POST",
        host: "api.example.com",
        path: "/customers",
        action: "detected",
        alert: true,
        seen: false,
        detail: null,
        findings: [
          {
            piiType: "email",
            fieldPath: "$.email",
            action: "detected",
            token: "sent unchanged",
          },
        ],
      },
      {
        id: "preview-clean",
        timestamp: "2026-10-30T15:03:00Z",
        processName: "curl",
        method: "POST",
        host: "api.example.com",
        path: "/health",
        action: "clean",
        alert: false,
        seen: true,
        detail: "scanned: no cleartext PII",
        findings: [],
      },
      {
        id: "preview-allowed",
        timestamp: "2026-10-30T15:02:00Z",
        processName: "Safari",
        method: "POST",
        host: "hooks.example.com",
        path: "/form",
        action: "allowed",
        alert: false,
        seen: true,
        detail: null,
        findings: [
          {
            piiType: "phone",
            fieldPath: "$.phone",
            action: "allowed",
            token: "already-masked",
          },
        ],
      },
    ],
  };
}
