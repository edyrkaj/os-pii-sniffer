export type PiiType = "email" | "phone" | "card" | "address" | "contact";

export type TypeRule = {
  mask: boolean;
  alert: boolean;
};

export type Rules = Record<PiiType, TypeRule>;

export type Finding = {
  piiType: PiiType;
  fieldPath: string;
  action: "masked" | "allowed";
  token: string;
};

export type ActivityEvent = {
  id: string;
  timestamp: string;
  processName: string;
  method: string;
  host: string;
  path: string;
  action: "masked" | "allowed" | "skipped";
  alert: boolean;
  seen: boolean;
  detail: string | null;
  findings: Finding[];
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
};

export const PII_TYPES: { id: PiiType; label: string; hint: string }[] = [
  {
    id: "email",
    label: "Email",
    hint: "Cleartext addresses are replaced with [redacted-email].",
  },
  {
    id: "phone",
    label: "Phone",
    hint: "Plausible phone numbers are replaced with [redacted-phone].",
  },
  {
    id: "card",
    label: "Credit card",
    hint: "Luhn-valid card numbers are replaced with [redacted-card].",
  },
  {
    id: "address",
    label: "Address",
    hint: "Street addresses are experimental and use [redacted-address].",
  },
  {
    id: "contact",
    label: "Contact",
    hint: "vCards and name-plus-email objects use [redacted-contact].",
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
    bypassHosts: ["bank.example"],
    events: [
      {
        id: "preview-alert",
        timestamp: "2026-10-30T15:04:00Z",
        processName: "curl",
        method: "POST",
        host: "api.example.com",
        path: "/customers",
        action: "masked",
        alert: true,
        seen: false,
        detail: null,
        findings: [
          {
            piiType: "email",
            fieldPath: "$.email",
            action: "masked",
            token: "[redacted-email]",
          },
        ],
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
