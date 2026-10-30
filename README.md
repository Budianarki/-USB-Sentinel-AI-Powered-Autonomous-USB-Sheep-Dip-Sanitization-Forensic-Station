# USB Sentinel

AI-Agent USB Sanitization Station (Sheep Dip Station) for physical security perimeter at server room entrances.

> Primary source of truth: `CLAUDE.md`.

## Features
- **Layer 1: Device Guard** (USB class verification, BadUSB prevention, hardened mount `ro,noexec,nosuid,nodev`).
- **Layer 2: Deterministic Scan** (ClamAV, YARA, magic bytes mismatch check, static feature extraction).
- **Layer 3: AI Agent Layer** (Tiered multi-agent via Gateway: Static Analyst, Intel, Context/Anomaly, Critic, Responder).
- **Layer 4: Policy Engine** (Deterministic rule-based decision: ALLOW, QUARANTINE, BLOCK, HUMAN_REVIEW).

## Important Security Note
**Physical server ports must be disabled** (via BIOS, GPO, or USBGuard). Otherwise, the sanitization station can be bypassed by plugging directly into server machines.
