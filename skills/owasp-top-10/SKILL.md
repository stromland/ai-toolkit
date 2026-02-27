---
name: owasp-top-10-2025
description: >
  Applies OWASP Top 10:2025 security guidance when reviewing code, designing systems, or discussing
  web application security. Use when the user asks about application security risks, vulnerability
  prevention, secure coding practices, security reviews, threat modeling, OWASP compliance, or
  mentions any of: broken access control, security misconfiguration, supply chain security,
  cryptographic failures, injection, insecure design, authentication failures, data integrity,
  security logging, error handling, or exception handling. Also trigger when reviewing pull requests
  for security issues, hardening configurations, or building new features that handle user input,
  authentication, authorization, or sensitive data.
---

# OWASP Top 10:2025 — Security Guidance for Developers

The OWASP Top 10:2025 is the industry standard for the most critical web application security risks.
This skill helps you apply these standards during code review, architecture design, and implementation.

Source: https://owasp.org/Top10/2025/

## The 2025 List at a Glance

| #  | Category | Key Concern |
|----|----------|-------------|
| A01 | Broken Access Control | Users acting outside intended permissions |
| A02 | Security Misconfiguration | Insecure defaults, open cloud storage, verbose errors |
| A03 | Software Supply Chain Failures | Compromised dependencies, build systems, distribution (**new scope**) |
| A04 | Cryptographic Failures | Weak crypto, plaintext data, key leakage |
| A05 | Injection | SQL, NoSQL, OS command, LDAP, XSS injection |
| A06 | Insecure Design | Missing or ineffective security controls at the design level |
| A07 | Authentication Failures | Credential stuffing, weak passwords, broken session management |
| A08 | Software or Data Integrity Failures | Insecure deserialization, unsigned updates, tampered artifacts |
| A09 | Security Logging & Alerting Failures | Insufficient logging, no alerting, poor incident visibility |
| A10 | Mishandling of Exceptional Conditions | Fail-open errors, unhandled exceptions, crash-path exploits (**new**) |

## Key Changes from 2021

Three structural changes define the 2025 update:

1. **SSRF consolidated into A01** — Server-Side Request Forgery is now part of Broken Access Control,
   reflecting that both are fundamentally about unauthorized resource access.
2. **A03 expanded from "Vulnerable Components" to "Supply Chain Failures"** — Now covers the entire
   ecosystem: dependencies, build systems, CI/CD pipelines, and distribution infrastructure. Voted
   the #1 concern in the OWASP community survey.
3. **A10 is brand new: Mishandling of Exceptional Conditions** — Replaces the old SSRF category.
   Focuses on fail-open scenarios, unhandled exceptions, and systems that break insecurely under stress.

The 2025 edition also shifted focus from symptoms to root causes. Categories like "Cryptographic
Failures" address the underlying problem rather than the resulting "Sensitive Data Exposure."

## How to Use This Skill

**For code reviews:** Check the relevant categories below against the code under review. The
references file has specific patterns to look for and prevention techniques for each category.

**For architecture/design:** Use A06 (Insecure Design) as your starting point, then verify that
each relevant category has controls designed in from the start.

**For threat modeling:** Walk through each category and ask "could this apply to our system?"

For detailed guidance on any category, read the reference file:
→ `references/categories.md` — Full details on all 10 categories with descriptions, common
  vulnerabilities, prevention strategies, and code-level examples.

## Quick Prevention Checklist

When building or reviewing any feature, verify:

- [ ] **Access control** — Deny by default. Server-side enforcement. Record-level ownership checks.
- [ ] **Configuration** — No defaults in production. Minimal platform. Security headers set. Error
      pages reveal nothing useful to attackers.
- [ ] **Dependencies** — Pinned versions. SBOM maintained. Provenance verified. Automated scanning.
- [ ] **Cryptography** — Data classified. TLS everywhere. Strong algorithms (no MD5/SHA1 for
      security). Keys rotated. No secrets in code.
- [ ] **Input handling** — Parameterized queries. Input validation. Output encoding. No dynamic
      queries from user input.
- [ ] **Design** — Threat model exists. Abuse cases considered. Rate limiting. Separation of
      privilege.
- [ ] **Authentication** — MFA supported. No default credentials. Passwords checked against breach
      lists. Session tokens rotated on login.
- [ ] **Integrity** — Code signed. Updates verified. Deserialization restricted. CI/CD pipeline
      integrity validated.
- [ ] **Logging** — Login failures logged. Access control failures logged. Alerts configured. Logs
      not exposed to users. Log injection prevented.
- [ ] **Error handling** — Fail closed. Exceptions caught specifically. No sensitive info in error
      responses. Graceful degradation under stress.
