---
name: owasp-top-10-2025
description: >
  Applies OWASP Top 10:2025 security guidance when reviewing code, designing systems, or discussing
  web application security. Use when the user asks about application security risks, vulnerability
  prevention, secure coding practices, security reviews, security audit, code review, PR review,
  pull request review, penetration testing, SAST findings, threat modeling, OWASP compliance, or
  mentions any of: broken access control, IDOR, SSRF, CORS, security misconfiguration, supply chain
  security, vulnerable dependencies, cryptographic failures, plaintext secrets, hardcoded keys,
  injection, SQL injection, XSS, command injection, insecure design, authentication failures,
  credential stuffing, session management, data integrity, insecure deserialization, security
  logging, error handling, exception handling, fail-open, or fail-closed. Also trigger when
  reviewing pull requests for security issues, hardening configurations, or building any feature
  that handles user input, authentication, authorization, file uploads, payments, or sensitive data.
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

## How to Respond

When this skill is active, apply the following approach consistently:

### Review Methodology

1. **Scan all 10 categories** against the code, design, or question at hand.
2. **Report only what applies** — don't list categories that aren't relevant just to be thorough.
3. **Always provide a concrete fix** — every finding must include either corrected code or a
   specific actionable step. Never leave a finding without a remedy.
4. **Reference authoritative guidance** — point to the relevant OWASP Cheat Sheet or category
   for each finding. See `references/categories.md` for cheat sheet links per category.
5. **Check for patterns, not just instances** — if you find one SQL injection, look for the same
   pattern elsewhere before reporting.

### Severity Definitions

Rate every finding with one of these four levels:

| Severity | Criteria |
|----------|----------|
| 🔴 **Critical** | Directly exploitable with no preconditions. Leads to full system/data compromise, RCE, auth bypass, or mass data exposure. Examples: SQL injection with no auth required, hardcoded admin credentials, deserialization RCE. |
| 🟠 **High** | Exploitable with low complexity or minimal access. Significant data exposure, privilege escalation, or service disruption likely. Examples: IDOR on sensitive records, missing auth on admin endpoints, broken session invalidation. |
| 🟡 **Medium** | Exploitable under specific conditions or requires some user interaction. Limited data exposure or requires chaining with another issue. Examples: CSRF on low-value actions, verbose error messages leaking internals, missing rate limiting on password reset. |
| 🔵 **Low / Informational** | Defense-in-depth improvements. Not directly exploitable alone, but reduces security posture. Examples: missing security headers, overly broad CORS, unused dependencies. |

### Finding Format

Structure each finding as:

```
[SEVERITY] CategoryCode — Short Title
Location: file.ext:line or component/endpoint
Issue: One sentence explaining what the vulnerability is and why it's dangerous.
Fix: Corrected code snippet or specific remediation steps.
Reference: OWASP Cheat Sheet or category link.
```

### Context-Specific Guidance

**For code reviews / PR reviews:** Scan changed lines first, then look for call sites and related
patterns throughout the codebase context available to you. Flag issues in the diff specifically
(file + line). Prioritize Critical and High; mention Medium/Low briefly at the end.

**For architecture/design questions:** Start with A06 (Insecure Design), then work through each
relevant category. Focus on what controls need to be designed in, not just implemented.

**For threat modeling:** Walk through each category and ask "could an attacker exploit this in
our system?" Produce a finding per plausible threat vector, with likelihood and impact reasoning.

**For general security questions:** Cite the relevant OWASP category, explain the risk clearly,
and give concrete prevention steps tailored to the user's stack if known.

---

## Reference Files

→ `references/categories.md` — Full details on all 10 categories: descriptions, common
  vulnerabilities, prevention strategies, code review patterns, and OWASP Cheat Sheet links.
→ `references/code-patterns.md` — Insecure → secure code examples in JavaScript and Python
  for the most frequently encountered vulnerability types.

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
