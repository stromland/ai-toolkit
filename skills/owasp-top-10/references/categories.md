# OWASP Top 10:2025 — Detailed Category Reference

Read the section relevant to your current task. You don't need to read this entire file.

## Table of Contents

1. [A01: Broken Access Control](#a01-broken-access-control)
2. [A02: Security Misconfiguration](#a02-security-misconfiguration)
3. [A03: Software Supply Chain Failures](#a03-software-supply-chain-failures)
4. [A04: Cryptographic Failures](#a04-cryptographic-failures)
5. [A05: Injection](#a05-injection)
6. [A06: Insecure Design](#a06-insecure-design)
7. [A07: Authentication Failures](#a07-authentication-failures)
8. [A08: Software or Data Integrity Failures](#a08-software-or-data-integrity-failures)
9. [A09: Security Logging & Alerting Failures](#a09-security-logging--alerting-failures)
10. [A10: Mishandling of Exceptional Conditions](#a10-mishandling-of-exceptional-conditions)

---

## A01: Broken Access Control

**Ranking:** #1 (unchanged from 2021). 100% of tested applications had some form of this issue.
**CWEs:** 40 mapped CWEs. Key ones: CWE-200 (Info Exposure), CWE-201 (Sent Data Exposure),
CWE-918 (SSRF — new to this category), CWE-352 (CSRF).

### What It Is

Access control enforces that users cannot act outside their intended permissions. Failures lead to
unauthorized data access, modification, or deletion, and performing actions beyond the user's role.
SSRF is now included here because it is fundamentally about unauthorized access to resources —
whether those resources are another user's data or an internal network endpoint.

### Common Vulnerabilities

- Bypassing access checks by modifying URLs, internal state, or API requests
- Viewing or editing someone else's account by manipulating identifiers (IDOR)
- Privilege escalation — acting as admin without being one, or acting as a user without logging in
- API access without access controls for POST, PUT, DELETE operations
- CORS misconfiguration allowing unauthorized API access
- Force browsing to authenticated/privileged pages
- SSRF — tricking server-side code into making requests to internal resources (e.g., cloud metadata
  at `169.254.169.254`)

### Prevention

- **Deny by default.** Except for public resources, deny access unless explicitly granted.
- **Implement once, reuse everywhere.** Build access control into a shared module. Don't scatter
  authorization logic across individual endpoints.
- **Enforce record ownership.** Model access controls so that users can only CRUD their own records.
- **Enforce server-side.** Never rely on client-side access checks alone.
- **Minimize CORS.** Only allow origins you explicitly trust.
- **Rate-limit API access** to reduce automated attack impact.
- **Invalidate sessions on logout.** Stateless JWT tokens should have short lifetimes.
- **Log access control failures** and alert on repeated attempts.
- For SSRF: validate and sanitize all URLs constructed from user input. Use allowlists for permitted
  destinations. Block requests to internal networks and cloud metadata endpoints.

### Code Review Patterns

Look for:
- Authorization checks missing on controller/handler methods
- Direct object references using user-supplied IDs without ownership validation
- URL construction using unsanitized user input (SSRF)
- Missing CORS configuration or overly permissive `Access-Control-Allow-Origin: *`
- Reliance on hidden fields or client-side checks for authorization

---

## A02: Security Misconfiguration

**Ranking:** #2 (up from #5 in 2021). Found in 3% of tested apps with 719,000+ mapped CWEs.
**CWEs:** Key ones: CWE-16 (Configuration), CWE-611 (XXE).

### What It Is

The application, framework, server, or cloud service is configured incorrectly from a security
perspective. This is increasingly common as software becomes more configurable and environments
grow more complex (containers, cloud services, microservices).

### Common Vulnerabilities

- Unnecessary features enabled (ports, services, pages, accounts, privileges)
- Default credentials still active in production
- Stack traces or overly informative error messages exposed to users
- Missing or misconfigured security headers (CSP, HSTS, X-Frame-Options)
- Outdated or vulnerable software running with default configs
- Cloud storage (S3 buckets, Azure blobs) with permissive access policies
- Overly permissive IAM roles and policies
- XML External Entity (XXE) processing enabled
- Directory listing enabled on web server
- Missing TLS configuration or using outdated protocol versions

### Prevention

- **Harden systematically.** Use a repeatable hardening process for every environment (dev, staging,
  prod). Automate it.
- **Strip the platform down.** Remove or don't install unused features, frameworks, and dependencies.
- **Review and update configurations** as part of the patch management process.
- **Segment application architecture** with proper separation and security controls between
  components.
- **Send security directives to clients** via security headers.
- **Automate verification.** Run configuration audits in CI/CD and production.
- **Disable XML external entity processing** unless specifically needed.
- **Use different credentials** for every environment. Never share credentials between dev and prod.

### Code Review Patterns

Look for:
- Hardcoded credentials, API keys, or connection strings
- Debug mode or verbose error handling enabled in non-dev configurations
- Missing security headers in response middleware
- XML parsers without external entity processing disabled
- Cloud IaC (Terraform, CloudFormation) with permissive resource policies
- Docker images running as root or with unnecessary capabilities

---

## A03: Software Supply Chain Failures

**Ranking:** #3 (expanded from A06:2021 "Vulnerable and Outdated Components").
**CWEs:** 5 mapped. Fewest occurrences in test data, but **highest average exploit and impact
scores**. Voted #1 concern in the community survey.

### What It Is

This category goes far beyond just "use updated libraries." It covers the entire software supply
chain: dependencies, package registries, CI/CD systems, build pipelines, artifact repositories,
container registries, and update mechanisms. A failure is any breakdown or compromise in those
stages — a malicious package, a hijacked maintainer account, a tampered build, or an unsigned
distribution artifact.

### Common Vulnerabilities

- Using components with known vulnerabilities (still the most common scenario)
- Not knowing what components you use (no SBOM — Software Bill of Materials)
- Transitive dependency vulnerabilities (your dependency's dependency is compromised)
- Typosquatting and dependency confusion attacks on package registries
- Compromised CI/CD pipelines (build system as an attack vector, cf. SolarWinds)
- Malicious packages published under plausible names
- No integrity verification of downloaded packages (missing checksums, signatures)
- Unmaintained or abandoned dependencies still in production

### Prevention

- **Know your dependencies.** Maintain an SBOM and keep it current.
- **Pin dependency versions.** Use lockfiles (package-lock.json, Pipfile.lock, etc.).
- **Verify provenance and integrity.** Check signatures and checksums of packages.
- **Scan continuously.** Automate dependency scanning in CI/CD (Dependabot, Snyk, Trivy).
- **Monitor for new vulnerabilities** in your existing dependencies.
- **Harden CI/CD.** Treat your build pipeline as a security boundary. Least-privilege access for
  build service accounts. Audit pipeline configurations.
- **Use trusted registries.** Prefer well-known registries. Consider hosting a private, vetted
  registry for critical projects.
- **Review new dependencies** before adding them. Check maintainer reputation, download counts,
  recent activity, and known issues.
- **Remove unused dependencies** to reduce attack surface.

### Code Review Patterns

Look for:
- New dependencies added without justification or review
- Unpinned or loosely pinned versions (e.g., `^` or `*` ranges in package.json for critical deps)
- Dependencies downloaded over HTTP (not HTTPS)
- Post-install scripts in package.json that run arbitrary code
- CI/CD configuration changes that add new external access or modify build steps
- Missing lockfile updates accompanying dependency changes

---

## A04: Cryptographic Failures

**Ranking:** #4 (down from #2 in 2021). 3.8% of tested applications affected. 32 mapped CWEs.

### What It Is

Failures related to cryptography that lead to exposure of sensitive data or system compromise. This
includes using weak algorithms, improper key management, transmitting data in cleartext, and not
encrypting data that should be encrypted.

### Common Vulnerabilities

- Transmitting sensitive data in cleartext (HTTP, SMTP, FTP without TLS)
- Using deprecated algorithms (MD5, SHA1, DES, RC4) for security purposes
- Using default or weak cryptographic keys
- Not enforcing encryption (missing HSTS, TLS fallback to older versions)
- Storing passwords with reversible encryption or unsalted hashes
- Hard-coded encryption keys or secrets in source code
- Insufficient randomness for cryptographic operations
- Missing certificate validation

### Prevention

- **Classify data.** Know which data is sensitive according to privacy laws, regulatory
  requirements, and business needs.
- **Don't store sensitive data you don't need.** Discard it as soon as possible.
- **Encrypt at rest.** All sensitive data should be encrypted in storage.
- **Encrypt in transit.** Enforce TLS 1.2+ with strong cipher suites. Use HSTS.
- **Use strong, modern algorithms.** AES-256 for symmetric. RSA-2048+ or ECDSA for asymmetric.
  Argon2id, bcrypt, or scrypt for password hashing.
- **Never roll your own crypto.** Use well-vetted libraries and frameworks.
- **Manage keys properly.** Rotate keys. Don't store them in code. Use key management services
  (AWS KMS, Azure Key Vault, HashiCorp Vault).
- **Disable caching** for responses containing sensitive data.

### Code Review Patterns

Look for:
- Hard-coded keys, secrets, or passwords in source code
- Use of MD5, SHA1, DES, or RC4 in any security context
- Missing TLS enforcement or HTTP fallback paths
- Password storage using simple hashing (no salt, no key stretching)
- Random number generation using non-cryptographic PRNGs (e.g., `Math.random()`)
- Sensitive data in URLs (query parameters are logged)
- Missing certificate pinning in mobile apps

---

## A05: Injection

**Ranking:** #5 (down from #3 in 2021). Highest CVE count (62,445). 32 CWEs mapped.

### What It Is

User-supplied data is sent to an interpreter as part of a command or query without proper
validation, sanitization, or escaping. This includes SQL, NoSQL, OS command, LDAP, XPath, and
expression language injection, as well as Cross-Site Scripting (XSS).

### Common Vulnerabilities

- SQL injection via string concatenation in queries
- Command injection via unsanitized input passed to `exec()`, `system()`, etc.
- Cross-site scripting (stored, reflected, and DOM-based XSS)
- LDAP injection in directory service queries
- Expression Language (EL) / template injection in server-side templates
- NoSQL injection (e.g., MongoDB operator injection)
- Header injection (HTTP response splitting)

### Prevention

- **Use parameterized queries.** Prepared statements with bind variables for all database
  interactions. This is the single most important defense against SQL injection.
- **Use ORMs correctly.** ORMs protect against injection by default, but raw query features bypass
  this protection.
- **Validate input.** Server-side validation with allowlists where possible. Reject unexpected
  input rather than trying to sanitize it.
- **Encode output.** Context-appropriate output encoding for all user-supplied data rendered in HTML,
  JavaScript, CSS, or URLs.
- **Use safe APIs** that avoid the interpreter entirely, or provide a parameterized interface.
- **Apply Content Security Policy (CSP)** to mitigate XSS impact.
- **Escape special characters** where parameterized interfaces aren't available (last resort).

### Code Review Patterns

Look for:
- String concatenation or interpolation in SQL queries
- User input passed to `Runtime.exec()`, `os.system()`, `subprocess.run()`, etc.
- Template rendering with unescaped user input (e.g., `{{{ }}}` in Handlebars, `| safe` in Jinja2)
- User input reflected in HTML without encoding
- User input in HTTP headers without sanitization
- Dynamic LDAP/XPath query construction with user input
- `eval()` or `Function()` with user-controlled strings

---

## A06: Insecure Design

**Ranking:** #6 (down from #4 in 2021).

### What It Is

Insecure design is about missing or ineffective security controls at the architecture and design
level. This is distinct from implementation bugs — a perfect implementation of an insecure design
is still insecure. You cannot fix insecure design with a perfect implementation; security must be
designed in from the start.

### Common Vulnerabilities

- No threat model for the application or feature
- No rate limiting on sensitive operations (login, password reset, expensive API calls)
- Business logic flaws (unlimited discount application, negative quantity ordering)
- Missing abuse case analysis ("how could an attacker misuse this feature?")
- Trust boundaries not identified or enforced
- Over-reliance on client-side validation
- Missing separation of privilege for critical operations

### Prevention

- **Establish a Secure Development Lifecycle (SDLC).** Include security activities at each phase.
- **Threat model every significant feature.** Use STRIDE, PASTA, or similar frameworks.
- **Define and use security design patterns.** Build a reference architecture with vetted patterns.
- **Write abuse cases** alongside use cases. "As an attacker, I would try to..."
- **Apply least privilege** at every layer.
- **Limit resource consumption** per user and per session (rate limiting, quotas).
- **Integrate plausibility checks** at every tier (frontend, API, backend, database).
- **Segregate tenant data** in multi-tenant systems with strong isolation.

### Code Review Patterns

Look for:
- Endpoints without rate limiting (especially auth, reset, and resource-intensive operations)
- Business logic that doesn't validate against plausible ranges
- Missing server-side validation when client-side checks exist
- No separation between admin and user functionality paths
- Features added without documented security consideration

---

## A07: Authentication Failures

**Ranking:** #7 (unchanged). 36 CWEs mapped.
**Key CWEs:** CWE-259 (Hard-coded Password), CWE-287 (Improper Authentication),
CWE-384 (Session Fixation), CWE-798 (Hard-coded Credentials).

### What It Is

Weaknesses in confirming a user's identity or managing sessions. This allows attackers to
impersonate users, steal sessions, or bypass authentication entirely.

### Common Vulnerabilities

- Permitting credential stuffing and brute-force attacks (no rate limiting, no lockout)
- Using default, weak, or well-known passwords
- Weak or ineffective password recovery processes
- Storing passwords in plaintext or with weak hashing
- Missing or broken multi-factor authentication
- Exposing session identifiers in URLs
- Not rotating session IDs after login
- Not properly invalidating sessions on logout or timeout
- Hard-coded credentials in application code or configuration

### Prevention

- **Implement multi-factor authentication** to prevent credential stuffing and brute force.
- **Don't ship default credentials.** Especially not for admin accounts.
- **Check passwords against breach lists** (e.g., haveibeenpwned's list of known breached
  passwords).
- **Enforce password complexity** and length requirements (NIST 800-63b: minimum 8 chars,
  maximum 128+, no composition rules, check against breach lists).
- **Rate-limit login attempts.** Use progressive delays or temporary lockouts.
- **Use a server-side, secure session manager.** Generate high-entropy, random session IDs.
  Don't put session IDs in URLs.
- **Rotate session IDs on authentication state changes** (login, privilege escalation).
- **Invalidate sessions** on logout, idle timeout, and absolute timeout.

### Code Review Patterns

Look for:
- Missing rate limiting on authentication endpoints
- Passwords stored with insufficient hashing (plain SHA/MD5, missing salt)
- Session tokens in URLs or exposed in logs
- Missing session invalidation on logout
- Hard-coded credentials or API keys
- Password reset flows that leak information (e.g., "user not found" vs. "incorrect password")
- Missing CSRF protection on authentication state-change operations

---

## A08: Software or Data Integrity Failures

**Ranking:** #8 (unchanged from 2021).

### What It Is

Code and infrastructure that fails to protect against integrity violations. This covers assumptions
made about software updates, CI/CD pipelines, and critical data without verifying their integrity.
Unlike A03 (supply chain), this focuses on integrity failures within **your** environment — even
when the upstream supply chain is intact.

### Common Vulnerabilities

- Insecure deserialization (untrusted data deserialized into objects → RCE)
- Auto-updates downloaded without signature verification
- Loading functionality from untrusted CDNs or third-party scripts without SRI
  (Subresource Integrity)
- CI/CD pipelines without integrity controls on artifacts
- Unverified config or data from untrusted sources treated as trusted
- Mass assignment / object modification through uncontrolled property binding

### Prevention

- **Use digital signatures** to verify software, updates, and data originate from expected sources.
- **Verify integrity of dependencies** using checksums and Subresource Integrity (SRI) for
  browser-loaded resources.
- **Restrict deserialization.** Accept serialized data only from trusted sources. Use allowlists
  for permitted classes. Consider using simpler data formats (JSON) instead.
- **Enforce CI/CD pipeline integrity.** Proper segregation, access control, and configuration.
  Sign build artifacts.
- **Validate data integrity** for critical operations. Don't trust client-provided data for
  business-critical decisions.
- **Use integrity monitoring** for critical files and configurations.

### Code Review Patterns

Look for:
- Deserialization of untrusted input (Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`)
- CDN-loaded scripts without `integrity` attributes
- Update mechanisms without signature verification
- Mass assignment vulnerabilities (`@ModelAttribute` in Spring, `attr_accessible` in Rails)
- CI/CD configs that pull from unverified sources or run unreviewed scripts

---

## A09: Security Logging & Alerting Failures

**Ranking:** #9 (unchanged, renamed from "Logging and Monitoring Failures"). 5 CWEs mapped.

### What It Is

Without logging and monitoring, attacks cannot be detected. Without alerting, no one responds.
This category highlights that logging alone is insufficient — active alerting and response
capabilities are required. Breaches that go undetected for months cause dramatically more damage.

### Common Vulnerabilities

- Login failures, access control failures, and input validation failures not logged
- Logs not generating sufficient detail for forensic analysis
- Logs only stored locally (lost if system is compromised)
- No alerting thresholds or escalation processes
- Logging sensitive data (passwords, tokens, PII) in log entries
- Application logs vulnerable to injection attacks
- Penetration testing and DAST scans not triggering alerts

### Prevention

- **Log all security-relevant events.** Login attempts (success and failure), access control
  failures, input validation failures, authentication state changes.
- **Use a standardized log format** consumed by your log management solution.
- **Protect log integrity.** Append-only storage. Prevent log injection by encoding or validating
  log data.
- **Ensure logs are sufficient for forensics.** Include user context, timestamp, IP, action, and
  outcome.
- **Don't log sensitive data.** Mask or exclude passwords, tokens, credit card numbers, PII.
- **Establish alerting.** Define thresholds for suspicious activity (e.g., repeated login failures,
  access control violations from same IP).
- **Create an incident response plan** that uses these alerts.
- **Send logs to centralized, tamper-resistant storage** (SIEM, log aggregation service).

### Code Review Patterns

Look for:
- Security-relevant operations with no logging (auth, access control, admin actions)
- Sensitive data in log statements (passwords, tokens, full credit card numbers)
- Log injection vulnerabilities (user input written directly into log messages)
- Catch blocks that swallow exceptions silently
- Missing correlation IDs for request tracing across services

---

## A10: Mishandling of Exceptional Conditions

**Ranking:** #10 (**new in 2025**, replaces SSRF which was merged into A01).

### What It Is

Programs that fail to prevent, detect, and respond to unusual or unexpected conditions. The central
risk is **failing open** — when a system encounters an error and defaults to granting access or
skipping security checks instead of denying access safely. This also covers unhandled exceptions
that crash systems, expose internal state, or create exploitable conditions.

### Common Vulnerabilities

- Access control checks that default to "allow" when an exception occurs
- Database errors during authorization that result in granting access
- Unhandled exceptions that expose stack traces, internal paths, or configuration details
- Error conditions that skip validation or security checks
- Using generic exception handlers that mask security-critical failures
- Missing timeout handling leading to resource exhaustion
- Catch-all exception handlers that log and continue instead of failing safely
- Race conditions in error paths that leave system in inconsistent state

### Prevention

- **Fail closed, always.** If an error occurs during a security check, deny access. Never default
  to "allow" on error.
- **Catch exceptions specifically.** Generic `catch (Exception e)` blocks hide critical failures.
  Handle specific exception types with appropriate responses.
- **Don't expose internal details in errors.** Return generic error messages to users. Log the
  full details server-side.
- **Test error paths explicitly.** Include negative testing, fuzzing, and chaos engineering.
  Your error handling code is only as reliable as your testing of it.
- **Handle resource exhaustion gracefully.** Set timeouts on all external calls. Implement circuit
  breakers. Define what happens when a service is unavailable.
- **Validate that security controls work under error conditions.** If the database is down, does
  your auth system deny access or grant it?
- **Use structured error handling patterns.** Result types, Option/Maybe monads, or explicit error
  returns rather than exceptions where language/framework supports it.

### Code Review Patterns

Look for:
- Catch blocks that return success or default-allow on error
- Empty catch blocks or catch blocks that only log and continue
- Generic exception handlers (`catch (Exception e)`) around security-critical code
- Missing timeout configuration on HTTP clients, database connections, external service calls
- Error responses that include stack traces, SQL errors, or internal paths
- Authorization code without explicit handling of the "check failed due to error" case
- Missing null checks or optional handling that could skip security logic

---

## Cross-Cutting Concerns

Several themes span multiple categories. When reviewing code or designing systems, consider these
holistic patterns:

**Input validation** → A01, A05, A08, A10
Validate all input server-side. Use allowlists. Reject invalid input rather than sanitizing.

**Secure defaults** → A01, A02, A07, A10
Deny by default. Fail closed. Require explicit opt-in for access, features, and permissions.

**Defense in depth** → All categories
No single control should be the only protection. Layer controls at network, application, and data
levels.

**Least privilege** → A01, A02, A03, A06
Every user, process, and service account should have the minimum permissions needed.

**Automation** → A02, A03, A09
Automate security checks: configuration verification, dependency scanning, log monitoring, and
alerting. Manual processes don't scale and drift over time.
