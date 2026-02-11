---
name: npm-package-reviewer
description: "Automatically reviews npm packages for security, maintenance, and trust signals before installation. Triggers on npm install, yarn add, and pnpm add commands."
---

# npm Package Reviewer

## Overview

Review npm packages for security and trustworthiness **before** installing them. This skill automatically triggers whenever you are about to run a package install command, queries public security APIs, and presents a GO / CAUTION / STOP recommendation.

## When to Activate

**MUST activate** before executing any of these commands:
- `npm install <package>` / `npm i <package>`
- `npm install --save-dev <package>`
- `yarn add <package>`
- `pnpm add <package>`
- `npx <package>` (when package is not already installed)

**Do NOT activate** for:
- `npm install` (no package argument — just installs from lockfile)
- `npm update` (updates existing packages)
- Packages already reviewed in the current session

## The Process

### Step 1: Extract Package Names

Parse the install command to identify all package names being installed. Handle:
- Simple names: `express`, `lodash`
- Scoped packages: `@types/node`, `@babel/core`
- Versioned: `express@4.18.2` — extract name and version separately
- Multiple packages: review each one

### Step 2: Run the Review Script

For each package, run:

```bash
bash "${SKILL_DIR}/scripts/review-package.sh" <package-name> [version]
```

Where `${SKILL_DIR}` is the directory containing this `SKILL.md` file. The script queries:
- **deps.dev** (Google) — known vulnerabilities, OpenSSF Scorecard
- **npm registry** — maintainers, install scripts, publish dates, repository
- **npm downloads API** — weekly download counts

### Step 3: Present Findings

Present a concise summary to the user based on the script output:

**For 🟢 GO:**
> ✅ `express@4.21.0` — No issues found. 12M weekly downloads, 5 maintainers, no vulnerabilities. Installing.

Then proceed with the install.

**For 🟡 CAUTION:**
> ⚠️ `some-package@1.0.0` — Minor concerns:
> - Single maintainer
> - 800 weekly downloads
>
> Proceed with install?

Wait for user confirmation before installing.

**For 🔴 STOP:**
> 🚫 `risky-pkg@2.0.0` — Critical issues found:
> - 2 known vulnerabilities (CVE-2024-XXXX)
> - Has postinstall script
>
> **Not recommended.** Want me to find an alternative, install anyway, or skip?

Do NOT install. Ask the user what to do.

### Step 4: Handle Multiple Packages

When a command installs multiple packages (e.g., `npm install express lodash moment`):
1. Review all packages (run the script for each)
2. Present a combined summary
3. If any package is STOP, flag it individually — don't block the safe ones
4. Suggest installing safe packages and skipping problematic ones

## Red Flags Reference

### Critical (→ STOP)
- Known CVE vulnerabilities from deps.dev
- Install scripts detected (preinstall/postinstall) — common malware vector
- Extremely low downloads (< 100/week) — likely typosquat or malicious
- No maintainers listed

### Warning (→ CAUTION)
- Single maintainer (bus factor risk)
- Low downloads (< 1,000/week)
- Last published > 2 years ago (possibly abandoned)
- No repository URL (can't audit source)
- Unusual or missing license
- Very new package (< 30 days old)
- High dependency count (> 50 — larger attack surface)
- Low OpenSSF Scorecard (< 4/10)
- deps.dev data unavailable (can't verify vulnerabilities)

### Clean (→ GO)
- No vulnerabilities
- Healthy download numbers
- Multiple maintainers
- Active maintenance (published within last year)
- Known permissive license (MIT, ISC, Apache-2.0, etc.)
- Source repository available

## Edge Cases

- **Package not found**: The script handles this — report to user that the package doesn't exist on npm
- **API timeout**: The script has 10s timeouts — if APIs are down, warn the user that security checks were incomplete
- **Private registry packages**: The script only checks public npm — note this limitation if the project uses a private registry
- **Already installed packages**: Skip review if the package is already in node_modules at the same version

## Key Principle

**Never install a 🔴 STOP package without explicit user approval.** The user's security is more important than convenience.
