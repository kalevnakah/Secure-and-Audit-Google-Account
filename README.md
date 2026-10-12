# Google Workspace Compromised Account Response & Audit

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-brightgreen.svg)
![GAM](https://img.shields.io/badge/GAM-7.0+%20|%20GAMADV--XTD3-orange.svg)

This suite provides an automated, structured approach to locking down a compromised Google Workspace account and gathering a comprehensive forensic audit. It relies heavily on [GAM](https://github.com/GAM-team/GAM) to execute actions against the Google Workspace Admin APIs.

---

## 🚀 What's New in v2.0.0

* **Dedicated Attachment Audit (`Attachments_Accessed`):** New forensic tab capturing all attachment downloads (Event 17), saves to Google Drive (Event 18), and link preview clicks (Event 16) with timestamp, message subject, and client IP address.
* **Human-Readable Action Decoder:** Gmail log events automatically decode numeric event IDs (`mail_event_type_id`) into plain-English descriptions (`mail_event_action`) right next to the ID column in `Gmail_Log_Events` and `Attachments_Accessed`.
* **Hardened Containment Order:** Credentials and authorizations are revoked *before* account suspension, eliminating "User is suspended" API barriers during remediation.
* **Intelligent Vault Hold Propagation:** Actively polls Google Vault's API index until new matters are verified before applying holds, preventing eventual-consistency failures.
* **Pre-flight Account Check:** Validates target user existence before running containment actions or forensic queries.
* **Excel Engine & Data Hardening:** Auto-formats sheets with bold headers, frozen panes (`A2`), auto-padded column widths, sheet name sanitization, and safeguards against cell character limits and large JSON payloads.
* **Phishing Remediation Companion Tool:** Bundles `Remove-MaliciousEmail.py` for domain-wide removal of malicious emails by Message-ID.

---

## 📦 Prerequisites and Dependencies

### Python Dependencies
This script requires Python 3.9 or higher. 
The following external Python libraries must be installed:
* `openpyxl`: Used to generate the consolidated multi-tab Excel spreadsheet (`.xlsx`).
* `tzdata` (Windows Only): Provides IANA time zone database support for accurate timestamp conversion.

Install dependencies via pip:
```bash
pip install openpyxl tzdata
```

### Supported GAM Version
* **GAM 7.0+** or **GAMADV-XTD3**: The script leverages advanced report parameters and output formats standard in modern GAM releases. Ensure GAM is installed, authorized with Domain-Wide Delegation, and accessible in your system's PATH.

### Supported Google Workspace Subscriptions
* **Base Compatibility:** The core containment steps (password reset, cookie reset, basic audits) work across *all* Google Workspace editions (Business Starter, Education Fundamentals, etc.).
* **Advanced Logging Restrictions:** Some API endpoints queried by this script (like the Drive Activity API v2, Chrome Browser Logs, and Workspace Studio logs) require premium editions such as **Enterprise Standard/Plus** or **Education Standard/Plus**. If a tier restriction is hit (e.g., Drive Activity returns a 73 error), the script gracefully logs an explanatory notice in the resulting Excel sheet.

---

## ⚙️ Configuration (Global Variables)

You can customize the script's behavior by modifying the variables at the top of `SecureAndAuditGoogleUser.py`:

* `GAM_CMD` *(default: "gam")*: The command used to invoke GAM. Change this if your executable is named differently (e.g., `gamadv-xtd3`) or if you need to provide a full absolute path.
* `AUDIT_DAYS_BACK` *(default: 30)*: The number of days into the past to query for log events. Increasing this significantly will increase the time it takes to generate the report.
* `REPORT_TIMEZONE` *(default: "-06:00")*: The target time zone for timestamp conversion in the Excel file. You can use a standard UTC offset (`-06:00`, `+01:00`) or an IANA name (`America/Chicago`, `Europe/London`) which automatically accounts for Daylight Saving Time.

---

## 🛡️ Execution Phases & Red Flags Guide

The script runs in three distinct phases:

### Phase 1: Immediate Containment
**Purpose:** Immediately cut off attacker access and reset all authentication tokens to secure the account.
1. **Backup Codes** (`gam user <email> print/update backupcodes`): Audits existing offline codes to Excel, then invalidates and rotates them.
2. **App Passwords** (`gam user <email> print/delete asps all`): Audits and revokes legacy protocol passwords often abused to bypass MFA.
3. **OAuth Tokens** (`gam user <email> print/delete tokens clientid <id>`): Audits and revokes third-party app authorizations individually.
4. **Password Reset** (`gam update user <email> password <pwd> changepassword on`): Sets a randomized 16-character complex password and forces change on next login.
5. **Session Invalidation** (`gam user <email> signout`): Invalidates all active web and device sessions.
6. **2-Step Verification** (`gam user <email> turnoff2sv`): *(Optional)* Clears attacker-registered physical keys/prompts if 2SV is not domain-enforced.
7. **Suspend Account** (`gam update user <email> suspended on`): Halts all access as the final containment step.

🚨 **Red Flags to Look For:**
* **`OAuth_Tokens_Before_Revoke`:** Look for suspicious, highly privileged third-party apps (e.g., generic names like "Email App" with full Gmail read/write scope).
* **`App_Passwords_Before_Revoke`:** The presence of active App Passwords often indicates how an attacker bypassed Multi-Factor Authentication via legacy IMAP/SMTP protocols.

---

### Phase 2: Forensic Audit Logs
**Purpose:** Collect deep telemetry on what the attacker did while they had access.

#### 1. Email & Attachment Telemetry
* **`Attachments_Accessed`:** Queries attachment downloads (Event 17), Drive saves (Event 18), and preview clicks (Event 16). Cross-reference the logged client IP with the attacker's IP to confirm which attachments were exfiltrated.
* **`Gmail_Log_Events`:** Queries message delivery and transit events, automatically augmented with a plain-English `mail_event_action` column.
* **`Sent_Messages` & `Scheduled_Draft_Messages`:** Review outbound mail and drafts for generic phishing templates prepared or distributed by the attacker.
* **`Gmail_Filters`, `Gmail_Forwarding`, `Gmail_Delegates`:** Look for covert exfiltration or hiding rules (e.g., forwarding copies externally, or filtering emails with words like "invoice" or "security" directly to Trash).

#### 2. Authentication & Logins
* **`Login_Audit`:** Queries Admin login logs (`gam report logins`). Look for logins from unfamiliar geographic regions, Tor/VPN exit nodes, or anomalous hours.

#### 3. Data Exfiltration & Drive Activity
* **`Drive_Audit_Log` & `Drive_Downloads`:** Identifies mass downloads, syncing, or file revisions.
* **`Drive_External_Sharing`:** Highlights sensitive internal documents whose access was changed to "Shared Externally" or granted directly to an external address.
* **`Takeout_Audit`:** Any entry here indicates Google Takeout was requested to dump the user's entire mailbox and Drive data.

#### 4. Educational Ecosystem & Permissions
* **`Classroom_Audit` & `Classroom_State_Change`:** Course un-enrollments or archived courses.
* **`Groups_Audit`:** Attacker adding external emails to internal Google Groups.
* **`Admin_Privilege_Audit`:** Privilege escalation events (e.g. user granted Super Admin rights).
* **`Workspace_Studio_Audit`:** Unauthorized automation flows or AppSheet actions.
* **`Recovery_Info`:** Backdoor secondary emails or phone numbers configured to maintain persistence.

---

### Phase 3: Evidence Preservation (Google Vault)
**Purpose:** Guarantee that log data and user content cannot be purged, even if an attacker or user empties trash.
* **Google Vault Holds** (`gam create vaultmatter`, `gam create vaulthold`): Creates an incident-specific Vault Matter (`Account_Compromise_<email>_<timestamp>`) and applies legal holds across **Gmail**, **Google Drive**, and **Google Chat** (`hangouts_chat`).
* **Active Verification:** The script verifies the matter's active status via `gam info vaultmatter` before applying holds to prevent propagation delays.

---

## 🛠️ Companion Tool: `Remove-MaliciousEmail.py`

This repository includes a dedicated incident response utility for bulk-purging phishing or malicious emails domain-wide:

```bash
python Remove-MaliciousEmail.py
```
* **Message-ID Targeting:** Targets emails via RFC 822 Message-ID (`rfc822msgid:<ID>`).
* **Dry-Run Simulation:** Simulates mailbox search across all users to preview impact before deletion.
* **Confirmed Live Mode:** Permanently purges malicious messages from all user mailboxes with explicit confirmation safeguards.

---

## 🚀 Usage

Run the primary lockdown and audit script:
```bash
python SecureAndAuditGoogleUser.py
```
1. Enter the target user's email address (the script will verify the user exists in Google Workspace).
2. Choose between full containment (`y`) or audit-only (`n`).
3. Once complete, an Excel spreadsheet named `Audit_<user>_<timestamp>.xlsx` with up to 28 formatted forensic tabs will be generated in your current directory.

---

## 📝 Changelog

### v2.0.0
* **Added:** `Attachments_Accessed` tab filtering Gmail event types 16, 17, and 18 (attachment downloads, saves to Drive, preview clicks).
* **Added:** Human-readable action translator (`GMAIL_EVENT_MAP` & `enrich_gmail_log_events`) inserting `mail_event_action` next to `mail_event_type_id`.
* **Added:** Companion script `Remove-MaliciousEmail.py` for domain-wide phishing remediation.
* **Improved:** Containment order reversed to revoke tokens/passwords/sessions *before* suspending account.
* **Fixed:** `delete asps` syntax updated to include required `all` argument.
* **Fixed:** `delete tokens` updated to individually iterate and revoke all active OAuth client IDs.
* **Fixed:** Vault hold propagation race condition resolved via active `gam info vaultmatter` polling.
* **Fixed:** Vault chat corpus updated to standard `hangouts_chat`.
* **Fixed:** Workspace Studio report query updated to omit invalid `edit_flow` event.
* **Fixed:** Standardized `start` parameter across all 25 audit tasks to ensure strict adherence to `AUDIT_DAYS_BACK`.
* **Hardened:** Pre-flight account check, Excel cell character truncation, sheet name sanitization, and large CSV field size limits.

### v1.0.0
* Initial release of automated compromised account response script and forensic audit reporting.