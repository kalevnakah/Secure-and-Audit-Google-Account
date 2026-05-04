# Google Workspace Compromised Account Response & Audit

This utility provides an automated, structured approach to locking down a compromised Google Workspace account and gathering a comprehensive forensic audit. It relies heavily on [GAM](https://github.com/GAM-team/GAM) to execute actions against the Google Workspace Admin APIs.

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
* **Advanced Logging Restrictions:** Some API endpoints queried by this script (like the Drive Activity API v2, Chrome Browser Logs, and Workspace Studio logs) require premium editions such as **Enterprise Standard/Plus** or **Education Standard/Plus**. If a tier restriction is hit (e.g., Drive Activity returns a 73 error), the script will gracefully handle the error and notify you in the resulting Excel sheet.

---

## ⚙️ Configuration (Global Variables)

You can customize the script's behavior by modifying the variables at the top of `SecureAndAuditUser.py`:

* `GAM_CMD` *(default: "gam")*: The command used to invoke GAM. Change this if your executable is named differently (e.g., `gamadv-xtd3`) or if you need to provide a full absolute path.
* `AUDIT_DAYS_BACK` *(default: 30)*: The number of days into the past to query for log events. Increasing this significantly will increase the time it takes to generate the report.
* `REPORT_TIMEZONE` *(default: "-06:00")*: The target time zone for timestamp conversion in the Excel file. You can use a standard UTC offset (`-06:00`, `+01:00`) or an IANA name (`America/Chicago`, `Europe/London`) which automatically accounts for Daylight Saving Time.

---

## 🛡️ Execution Phases & Red Flags Guide

The script runs in three distinct phases. Below is a summary of the GAM commands executed, their purpose, and what security analysts should look for in the output.

### Phase 1: Immediate Containment
**Purpose:** Immediately cut off attacker access and reset all authentication tokens to secure the account.
* **Backup Codes** (`gam user <email> update backupcodes`): Invalidates existing offline backup codes.
* **Suspend / Reset** (`gam update user <email> suspended on`, `password <pwd>`): Halts activity and sets a randomized 16-character secure password.
* **Cookie Reset** (`gam user <email> signout`): Invalidates active web sessions.
* **OAuth Tokens** (`gam user <email> print/delete tokens`): Revokes third-party app access.
* **App Passwords** (`gam user <email> print/delete asps`): Removes legacy protocol passwords (often abused by attackers).

🚨 **Red Flags to Look For:**
* Review the `OAuth_Tokens_Before_Revoke` tab for suspicious, highly privileged third-party apps (e.g., generic names like "Email App" with full Gmail read/write scope).
* Review `App_Passwords_Before_Revoke`. The presence of active App Passwords might indicate how the attacker bypassed Multi-Factor Authentication (MFA) via legacy IMAP protocols.

### Phase 2: Forensic Audit Logs
**Purpose:** Collect deep telemetry on what the attacker did while they had access.

#### 1. Persistence & Backdoors
* **Commands:** Queries for Email Filters, Forwarding Addresses, Delegates, and Recovery Info.
* 🚨 **Red Flags:**
  * **Filters:** Look for rules automatically moving emails containing "invoice", "wire transfer", or "hacked" to the Trash/Archive to hide them from the user.
  * **Forwarding/Delegates:** Look for unknown external email addresses set to receive copies of the user's mail.
  * **Recovery Info:** Look for a replaced secondary email or phone number; attackers do this to easily regain access via self-service password reset.

#### 2. Authentication & Logins
* **Commands:** Queries the Admin Login audit log (`gam report logins`).
* 🚨 **Red Flags:** 
  * Look for logins originating from suspicious geographic locations, VPN/Tor exit nodes, or unusual hours of the day for that specific user.

#### 3. Data Exfiltration
* **Commands:** Queries Drive Audit Logs, Drive Activity, Drive External Sharing, and Takeout Logs.
* 🚨 **Red Flags:**
  * **Takeout:** Any record in the `Takeout_Audit` tab is a massive red flag indicating the attacker downloaded an archive of the user's entire Workspace data.
  * **Drive Downloads:** Look for mass download events of sensitive files (HR records, financial documents).
  * **External Sharing:** Look for proprietary internal files whose visibility was recently changed to "Shared Externally" or shared directly to an attacker-controlled Gmail address.

#### 4. Email Abuse & Phishing
* **Commands:** Queries Sent Messages, Drafts, and Gmail Log Events.
* 🚨 **Red Flags:**
  * Review `Sent_Messages` and `Scheduled_Draft_Messages` for generic phishing templates (e.g., "Urgent: Document Shared with You") being prepared or sent to the user's contact book or external targets.
  * High volume of outbound emails in a short time frame within the `Gmail_Log_Events`.

#### 5. Educational Ecosystem & Admin Events
* **Commands:** Queries Classroom logs, Group Membership changes, and Admin privilege escalations.
* 🚨 **Red Flags:**
  * A user suddenly being granted Super Admin or Help Desk privileges in the `Admin_Privilege_Audit` tab.
  * The attacker adding external addresses to internal communication groups in `Groups_Audit`.

### Phase 3: Evidence Preservation
**Purpose:** Guarantee that log data and user content cannot be purged, even if the user attempts to empty their trash.
* **Google Vault Holds** (`gam create vaultmatter`, `gam create vaulthold`): Creates a specific Vault Matter for the compromise and places an immediate legal hold on the user's Gmail, Drive, and Chat data.

🚨 **Important Note:** Vault hold propagation can take a short amount of time. If the script fails to create the hold automatically, ensure you log into `vault.google.com` to apply it manually.

---

## 🚀 Usage

Run the script via your terminal:
```bash
python SecureAndAuditUser.py
```
1. You will be prompted for the target user's email address.
2. You will be prompted to choose between full containment (`y`) or audit-only (`n`).
3. Once complete, an Excel spreadsheet named `Audit_<user>_<timestamp>.xlsx` will be generated in your current directory containing all retrieved logs.