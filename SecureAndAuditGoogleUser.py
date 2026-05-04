import subprocess
import sys
import string
import secrets
import re
import csv
import io
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    from openpyxl import Workbook
except ImportError:
    print("ERROR: The 'openpyxl' library is required to create Excel files.")
    print("Please install it by running: pip install openpyxl")
    sys.exit(1)

# --- Configuration ---
# The path to your GAM executable. Default is 'gam' assuming it is in your system PATH.
GAM_CMD = "gam"
# Number of days to look back for the audit logs
AUDIT_DAYS_BACK = 30
# The target timezone for timestamps in the report.
# You can use a standard UTC offset like '-06:00' (for CST), '-05:00' (EST), '+01:00' (CET), etc.
# Alternatively, use an IANA Time Zone name which automatically handles Daylight Saving Time.
# Common IANA examples: 'America/New_York', 'America/Chicago', 'America/Denver', 
# 'America/Los_Angeles', 'Europe/London', 'Asia/Tokyo', 'UTC'.
REPORT_TIMEZONE = "-06:00"
# --- End of Configuration ---

def parse_timezone(tz_str):
    """Parses a timezone string into a tzinfo object (IANA or UTC offset)."""
    match = re.match(r'^([+-])(\d{1,2}):(\d{2})$', tz_str.strip())
    if match:
        sign = 1 if match.group(1) == '+' else -1
        hours, minutes = int(match.group(2)), int(match.group(3))
        return timezone(timedelta(hours=sign * hours, minutes=sign * minutes))
    return ZoneInfo(tz_str.strip())

# Validate and set target timezone
try:
    TARGET_TZ = parse_timezone(REPORT_TIMEZONE)
except ZoneInfoNotFoundError:
    print(f"ERROR: Timezone '{REPORT_TIMEZONE}' not found.")
    print("On Windows, the 'tzdata' package is required for IANA timezone support.")
    print("Please install it by running: pip install tzdata")
    print("Alternatively, use a standard UTC offset like '-06:00'.")
    sys.exit(1)

# Regex to detect ISO 8601 timestamp strings commonly output by Google Workspace APIs
# Examples: "2026-04-30T08:51:32.000Z", "2026-04-30 08:51:32-06:00"
ISO8601_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$')

def add_to_excel(wb, sheet_name, data_string):
    """Parses a CSV string and adds it to a new sheet in the workbook."""
    # Ensure sheet name is 31 chars or less
    sheet_name = sheet_name[:31]
    
    # Handle duplicates just in case
    base_name = sheet_name
    counter = 1
    while sheet_name in wb.sheetnames:
        sheet_name = f"{base_name[:28]}_{counter}"
        counter += 1
        
    ws = wb.create_sheet(title=sheet_name)
    
    if not data_string or not data_string.strip():
        ws.append(["No results found."])
        return

    # Parse CSV data
    reader = csv.reader(io.StringIO(data_string))
    for row in reader:
        new_row = []
        for cell in row:
            if cell and ISO8601_REGEX.match(cell):
                try:
                    dt = datetime.fromisoformat(cell.replace('Z', '+00:00'))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    new_row.append(dt.astimezone(TARGET_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'))
                except Exception:
                    new_row.append(cell)
            else:
                new_row.append(cell)
        ws.append(new_row)

def generate_secure_password(length=16):
    """Generates a secure, random password for the account reset."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3):
            break
    return password

def run_gam_command(command, wb=None, sheet_name=None):
    """Executes a GAM command. Captures output to an Excel sheet if specified."""
    full_command = [GAM_CMD] + command
    print(f"Executing: {' '.join(full_command)}")
    try:
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        if wb and sheet_name and result.stdout:
            add_to_excel(wb, sheet_name, result.stdout)
            print(f"  -> Saved output to sheet '{sheet_name[:31]}'")
        return result.stdout
    except FileNotFoundError:
        print(f"ERROR: '{GAM_CMD}' command not found. Ensure GAM is installed and in your PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        # GAM returns exit code 10 when check serviceaccount fails some scopes
        if e.returncode == 10:
            print("  -> WARNING: Some service account scopes failed validation (Exit Code 10).")
            if wb and sheet_name and e.stdout:
                add_to_excel(wb, sheet_name, e.stdout)
                print(f"  -> Saved output to sheet '{sheet_name[:31]}'")
            return e.stdout
        # GAM returns exit code 60 when a query succeeds but finds 0 items
        if e.returncode == 60:
            print("  -> No results found (0 items).")
            if wb and sheet_name:
                add_to_excel(wb, sheet_name, "No results found.\n")
            return None
        # Catch specific error for Drive Activity API authorization issues
        if e.returncode == 73 and 'Drive Activity API v2 Service/App not enabled' in e.stderr:
            message = "-> The 'Drive Activity API v2' is restricted by Google and not available on the Education Fundamentals edition (use 'gam report drive' instead). If you are on a premium tier, please verify your Drive SDK Admin permissions, ensure the API is enabled in your Google Cloud Project, and check GAM's Domain-Wide Delegation scopes (run 'gam update project')."
            print(f"  {message}")
            if wb and sheet_name:
                add_to_excel(wb, sheet_name, f"{message}\n")
            return None
        print(f"  -> WARNING: Command failed with exit code {e.returncode}.")
        print(f"  -> Stderr: {e.stderr.strip()}")
        return None

def main():
    print("=====================================================")
    print("   Google Workspace - Compromised Account Response   ")
    print("=====================================================\n")
    
    target_email = input("Enter the email address of the compromised user: ").strip().lower()
    if not target_email:
        print("Email address cannot be empty. Exiting.")
        return

    # Setup dates for audit
    target_tz = TARGET_TZ
    end_date = datetime.now(target_tz)
    start_date = end_date - timedelta(days=AUDIT_DAYS_BACK)
    
    # GAM API parameters generally expect UTC for precise datetime boundaries
    iso_start = start_date.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    date_start = start_date.strftime("%Y-%m-%d")
    date_start_slash = start_date.strftime("%Y/%m/%d")

    timestamp = end_date.strftime("%Y%m%d_%H%M%S")
    audit_file = f"Audit_{target_email}_{timestamp}.xlsx"

    # Initialize the Excel workbook
    wb = Workbook()
    wb.remove(wb.active)  # Remove the default sheet

    print(f"\n[PHASE 1: IMMEDIATE CONTAINMENT]")
    do_lockdown = input(f"Do you want to perform immediate lockdown/containment on {target_email}? (y/n - 'n' will skip to audit only): ").lower().strip()

    if do_lockdown == 'y':
        # 1. Rotate Backup Codes
        print("\n--- Rotating Backup Codes ---")
        run_gam_command(["user", target_email, "update", "backupcodes"])

        # 2. Suspend Account
        print("\n--- Suspending Account ---")
        run_gam_command(["update", "user", target_email, "suspended", "on"])

        # 3. Reset Password
        print("\n--- Resetting Password ---")
        new_password = generate_secure_password()
        run_gam_command(["update", "user", target_email, "password", new_password, "changepassword", "on"])
        print(f"  -> New temporary password set to: {new_password}")
        print("  -> (User will be forced to change this on next login)")

        # 4. Reset Cookies
        print("\n--- Resetting Sign-in Cookies ---")
        run_gam_command(["user", target_email, "signout"])

        # 5. Revoke OAuth Tokens
        print("\n--- Auditing and Revoking OAuth Tokens ---")
        tokens_out = run_gam_command(["user", target_email, "print", "tokens"], wb=wb, sheet_name="OAuth_Tokens_Before_Revoke")
        
        # Parse the tokens from the CSV and loop through to delete them
        try:
            if tokens_out:
                reader = csv.DictReader(io.StringIO(tokens_out))
                for row in reader:
                    client_id = row.get('clientId')
                    if client_id:
                        print(f"  -> Revoking token for Client ID: {client_id}")
                        run_gam_command(["user", target_email, "delete", "tokens", "clientid", client_id])
        except csv.Error as e:
            print(f"  -> WARNING: Failed to parse tokens CSV: {e}")
        except Exception as e:
            print(f"  -> WARNING: Failed to revoke tokens: {e}")

        # 6. Remove App Passwords
        print("\n--- Removing App Passwords ---")
        run_gam_command(["user", target_email, "print", "asps"], wb=wb, sheet_name="App_Passwords_Before_Revoke")
        run_gam_command(["user", target_email, "delete", "asps", "all"])

    else:
        print("\n--- Skipping Immediate Containment ---")
        print("\n--- Auditing OAuth Tokens ---")
        run_gam_command(["user", target_email, "print", "tokens"], wb=wb, sheet_name="OAuth_Tokens_Audit")

    # Audit Recovery Info (Check for backdoors)
    print("\n--- Auditing Recovery Info ---")
    run_gam_command(["print", "users", "query", f"email:{target_email}", "fields", "primaryEmail,recoveryEmail,recoveryPhone"], wb=wb, sheet_name="Recovery_Info")

    print(f"\n[PHASE 2: FORENSIC AUDIT]")
    print(f"Gathering logs for the past {AUDIT_DAYS_BACK} days (since {date_start})...")
    print(f"All audit data will be saved to '{audit_file}'.")

    # List of tuples: (Description, GAM Command List, Excel Sheet Name)
    audit_tasks = [
        ("Login Logs", ["report", "logins", "user", target_email, "start", iso_start], "Login_Audit"),
        ("Chrome Browser Logs", ["report", "chrome", "user", target_email, "start", date_start], "Chrome_Browser_Audit"),
        ("Gmail Filters", ["user", target_email, "print", "filters"], "Gmail_Filters"),
        ("Changed Gmail Settings (Admin Logs)", ["report", "admin", "user", target_email, "event", "change_gmail_setting", "start", date_start], "Changed_Gmail_Settings"),
        ("Changed Gmail Settings Targeting User", ["report", "admin", "event", "change_gmail_setting", "filters", f"USER_EMAIL=={target_email}", "start", date_start], "Changed_Gmail_Tgt"),
        ("Gmail Forwarding Addresses", ["user", target_email, "print", "forwardingaddresses"], "Gmail_Forwarding"),
        ("Gmail Delegates", ["user", target_email, "print", "delegates"], "Gmail_Delegates"),
        ("Sent Mail (Phishing Check)", ["user", target_email, "print", "messages", "query", f"in:sent after:{date_start_slash}"], "Sent_Messages"),
        ("Scheduled and Draft Mail", ["user", target_email, "print", "messages", "query", "in:scheduled OR in:draft"], "Scheduled_Draft_Messages"),
        ("Gmail Log Events (Email Trace)", ["report", "gmail", "user", target_email, "start", date_start], "Gmail_Log_Events"),
        ("IMAP Settings", ["user", target_email, "print", "imap"], "IMAP_Settings"),
        ("POP Settings", ["user", target_email, "print", "pop"], "POP_Settings"),
        ("Drive Activity", ["user", target_email, "print", "driveactivity", "starttime", iso_start], "Drive_Activity"),
        ("General Drive Audit Logs", ["report", "drive", "user", target_email, "start", date_start], "Drive_Audit_Log"),
        ("Drive Downloads and Desktop Syncs", ["report", "drive", "user", target_email, "event", "download,sync_item_content", "start", date_start], "Drive_Downloads"),
        ("External Drive Sharing", ["report", "drive", "user", target_email, "filters", "visibility==shared_externally"], "Drive_External_Sharing"),
        ("Drive File Locks (Checkouts)", ["report", "drive", "user", target_email, "event", "add_lock,remove_lock", "start", date_start], "Drive_Locks"),
        ("Classroom Activity", ["report", "classroom", "user", target_email, "event", "user_removed_from_course"], "Classroom_Audit"),
        ("Classroom State Changes", ["report", "classroom", "user", target_email, "event", "archived_course,deleted_course", "start", date_start], "Classroom_State_Change"),
        ("Group Membership Changes", ["report", "groups_enterprise", "user", target_email, "event", "add_member,remove_member"], "Groups_Audit"),
        ("Admin Privilege Changes", ["report", "admin", "user", target_email, "event", "grant_admin_privilege,revoke_admin_privilege"], "Admin_Privilege_Audit"),
        ("Workspace Studio Flows (Automations)", ["report", "workspace_studio", "user", target_email, "event", "create_flow,edit_flow", "start", date_start], "Workspace_Studio_Audit"),
        ("Service Account Delegations", ["user", target_email, "check", "serviceaccount"], "Service_Account_Delegations"),
        ("Google Takeout Logs", ["report", "takeout", "user", target_email, "start", date_start], "Takeout_Audit")
    ]

    for desc, cmd, sheet in audit_tasks:
        print(f"\n--- Retrieving {desc} ---")
        run_gam_command(cmd, wb=wb, sheet_name=sheet)

    print(f"\n[PHASE 3: EVIDENCE PRESERVATION (GOOGLE VAULT)]")
    print("\n--- Creating Google Vault Matter ---")
    matter_name = f"Account_Compromise_{target_email}_{timestamp}"
    matter_output = run_gam_command(["create", "vaultmatter", "name", matter_name, "description", f"Forensic hold for {target_email}"])
    
    if matter_output is not None:
        print("  -> Waiting 15 seconds for Google Vault Matter to propagate...")
        time.sleep(15)
        for service in ["mail", "drive", "hangoutschat"]:
            print(f"\n--- Applying Vault Hold for {service.upper()} ---")
            hold_name = f"{service.upper()}_Hold"
            run_gam_command(["create", "vaulthold", "matter", matter_name, "name", hold_name, "corpus", service, "accounts", target_email])
    else:
        print("  -> WARNING: Could not create Vault Matter. Please manually create it and apply Vault Holds.")

    print("\n=====================================================")
    if do_lockdown == 'y':
        print(f" Containment and Audit Complete!")
        print(f" Account {target_email} has been secured.")
    else:
        print(f" Audit Complete!")
        print(f" Account {target_email} was NOT secured (Audit Only).")

    # Save the Excel workbook
    try:
        wb.save(audit_file)
        print(f" Please review the Excel file: {audit_file}")
    except Exception as e:
        print(f" WARNING: Failed to save Excel file '{audit_file}': {e}")
        
    print("=====================================================")

if __name__ == "__main__":
    main()
