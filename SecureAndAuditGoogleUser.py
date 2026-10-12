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
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
except ImportError:
    print("ERROR: The 'openpyxl' library is required to create Excel files.")
    print("Please install it by running: pip install openpyxl")
    sys.exit(1)

# Increase CSV field size limit to prevent crash on large logs/JSON fields
csv.field_size_limit(2147483647)

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
ISO8601_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$')
# Max character length allowed by Excel in a single cell
EXCEL_CELL_LIMIT = 32700

def sanitize_sheet_name(name):
    """Sanitizes sheet names by removing invalid characters and limiting length."""
    # Excel forbids \ / ? * [ ] : in sheet names
    clean_name = re.sub(r'[\\/*?:\[\]]', '_', name.strip())
    return clean_name[:31]

def add_to_excel(wb, sheet_name, data_string):
    """Parses a CSV string and adds it to a styled sheet in the workbook."""
    sheet_name = sanitize_sheet_name(sheet_name)
    
    # Handle duplicate sheet names
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
    row_count = 0
    col_widths = {}
    
    for row in reader:
        row_count += 1
        new_row = []
        for col_idx, cell in enumerate(row, start=1):
            cell_str = str(cell)
            if cell_str and ISO8601_REGEX.match(cell_str):
                try:
                    dt = datetime.fromisoformat(cell_str.replace('Z', '+00:00'))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    cell_val = dt.astimezone(TARGET_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')
                except Exception:
                    cell_val = cell_str
            else:
                cell_val = cell_str
            
            # Truncate to prevent Excel cell overflow
            if len(cell_val) > EXCEL_CELL_LIMIT:
                cell_val = cell_val[:EXCEL_CELL_LIMIT] + "... [TRUNCATED]"
            
            new_row.append(cell_val)
            # Track column length for auto-width
            col_widths[col_idx] = max(col_widths.get(col_idx, 0), min(len(cell_val), 60))
        
        ws.append(new_row)

    if row_count == 0:
        ws.append(["No results found."])
        return

    # Format header row and freeze pane
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
    
    for col_num in range(1, len(col_widths) + 1):
        cell = ws.cell(row=1, column=col_num)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="left", vertical="center")
        
        col_letter = get_column_letter(col_num)
        # Add padding to width, clamped between 12 and 60
        ws.column_dimensions[col_letter].width = max(col_widths.get(col_num, 10) + 3, 12)

    ws.freeze_panes = "A2"

def generate_secure_password(length=16):
    """Generates a secure, random password for the account reset."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3
                and any(c in "!@#$%^&*" for c in password)):
            break
    return password

# Mapping of Google Workspace Reports API mail_event_type integer codes to human-readable actions
GMAIL_EVENT_MAP = {
    0: "Standard delivery / transit",
    1: "Message sent",
    2: "Message received",
    3: "User marked spam",
    4: "Gmail flagged spam",
    5: "Message quarantined",
    6: "Message released from quarantine",
    7: "Message opened (first time)",
    8: "Message marked unread",
    9: "Message replied (first time)",
    10: "Message forwarded (first time)",
    11: "Message auto-forwarded",
    12: "Message moved to Inbox",
    13: "Message moved to Trash",
    14: "Message removed from Trash",
    15: "Link clicked in message body",
    16: "Link clicked in attachment preview",
    17: "Attachment(s) downloaded",
    18: "Attachment(s) saved to Google Drive",
}

def enrich_gmail_log_events(data_string):
    """
    Parses GAM Gmail report CSV, identifies the mail_event_type ID column,
    and inserts a human-readable action column right next to it.
    """
    if not data_string or not data_string.strip() or "No results found." in data_string:
        return data_string

    try:
        reader = list(csv.reader(io.StringIO(data_string)))
        if len(reader) < 2:
            return data_string

        header = reader[0]
        event_id_col = None
        
        # Scan data rows to locate which column holds the integer ID before 'mail_event_type'
        for row in reader[1:]:
            for i, val in enumerate(row):
                if val == 'mail_event_type':
                    if i > 0 and row[i - 1].strip().isdigit():
                        event_id_col = i - 1
                        break
            if event_id_col is not None:
                break

        # Fallback: check header names if row value scan did not match
        if event_id_col is None:
            for i, col in enumerate(header):
                if 'mail_event_type' in col.lower() or 'eventtype' in col.lower():
                    event_id_col = i
                    break

        if event_id_col is None:
            return data_string

        # Build new header: label ID column and insert human-readable action column
        new_header = list(header)
        new_header[event_id_col] = "mail_event_type_id"
        new_header.insert(event_id_col + 1, "mail_event_action")

        new_rows = [new_header]
        for row in reader[1:]:
            new_row = list(row)
            if len(new_row) <= event_id_col:
                new_row.extend([""] * (event_id_col - len(new_row) + 1))
            
            raw_id = new_row[event_id_col].strip() if event_id_col < len(new_row) else ""
            action_desc = ""
            if raw_id.isdigit():
                action_desc = GMAIL_EVENT_MAP.get(int(raw_id), f"Event {raw_id}")
            elif raw_id:
                action_desc = raw_id
                
            new_row.insert(event_id_col + 1, action_desc)
            new_rows.append(new_row)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerows(new_rows)
        return output.getvalue()
    except Exception as e:
        print(f"  -> Notice: Could not enrich Gmail events: {e}")
        return data_string

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
            encoding='utf-8',
            errors='replace'
        )
        if wb and sheet_name:
            output_to_save = result.stdout if result.stdout and result.stdout.strip() else "No results found.\n"
            if sheet_name in ["Gmail_Log_Events", "Attachments_Accessed"] and output_to_save != "No results found.\n":
                output_to_save = enrich_gmail_log_events(output_to_save)
            add_to_excel(wb, sheet_name, output_to_save)
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
                output = e.stdout if e.stdout and e.stdout.strip() else "No results found.\n"
                add_to_excel(wb, sheet_name, output)
            return None
        # Catch specific error for Drive Activity API authorization issues
        if e.returncode == 73 and 'Drive Activity API v2 Service/App not enabled' in e.stderr:
            message = "-> The 'Drive Activity API v2' is restricted by Google and not available on the Education Fundamentals edition (use 'gam report drive' instead). If you are on a premium tier, please verify your Drive SDK Admin permissions, ensure the API is enabled in your Google Cloud Project, and check GAM's Domain-Wide Delegation scopes (run 'gam update project')."
            print(f"  {message}")
            if wb and sheet_name:
                add_to_excel(wb, sheet_name, f"Message\n{message}\n")
            return None
        # Catch specific error for 2SV enforced by policy or suspended
        if e.returncode == 50 and ('user is required by admin policy' in e.stderr or 'Not Authorized to access this resource' in e.stderr):
            print("  -> INFO: 2-Step Verification cannot be turned off (enforced by domain policy or account is suspended).")
            return None
        # Catch backup codes update on already suspended account
        if e.returncode == 51 and 'User is suspended' in e.stderr:
            print("  -> INFO: Account is already suspended; backup verification codes cannot be updated while suspended.")
            return None
        print(f"  -> WARNING: Command failed with exit code {e.returncode}.")
        if e.stderr:
            print(f"  -> Stderr: {e.stderr.strip()}")
        # Log failure reason into worksheet for forensic record
        if wb and sheet_name:
            err_msg = f"ERROR: Command failed with exit code {e.returncode}.\n{e.stderr.strip() if e.stderr else 'No error details.'}"
            add_to_excel(wb, sheet_name, f"Status\n{err_msg}\n")
        return None

def main():
    print("=====================================================")
    print("   Google Workspace - Compromised Account Response   ")
    print("=====================================================")
    
    target_email = input("Enter the email address of the compromised user: ").strip().lower()
    if not target_email or "@" not in target_email:
        print("Invalid email address. Exiting.")
        return

    # Pre-flight check: verify user exists in Google Workspace
    print(f"\nVerifying user '{target_email}' in Google Workspace...")
    user_check = subprocess.run([GAM_CMD, "info", "user", target_email], capture_output=True, text=True, encoding='utf-8', errors='replace')
    if user_check.returncode != 0:
        print(f"WARNING: User '{target_email}' was not found or GAM could not retrieve user info.")
        if user_check.stderr:
            print(f"Details: {user_check.stderr.strip()}")
        proceed = input("Do you still wish to continue? (y/n): ").strip().lower()
        if proceed != 'y':
            print("Aborted by user.")
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
        # Step 1: Audit Credentials & Rotate Backup Codes
        print("\n--- Auditing & Rotating Security Credentials ---")
        run_gam_command(["user", target_email, "print", "backupcodes"], wb=wb, sheet_name="Backup_Codes_Before_Revoke")
        run_gam_command(["user", target_email, "update", "backupcodes"])

        # Step 2: Audit & Revoke App Passwords (Requires 'all' keyword in GAM)
        print("\n--- Auditing and Revoking App Passwords ---")
        run_gam_command(["user", target_email, "print", "asps"], wb=wb, sheet_name="App_Passwords_Before_Revoke")
        run_gam_command(["user", target_email, "delete", "asps", "all"])

        # Step 3: Audit & Revoke OAuth Tokens
        print("\n--- Auditing and Revoking OAuth Tokens ---")
        tokens_output = run_gam_command(["user", target_email, "print", "tokens"], wb=wb, sheet_name="OAuth_Tokens_Before_Revoke")
        if tokens_output and "clientId" in tokens_output:
            print("  -> Revoking individual OAuth application tokens...")
            try:
                reader = csv.DictReader(io.StringIO(tokens_output))
                revoked_count = 0
                for row in reader:
                    cid = row.get("clientId")
                    if cid:
                        run_gam_command(["user", target_email, "delete", "tokens", "clientid", cid])
                        revoked_count += 1
                print(f"  -> Successfully revoked {revoked_count} OAuth token(s).")
            except Exception as e:
                print(f"  -> WARNING: Failed during OAuth token iteration: {e}")

        # Step 4: Reset Password
        print("\n--- Resetting Password ---")
        new_password = generate_secure_password()
        run_gam_command(["update", "user", target_email, "password", new_password, "changepassword", "on"])
        print(f"  -> New temporary password set to: {new_password}")
        print("  -> (User will be forced to change this on next login)")

        # Step 5: Terminate All Web and Application Sessions
        print("\n--- Terminating Active Web & Device Sessions ---")
        run_gam_command(["user", target_email, "signout"])

        # Step 6: Optional 2SV Removal (Must be run BEFORE suspending the account)
        # Note: GAM command is 'turnoff2sv'. Only run if you need to clear attacker-registered security keys/prompts.
        run_gam_command(["user", target_email, "turnoff2sv"])

        # Step 7: Suspend Account (Performed as the final containment step)
        print("\n--- Suspending Account ---")
        run_gam_command(["update", "user", target_email, "suspended", "on"])

    else:
        print("\n--- Skipping Immediate Containment ---")
        print("\n--- Auditing Security Credentials & Tokens ---")
        run_gam_command(["user", target_email, "print", "tokens"], wb=wb, sheet_name="OAuth_Tokens_Audit")
        run_gam_command(["user", target_email, "print", "asps"], wb=wb, sheet_name="App_Passwords_Audit")
        run_gam_command(["user", target_email, "print", "backupcodes"], wb=wb, sheet_name="Backup_Codes_Audit")

    # Audit Recovery Info & Security Posture
    print("\n--- Auditing Recovery Info & Account Posture ---")
    run_gam_command(
        ["print", "users", "query", f"email:{target_email}", "fields", "primaryEmail,recoveryEmail,recoveryPhone,suspended,isEnrolledIn2Sv,isEnforcedIn2Sv"],
        wb=wb,
        sheet_name="Recovery_Info"
    )

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
        ("Attachments Accessed", ["report", "gmail", "user", target_email, "gmaileventtypes", "16,17,18", "start", date_start], "Attachments_Accessed"),
        ("IMAP Settings", ["user", target_email, "print", "imap"], "IMAP_Settings"),
        ("POP Settings", ["user", target_email, "print", "pop"], "POP_Settings"),
        ("Drive Activity", ["user", target_email, "print", "driveactivity", "starttime", iso_start], "Drive_Activity"),
        ("General Drive Audit Logs", ["report", "drive", "user", target_email, "start", date_start], "Drive_Audit_Log"),
        ("Drive Downloads and Desktop Syncs", ["report", "drive", "user", target_email, "event", "download,sync_item_content", "start", date_start], "Drive_Downloads"),
        ("External Drive Sharing", ["report", "drive", "user", target_email, "filters", "visibility==shared_externally", "start", date_start], "Drive_External_Sharing"),
        ("Drive File Locks (Checkouts)", ["report", "drive", "user", target_email, "event", "add_lock,remove_lock", "start", date_start], "Drive_Locks"),
        ("Classroom Activity", ["report", "classroom", "user", target_email, "event", "user_removed_from_course", "start", date_start], "Classroom_Audit"),
        ("Classroom State Changes", ["report", "classroom", "user", target_email, "event", "archived_course,deleted_course", "start", date_start], "Classroom_State_Change"),
        ("Group Membership Changes", ["report", "groups_enterprise", "user", target_email, "event", "add_member,remove_member", "start", date_start], "Groups_Audit"),
        ("Admin Privilege Changes", ["report", "admin", "user", target_email, "event", "grant_admin_privilege,revoke_admin_privilege", "start", date_start], "Admin_Privilege_Audit"),
        ("Workspace Studio Flows (Automations)", ["report", "workspace_studio", "user", target_email, "start", date_start], "Workspace_Studio_Audit"),
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
    
    if matter_output:
        print(f"  -> Waiting for Google Vault Matter '{matter_name}' to propagate...")
        for attempt in range(1, 7):
            check = subprocess.run([GAM_CMD, "info", "vaultmatter", matter_name], capture_output=True, text=True, encoding='utf-8', errors='replace')
            if check.returncode == 0:
                print(f"  -> Matter '{matter_name}' is verified and ready.")
                break
            time.sleep(5)
        
        for service in ["mail", "drive", "hangouts_chat"]:
            print(f"\n--- Applying Vault Hold for {service.upper()} ---")
            hold_name = f"{service.upper()}_Hold"
            hold_cmd = ["create", "vaulthold", "matter", matter_name, "name", hold_name, "corpus", service, "accounts", target_email]
            
            # Retry loop with short delay to handle Vault eventual consistency
            for attempt in range(1, 4):
                hold_result = run_gam_command(hold_cmd)
                if hold_result is not None:
                    break
                if attempt < 3:
                    print(f"  -> Hold creation pending propagation, retrying in 5 seconds (attempt {attempt}/3)...")
                    time.sleep(5)
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
