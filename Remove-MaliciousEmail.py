import subprocess
import sys
import re

# --- Configuration ---
# The path to your GAM executable. Default is 'gam' assuming it is in your system PATH.
# Change this if your executable is named differently (e.g., 'gamadv-xtd3').
GAM_CMD = "gam"
# --- End of Configuration ---

def run_gam_command(command):
    """
    Executes a GAM command, streams its output in real-time, and handles errors.
    """
    full_command = [GAM_CMD] + command
    print(f"\nExecuting: {' '.join(full_command)}\n")
    
    try:
        # Using Popen to stream output in real-time, which is useful for long-running GAM commands.
        # stderr is redirected to stdout to capture all output in one stream.
        process = subprocess.Popen(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            bufsize=1  # Line-buffered
        )

        # Read and print output line by line as it comes in.
        for line in iter(process.stdout.readline, ''):
            print(line, end='')
        
        process.stdout.close()
        return_code = process.wait()

        if return_code != 0:
            print(f"\n---")
            print(f"WARNING: GAM command finished with a non-zero exit code: {return_code}.")
            print("Review the output above for specific GAM errors.")
            print(f"---\n")

    except FileNotFoundError:
        print(f"ERROR: The command '{GAM_CMD}' was not found.")
        print("Please ensure GAM is installed correctly and that its location is in your system's PATH.")
        print(f"You can also set the GAM_CMD variable at the top of this script to the full path of your GAM executable.")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred while trying to run the GAM command: {e}")
        sys.exit(1)

def main():
    """
    Main function to guide the user through the email deletion process.
    """
    print("=====================================================")
    print("   Bulk Remove Malicious Email via Message-ID        ")
    print("=====================================================\n")

    print("This script will delete a specific email from ALL user mailboxes in the domain.")
    print("To identify the email, you need its unique 'Message-ID'.")
    print("You can find this by viewing the 'Original message' headers in Gmail.\n")

    message_id = input("Enter the full Message-ID (including angle brackets < >): ").strip()

    # Basic validation to ensure the Message-ID looks plausible.
    if not (message_id.startswith('<') and message_id.endswith('>') and '@' in message_id):
        print("\nERROR: Invalid Message-ID format.")
        print("It should look like '<CAD=12345_abcde@mail.gmail.com>'.")
        print("Please restart the script and try again.")
        return

    print("\n---")
    print("Run Mode:")
    print("  'dry' - (Recommended First) Simulates the deletion and shows which users would be affected.")
    print("  'live' - Performs the actual deletion. This action CANNOT be undone.")
    
    while (run_mode := input("Select run mode ('dry' or 'live'): ").lower().strip()) not in ["dry", "live"]:
        print("Invalid input. Please enter 'dry' or 'live'.")

    print(f"--- Running in {run_mode.upper()} mode ---")

    # Construct the base GAM command.
    # The query uses `rfc822msgid:` which is the correct field for Message-ID searches.
    # `all users` targets every user in the domain.
    command = [
        "all", "users", "delete", "messages",
        "query", f"rfc822msgid:{message_id}"
    ]

    # The 'doit' flag is what makes GAM perform the actual deletion.
    # Without it, GAM runs in a 'dry run' or simulation mode.
    if run_mode == 'live':
        confirmation = input(f"\nWARNING: You are in 'live' mode. This will permanently delete the email with Message-ID\n'{message_id}'\nfrom ALL user mailboxes. This cannot be undone.\n\nAre you absolutely sure you want to proceed? (yes/no): ").lower().strip()
        if confirmation == 'yes':
            command.append("doit")
            print("\nConfirmation received. Proceeding with deletion...")
        else:
            print("\nDeletion cancelled. Exiting.")
            return
    else:
        print("\nRunning in 'dry run' mode. No emails will be deleted.")

    # Execute the final command
    run_gam_command(command)

    print("\n=====================================================")
    print("  Script finished.                                   ")
    print("=====================================================")

if __name__ == "__main__":
    main()