import readline

last_fetched_otp = None

def write_operation_and_check_status(operation_command, operation_name):
    try:
        with open('/dev/otp_list', 'w') as otp_file:
            otp_file.write(operation_command)
            print(f"Successfully {operation_name} OTP.")

    except IOError as e:
        print(f"Failed to perform operation '{operation_command}': {e}")

def handle_add_passw(otp):
    write_operation_and_check_status(f"add:{otp}", "adding")

def handle_remove_passw(otp):
    write_operation_and_check_status(f"remove:{otp}", "removing")

def handle_fetch_passw():
    global last_fetched_otp
    try:
        with open('/dev/otp_list', 'r') as otp_file:
            otp = otp_file.readline().strip()
            if otp:
                print(f"Fetched OTP: {otp}")
                last_fetched_otp = otp
                return otp
            else:
                print("No OTPs available.")
    except IOError as e:
        print(f"Failed to fetch OTP: {e}")

def handle_validate_passw(otp):
    global last_fetched_otp
    if otp == last_fetched_otp:
        print(f"OTP {otp} is valid.")
        last_fetched_otp = ""
    else:
        print(f"OTP {otp} is invalid or already used.")

def handle_help():
    print("Available commands:")
    print("add_passw <otp_password>: Add a new password to the list.")
    print("remove_passw <otp_password>: Remove a password from the list.")
    print("fetch_passw: Fetch a password from the list.")
    print("validate_passw <otp_password>: Validate a password.")

COMMAND_HANDLERS = {
    'add_passw': handle_add_passw,
    'remove_passw': handle_remove_passw,
    'fetch_passw': handle_fetch_passw,
    'validate_passw': handle_validate_passw,
}

def complete(text, state):
    line = readline.get_line_buffer().split()
    if not line:
        options = COMMAND_HANDLERS.keys()
    else:
        if len(line) > 1 or (text and line[0] in COMMAND_HANDLERS):
            options = []
        else:
            options = [cmd for cmd in COMMAND_HANDLERS.keys() if cmd.startswith(text)]
    
    try:
        return [option + ' ' for option in options][state] + ('' if line[0] in COMMAND_HANDLERS and len(line) == 1 else '')
    except IndexError:
        return None

readline.set_completer(complete)
readline.parse_and_bind("tab: complete")

def main():
    while True:
        cmd_input = input('OTP> ').strip()
        if not cmd_input:
            continue

        args = cmd_input.split()
        cmd = args[0]
        otp = args[1] if len(args) > 1 else None

        if cmd == "exit":
            print("Exiting...")
            break
        elif cmd in COMMAND_HANDLERS:
            if cmd in ["fetch_passw", "help"]:
                COMMAND_HANDLERS[cmd]()  # Fetch and help don't require an OTP argument
            else:
                if otp is not None:
                    COMMAND_HANDLERS[cmd](otp)
                else:
                    print(f"Error: The '{cmd}' command requires an OTP argument.")
        else:
            handle_help()


if __name__ == "__main__":
    main()
