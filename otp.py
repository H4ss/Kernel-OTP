import readline

COMMANDS = ['add_passw', 'remove_passw', 'fetch_passw', 'validate_passw', 'help', 'exit']

def handle_add_passw(otp):
    try:
        with open('/dev/otp_list', 'w') as otp_file:
            otp_file.write(f"add:{otp}")
            print(f"Added OTP: {otp}")
    except IOError as e:
        print(f"Failed to add OTP: {e}")

def handle_remove_passw(otp):
    # Placeholder for remove command implementation
    pass

def handle_fetch_passw():
    # Placeholder for fetch command implementation
    pass

def handle_validate_passw(otp):
    # Placeholder for validate command implementation
    pass

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
    # Split the line into words and find the current word being typed
    line = readline.get_line_buffer().split()
    if not line:
        # No input: autocomplete commands
        options = COMMAND_HANDLERS.keys()
    else:
        # Input present: decide based on the position and content
        if len(line) > 1 or (text and line[0] in COMMAND_HANDLERS):
            # Autocompleting beyond the first word or mid-command (for commands without args)
            options = []  # No further suggestions; could be extended for subcommands/args
        else:
            # Autocompleting the command itself
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
