import readline

last_fetched_otp = None
totp_default_step = 30

''' Helper function to write operation to different device streams and check status '''
def write_operation_and_check_status(operation_command,device_path, operation_name):
    try:
        with open(device_path, 'w') as otp_file:
            otp_file.write(operation_command)
            print(f"Successfully {operation_name} OTP.")

    except IOError as e:
        print(f"\033[1;31mError:\033[0m Failed to perform operation '{operation_command}': {e}")

''' List based OTP management system & commands '''
def handle_add_passw(otp):
    write_operation_and_check_status(f"add:{otp}","/dev/otp_list", f"adding {otp} to the list")

def handle_remove_passw(otp):
    write_operation_and_check_status(f"remove:{otp}","/dev/otp_list" ,"removing from the list")

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
        print(f"\033[1;31mError:\033[0m Failed to fetch OTP: {e}")

def handle_validate_passw(otp):
    global last_fetched_otp
    if otp == last_fetched_otp:
        print(f"\033[1;32mOTP {otp} is valid.\033[0m")
        last_fetched_otp = ""
    else:
        print(f"\033[1;33mOTP {otp} is invalid or already used.\033[0m")

''' Time based OTP system & commands '''
def handle_set_totp_key(new_key):
    if len(new_key) > 32:
        print("Error: Secret key must be 32 characters or less.")
        return
    write_operation_and_check_status(f"key:{new_key}", "/dev/otp_time", "updating secret key for time")

def handle_set_totp_step(new_step):
    global totp_default_step
    try:
        new_step = int(new_step)
    except ValueError:
        print("\033[1;31mError:\033[0m Time step must be a number.")
        return

    if new_step < 10 or new_step > 60:
        print("\033[1;31mError:\033[0m Time step must be between 10 and 60 seconds.")
        return
    write_operation_and_check_status(f"step:{new_step}", "/dev/otp_time", f"updating time step({new_step}s) for time")
    totp_default_step = new_step

def handle_read_totp():
    try:
        with open('/dev/otp_time', 'r') as otp_file:
            otp = otp_file.readline().strip()
            print(f"Current TOTP: {otp}")
    except IOError as e:
        print(f"\033[1;31mError:\033[0m Failed to read current TOTP: {e}")

def handle_validate_totp(otp):
    try:
        with open('/dev/otp_time', 'r') as otp_file:
            current_otp = otp_file.readline().strip()
            if otp == current_otp:
                print(f"\033[1;32mOTP {otp} is valid.\033[0m")
            else:
                print(f"\033[1;33mOTP {otp} is invalid or already used.\033[0m")
    except IOError as e:
        print(f"\033[1;31mError:\033[0m Failed to validate TOTP: {e}")

def handle_totp_sync():
    pass

def handle_help():
    print("\033[1;32;40m OTP-SHELL - A simple OTP management shell. \033[0m")
    print("\033[1;34;40m------------------------- List-based OTP commands -------------------------\033[0m")
    print("\033[31m- add_passw <otp_password>\033[0m: Add a new password to the list.")
    print("\033[31m- remove_passw <otp_password>\033[0m: Remove a password from the list.")
    print("\033[31m- fetch_passw\033[0m: Fetch a password from the list. Fetching will invalidate the previous OTP!.")
    print("\033[31m- validate_passw <otp_password>\033[0m: Validate a OTP password.")
    print("\033[1;34;40m------------------------- Time-based OTP commands -------------------------\033[0m")
    print("\033[33m- set_totp_key <new_key>\033[0m: Set a new secret key for TOTP. Maximum key length is 32 characters.")
    print("\033[33m- set_totp_step <new_step>\033[0m: Set a new time step for TOTP. Default is 30 seconds, minimum is 10 second and maximum is 60 seconds.")
    print("\033[33m- fetch_totp\033[0m: Fetch the current TOTP.")
    print("\033[33m- validate_totp <otp code>\033[0m: Validate a TOTP.")
    print()


COMMAND_HANDLERS = {
    'add_passw': handle_add_passw,
    'remove_passw': handle_remove_passw,
    'fetch_passw': handle_fetch_passw,
    'validate_passw': handle_validate_passw,
    'set_totp_key': handle_set_totp_key,
    'set_totp_step': handle_set_totp_step,
    'fetch_totp': handle_read_totp,
    'validate_totp': handle_validate_totp,
    'help': handle_help
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
    print()
    print("Welcome to OTP-SHELL! Type 'help' for a list of available commands.")
    print()
    while True:
        cmd_input = input('\033[1;36mOTP-SHELL$\033[0m ').strip()
        if not cmd_input:
            continue

        args = cmd_input.split()
        cmd = args[0]
        otp = args[1] if len(args) > 1 else None

        if cmd == "exit":
            print("Goodbye! Exiting...")
            break
        elif cmd in COMMAND_HANDLERS:
            if cmd in ["fetch_passw", "help", "fetch_totp"]:
                COMMAND_HANDLERS[cmd]()
            else:
                if otp is not None:
                    COMMAND_HANDLERS[cmd](otp)
                else:
                    print(f"\033[1;31mError:\033[0m The '{cmd}' command requires an OTP argument.")
        else:
            print(f"\033[1;31mError:\033[0m Unknown command '{cmd}'.")
            print("Type 'help' for a list of available commands.")


if __name__ == "__main__":
    main()
