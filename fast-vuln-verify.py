import os
import sys
import datetime
import socket
import re
import shutil
import readline
from termcolor import colored
from modules import *

startScript = "Starting Verification/Scanner Method"
stopScript = "Stopping Verification/Scanner Method"
notFound = "Not Found"
noResults = "No Results"
setModule = "Set Module"
ctrlC = "Ctrl+C Detected"

now = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")

def get_terminal_size():
    try:
        columns, _ = shutil.get_terminal_size()
    except AttributeError:
        columns = int(os.environ.get('COLUMNS', 80))
    return columns


def create_ascii_banner(ascii_art):
    columns = get_terminal_size()
    ascii_lines = ascii_art.splitlines()
    centered_ascii_lines = []

    for line in ascii_lines:
        if len(line) < columns:
            padding = (columns - len(line)) // 2
            centered_ascii_lines.append(' ' * padding + line)
        else:
            centered_ascii_lines.append(line[:columns])  # Eğer ASCII metni terminal genişliğini aşarsa kes

    return '\n'.join(centered_ascii_lines)


def create_combined_banner(ascii_art, title, timestamp):
    columns = get_terminal_size()
    text_length = max(len(title), len(timestamp))

    banner_lines = []

    # Add ASCII Art centered
    ascii_lines = ascii_art.splitlines()
    for line in ascii_lines:
        if len(line) < columns:
            padding = (columns - len(line)) // 2
            banner_lines.append(' ' * padding + line)
        else:
            banner_lines.append(line[:columns])

    # Add Title centered
    padding = (columns - len(title)) // 2
    banner_lines.append(' ' * padding + title)

    # Add timestamp centered
    padding = (columns - len(timestamp)) // 2
    banner_lines.append(' ' * padding + timestamp)

    return '\n'.join(banner_lines)


def print_ascii_banner():
    ascii_art = r"""
⠄⠄⠄⣾⣿⠿⠿⠶⠿⢿⣿⣿⣿⣿⣦⣤⣄⢀⡅⢠⣾⣛⡉⠄⠄⠄⠸⢀⣿
⠄⠄⢀⡋⣡⣴⣶⣶⡀⠄⠄⠙⢿⣿⣿⣿⣿⣿⣴⣿⣿⣿⢃⣤⣄⣀⣥⣿⣿
⠄⠄⢸⣇⠻⣿⣿⣿⣧⣀⢀⣠⡌⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⣿⣿⣿
⠄⢀⢸⣿⣷⣤⣤⣤⣬⣙⣛⢿⣿⣿⣿⣿⣿⣿⡿⣿⣿⡍⠄⠄⢀⣤⣄⠉⠋
⠄⣼⣖⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⢇⣿⣿⡷⠶⠶⢿⣿⣿⠇⢀
⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⣿⣿⡇⣿⣿⣿⣿⣿⣿⣷⣶⣥⣴⣿
⢀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟
⢸⣿⣦⣌⣛⣻⣿⣿⣧⠙⠛⠛⡭⠅⠒⠦⠭⣭⡻⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃
⠘⣿⣿⣿⣿⣿⣿⣿⣿⡆⠄⠄⠄⠄⠄⠄⠄⠄⠹⠈⢋⣽⣿⣿⣿⣿⣵⣾⠃
⠄⠘⣿⣿⣿⣿⣿⣿⣿⣿⠄⣴⣿⣶⣄⠄⣴⣶⠄⢀⣾⣿⣿⣿⣿⣿⣿⠃⠄
⠄⠄⠈⠻⣿⣿⣿⣿⣿⣿⡄⢻⣿⣿⣿⠄⣿⣿⡀⣾⣿⣿⣿⣿⣛⠛⠁⠄⠄
FastVulnVerify
"""
    return ascii_art


def print_combined_banner():
    ascii_art = print_ascii_banner()
    title = "Vulnerability Analysis & Fast Verification Script BETA"
    timestamp = "STARTED AT: " + str(now)
    print(create_combined_banner(ascii_art, title, timestamp))
    # Print the total number of modules available
    total_modules = colored("> ", 'red', attrs=['bold']) + str(colored(len(modules), 'cyan'))
    print("Total " + total_modules + " module(s) available")
    print("Please use 'search' or 'use'.\n")


def print_table(headers, rows):
    column_widths = [max(len(str(item)) for item in col) for col in zip(*([headers] + rows))]
    separator = "+" + "+".join("-" * (width + 2) for width in column_widths) + "+"
    header_row = "| " + " | ".join(f"{header.ljust(width)}" for header, width in zip(headers, column_widths)) + " |"

    print(separator)
    print(header_row)
    print(separator)
    for row in rows:
        row_str = "| " + " | ".join(f"{str(item).ljust(width)}" for item, width in zip(row, column_widths)) + " |"
        print(row_str)
    print(separator)


def verificationSearch(keyword):
    command = keyword.strip()
    result = [module for module in modules if keyword.lower() in module["Title"].lower()]
    headers = ["ID", "Title", "Description"]
    rows = [[row["ID"], row["Title"], row["Description"]] for row in result]
    print_table(headers, rows)
    print(colored("> ", 'red', attrs=['bold']) + str(colored(len(result), 'cyan')) + " modules found.")
    return result


def is_valid_ip_or_hostname(ip_or_hostname):
    try:
        socket.gethostbyname(ip_or_hostname)
        return True
    except socket.gaierror:
        return False


def verificationRunModule(module_id):
    selected_module = next((module for module in modules if module["ID"] == module_id), None)
    if selected_module:
        run_command = selected_module["os_code"]
        print(colored(f"Selected Module: {selected_module['Title']}", 'blue', attrs=['bold']))

        while True:
            ip_address = input(
                colored("> ", 'red', attrs=['bold']) + "Enter IP address or hostname (separated by ' ') " + colored(
                    "=> ", 'red', attrs=['bold']))
            if ip_address.lower().strip().startswith("search "):
                keyword = ip_address[len("search "):].strip()
                verificationSearch(keyword)
                return  # Kullanıcı komutları devam etmesin

            if ip_address.lower().strip().startswith("use "):
                keyword = ip_address[len("use "):].strip()
                try:
                    moduleID = int(keyword)
                    current_module_id = moduleID
                    verificationRunModule(moduleID)
                except ValueError:
                    print(colored("Please define a valid module ID.", 'red', attrs=['bold']))
                return  # Kullanıcı komutları devam etmesin

            ip_list = re.split(r'[,\s]', ip_address)
            valid_ips = True
            for ip in ip_list:
                if ip:
                    if not is_valid_ip_or_hostname(ip):
                        print(colored("Invalid IP address or hostname: " + ip, 'red', attrs=['bold']))
                        valid_ips = False
                        break
            if valid_ips:
                break

        while True:
            try:
                port = input(colored("> ", 'red',
                                     attrs=['bold']) + "Enter port(s) (1-65535) or ports separated by ',': " + colored(
                    "=> ", 'red', attrs=['bold']))
                if port.lower().strip().startswith("search "):
                    keyword = port[len("search "):].strip()
                    verificationSearch(keyword)
                    return  # Kullanıcı komutları devam etmesin
                if port.lower().strip().startswith("use "):
                    keyword = port[len("use "):].strip()
                    try:
                        moduleID = int(keyword)
                        current_module_id = moduleID
                        verificationRunModule(moduleID)
                    except ValueError:
                        print(colored("Please define a valid module ID.", 'red', attrs=['bold']))
                    return  # Kullanıcı komutları devam etmesin
                if port == "exit":
                    print(colored("\nExiting Goodbye.", 'blue', attrs=['bold']))
                    sys.exit()
                elif port == "clear":
                    os.system("clear")
                else:
                    if not port:
                        port = ""
                        break
                    else:
                        if "," in port:
                            ports = port.split(",")
                            for p in ports:
                                if not p.isdigit() or int(p) < 1 or int(p) > 65535:
                                    raise ValueError
                            port = ",".join(ports)
                        elif not port.isdigit() or int(port) < 1 or int(port) > 65535:
                            raise ValueError
                        break
            except ValueError:
                print(colored("Please enter a valid port(s) within 1-65535 range or ports separated by ','.", 'red',
                              attrs=['bold']))
        run_command = run_command.replace("{RHOST}", ip_address)
        run_command = run_command.replace("{RPORT}", port)
        print(colored((startScript.center(100, '#')).replace("#", colored("#", 'cyan'))))
        print('\n')
        os.system(run_command)
        print('\n' * 2)
        print(colored((stopScript.center(100, '#')).replace("#", colored("#", 'cyan'))))
        print('\n' * 2)
    else:
        print(notFound.center(100, '#'))
        print("Module not found.")

def handle_command(command):
    command = command.strip().lower()
    if command == "exit":
        print(colored("\nExiting Goodbye.", 'red', attrs=['bold']))
        sys.exit()
    elif command == "clear":
        os.system("clear")
        return True
    return False


def process_command(full_command):
    global current_module_id
    try:
        command, keyword = full_command.split(maxsplit=1)
    except ValueError:
        command = full_command
        keyword = None

    if command == "search":
        if keyword:
            verificationSearch(keyword)
        else:
            print(colored("Please specify a keyword to search for.", 'red', attrs=['bold']))
    elif command == "use":
        if keyword:
            try:
                moduleID = int(keyword)
                current_module_id = moduleID
                verificationRunModule(moduleID)
            except ValueError:
                print(colored("Please define a valid module ID.", 'red', attrs=['bold']))
        else:
            print(colored("Please specify a module ID to use.", 'red', attrs=['bold']))
    else:
        print(colored("Invalid command. Please use 'search' or 'use'.", 'red', attrs=['bold']))

def main():
    try:
        # Print the combined banner only once at the start
        print_combined_banner()

        while True:
            try:
                full_command = input(colored("FastVulnVerify => ", 'cyan', attrs=['bold'])).strip()
                if handle_command(full_command):
                    continue

                process_command(full_command)
            except KeyboardInterrupt:
                print(colored("\nCtrl+C Detected. Exiting...", 'red', attrs=['bold']))
                sys.exit()

    except KeyboardInterrupt:
        print(colored("\nCtrl+C Detected. Exiting...", 'red', attrs=['bold']))
        sys.exit()


if __name__ == "__main__":
    main()
