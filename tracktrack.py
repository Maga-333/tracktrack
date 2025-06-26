import re
import time
from datetime import datetime
from colorama import Fore, Style, init
from pyfiglet import figlet_format
init(autoreset=True)

command_database = {
    "rm": {
        "description": "Used to remove files or directories.",
        "dangerous_options": {
            "-rf /": {
                "warning": "Deletes everything from the root. Extremely dangerous!",
                "recommendation": "Avoid using 'rm -rf /'. Use specific paths like 'rm -rf /home/user/folder'."
            },
            "-r": {
                "warning": "Recursively deletes folders.",
                "recommendation": "Ensure correct folder path before using '-r'."
            }
        }
    },
    "chmod": {
        "description": "Changes file permissions.",
        "dangerous_options": {
            "777": {
                "warning": "Gives full access to everyone. May expose sensitive files.",
                "recommendation": "Use restrictive permissions like 755 or 700."
            }
        }
    },
    "nc": {
        "description": "Netcat – for network comms.",
        "dangerous_options": {
            "-e": {
                "warning": "Spawns a shell remotely – used in reverse shells.",
                "recommendation": "Avoid '-e'. Use Netcat only for safe port testing."
            }
        }
    },
    "dd": {
        "description": "Low-level data copying, disk overwrite.",
        "dangerous_options": {
            "if=/dev/zero of=/dev/sda": {
                "warning": "Overwrites entire disk with zeros. Irrecoverable loss.",
                "recommendation": "Be 100% sure when using dd. Always check device name."
            }
        }
    },
    "chown": {
        "description": "Changes file ownership.",
        "dangerous_options": {
            "/": {
                "warning": "Changing ownership of root can destabilize the system.",
                "recommendation": "Target only necessary directories or files."
            }
        }
    },
    "nmap": {
        "description": "Network scanning tool.",
        "dangerous_options": {
            "-sS": {
                "warning": "Stealth SYN scan. Could trigger IDS alerts.",
                "recommendation": "Use responsibly with permission."
            }
        }
    },
    "curl": {
        "description": "Transfers data from/to a server.",
        "dangerous_options": {
            "| bash": {
                "warning": "Executes downloaded content directly. Very dangerous.",
                "recommendation": "Download script, inspect it, then run manually."
            }
        }
    },
    "wget": {
        "description": "Downloads files from the web.",
        "dangerous_options": {
            "| sh": {
                "warning": "Executes potentially malicious script. Avoid it.",
                "recommendation": "Always inspect the script before executing."
            }
        }
    },
    "bash": {
        "description": "Starts a new bash shell or script.",
        "dangerous_options": {
            "-i >& /dev/tcp/": {
                "warning": "Used in reverse shells to connect back to attacker.",
                "recommendation": "Monitor such activity; used in exploits."
            }
        }
    },
    "mkfs": {
        "description": "Formats a filesystem.",
        "dangerous_options": {
            "/dev/sda": {
                "warning": "Will wipe and reformat the entire drive.",
                "recommendation": "Never run mkfs on active system disks."
            }
        }
    },
    "passwd": {
        "description": "Changes user password.",
        "dangerous_options": {
            "root": {
                "warning": "Changing root password may lock out admin access.",
                "recommendation": "Ensure you know the impact before changing root credentials."
            }
        }
    },
    "useradd": {
        "description": "Creates new user accounts.",
        "dangerous_options": {
            "-o -u 0": {
                "warning": "Creates another root user. Huge security risk.",
                "recommendation": "Avoid duplicate UID 0 unless necessary for recovery."
            }
        }
    },
    "iptables": {
        "description": "Linux firewall tool.",
        "dangerous_options": {
            "-F": {
                "warning": "Flushes all firewall rules. System becomes unprotected.",
                "recommendation": "Always back up rules before flushing."
            }
        }
    },
    "systemctl": {
        "description": "Manages system services.",
        "dangerous_options": {
            "disable ssh": {
                "warning": "Disables SSH remote access. Can lock you out.",
                "recommendation": "Be cautious before disabling core services."
            }
        }
    },
    "kill": {
        "description": "Kills a process.",
        "dangerous_options": {
            "-9 1": {
                "warning": "Kills init process (PID 1). Crashes the system.",
                "recommendation": "Never kill PID 1. Use safe process IDs."
            }
        }
    },
    "ps": {
        "description": "Displays process status.",
        "dangerous_options": {
            "aux": {
                "warning": "Reveals all processes. Can be used for reconnaissance.",
                "recommendation": "Legit for admin use, but monitor in shared environments."
            }
        }
    },
    "strace": {
        "description": "Traces system calls and signals.",
        "dangerous_options": {
            "-p": {
                "warning": "Can spy on running processes.",
                "recommendation": "Ensure monitoring is authorized."
            }
        }
    },
    "tcpdump": {
        "description": "Captures network traffic.",
        "dangerous_options": {
            "-i any": {
                "warning": "Captures all traffic – can expose sensitive info.",
                "recommendation": "Restrict interface and apply filters."
            }
        }
    },
    "su": {
        "description": "Switches user (often to root).",
        "dangerous_options": {
            "-": {
                "warning": "Access to root shell. Monitor for unauthorized switches.",
                "recommendation": "Audit usage with logs."
            }
        }
    },
    "sudo": {
        "description": "Runs command as superuser.",
        "dangerous_options": {
            "": {
                "warning": "Full root privilege. Needs strict control.",
                "recommendation": "Use only when absolutely necessary."
            }
        }
    },
    "history": {
        "description": "Shows command history.",
        "dangerous_options": {
            "-d": {
                "warning": "Deletes history lines. Can hide activity.",
                "recommendation": "Prevent abuse by restricting access."
            }
        }
    },
    "cron": {
        "description": "Schedules recurring tasks.",
        "dangerous_options": {
            "@reboot": {
                "warning": "Executes at every boot. Often used by malware.",
                "recommendation": "Check cron jobs regularly."
            }
        }
    },
    "scp": {
        "description": "Secure copy over SSH.",
        "dangerous_options": {
            "-r": {
                "warning": "Can recursively copy full directories – including sensitive data.",
                "recommendation": "Restrict with firewall or chroot if needed."
            }
        }
    },
    "netstat": {
        "description": "Displays network connections.",
        "dangerous_options": {
            "-anp": {
                "warning": "Shows active ports + processes. Useful for attackers.",
                "recommendation": "Limit netstat use on multi-user systems."
            }
        }
    },
    "eval": {
        "description": "Evaluates and runs expressions/commands.",
        "dangerous_options": {
            "": {
                "warning": "Executes arbitrary code – huge injection risk.",
                "recommendation": "Avoid eval unless absolutely required."
            }
        }
    },
    "exec": {
        "description": "Executes a command – replaces current process.",
        "dangerous_options": {
            "": {
                "warning": "Replaces current process. Used in stealthy exploits.",
                "recommendation": "Use carefully with proper input sanitation."
            }
        }
    }
}

write_commands = [
    "echo", "tee", "cat", "printf", "touch", "nano", "vi", "vim", "nvim",
    "sed", "awk", "scp", "rsync", "cp", "mv", "dd", "chmod", "chown",
    "gzip", "bzip2", "xz", "zip", "unzip", "openssl", "tar", "dd", "logger",
    "heredoc", "tr", "tee", "ed", "ex", "patch", "apply", "sed -i", "perl -i",
    "python -c", "emacs", "ed", "ex", "compress", "cc", "gcc", "ld", "objcopy",
    "objdump", "ranlib", "ar", "strip", "mkfs", "mke2fs", "mkfs.ext4",
    "mount", "losetup", "fdisk", "parted", "ddrescue", "mkfifo", "ln",
    "chmod +x", "install", "cpio", "pax", "rsync --inplace", "xmlstarlet",
    "cheatwrite", "grep", "find", "awk", "less", "more", "head", "tail",
    "cut", "sort", "uniq", "wc", "diff", "comm"
]

# ✅ Log the command
def log_command(cmd):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open("logs/command_log.txt", "a") as f:
        f.write(f"[{timestamp}] {cmd}\n")

# ✅ Check the command + option for danger
def check_command(cmd):
    words = cmd.strip().split()
    if not words:
        return

    if words[0] in ["sudo", "su"]:
        words = words[1:]

    if not words:
        return

    main_cmd = words[0]
    option_string = " ".join(words[1:])

    if main_cmd in command_database:
        data = command_database[main_cmd]
        print(f"\n{Fore.GREEN}🧠 Command: '{main_cmd}' – {data['description']}")

        found_warning = False
        for danger_opt, details in data.get("dangerous_options", {}).items():
            if danger_opt in option_string:
                print(Fore.RED + f"\n⚠️ WARNING: Detected → '{danger_opt}'")
                print(Fore.LIGHTRED_EX + f"→ Reason: {details['warning']}")
                print(Fore.YELLOW + f"💡 Safer Tip: {details['recommendation']}")
                found_warning = True

        if not found_warning:
            print(Fore.LIGHTGREEN_EX + "✅ No dangerous option detected for this command.")
    else:
        # classify as write-type or unknown
        if main_cmd in write_commands:
            print(Fore.LIGHTBLUE_EX + f"✍️ '{main_cmd}' is a writing-type command. Looks safe to write files.")
        else:
            print(Fore.LIGHTBLACK_EX + f"ℹ️ Command '{main_cmd}' is not in the tracked database.")

# Main loop
def main():
    banner = figlet_format("TrackTrack", font="slant")
    print(Fore.YELLOW + banner)
    print(Fore.LIGHTYELLOW_EX + "🔒 Linux Command Watching by LNT\n")
    print(Fore.LIGHTBLACK_EX + "Type 'exit' to quit.\n")

    while True:
        cmd = input(Fore.CYAN + "💬 Enter command: " + Style.RESET_ALL)
        if cmd.lower() == "exit":
            print(Fore.MAGENTA + "👋 Exiting TrackTrack++")
            break

        log_command(cmd)
        check_command(cmd)

if __name__ == "__main__":
    main()
