import os
import sys
import json
import time
import logging
import requests
import re
import socket
import subprocess
import shutil
import ssl
import ipaddress
import requests
from tqdm import tqdm
from ipaddress import ip_network
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import subprocess
import xml.etree.ElementTree as ET
from web import *
from utils import check_target_defined, change_target, purge_target_prompt, display_logo
from config import LOG_DIR, LOG_FILE, find_sqlmap, find_nikto, TARGET_FILE, find_zap

GITHUB_RAW_BASE = "https://raw.githubusercontent.com/sec0ps/vapt-automation/main/"
GITHUB_VERSION_URL = GITHUB_RAW_BASE + "version.txt"
LOCAL_VERSION_FILE = "version.txt"
FILES_TO_UPDATE = [
    "README.md",
    "config.py",
    "main.py",
    "requirements.txt",
    "sql.py",
    "utils.py",
    "web.py"
]

def check_for_updates():
    print("\n=== Checking for updates from GitHub... ===")
    updated = False

    try:
        # Step 1: Read local version
        local_version = "0.0.0"
        if os.path.exists(LOCAL_VERSION_FILE):
            with open(LOCAL_VERSION_FILE, "r") as f:
                local_version = f.read().strip()

        # Step 2: Get remote version
        response = requests.get(GITHUB_VERSION_URL, timeout=5)
        if response.status_code != 200:
            print("[!] Could not retrieve remote version info (HTTP {}).".format(response.status_code))
            print("=== Update check skipped ===\n")
            return False

        remote_version = response.text.strip()

        # Step 3: Compare versions
        if remote_version > local_version:
            print(f"[+] New version detected: {remote_version} (current: {local_version})")
            for filename in FILES_TO_UPDATE:
                file_url = GITHUB_RAW_BASE + filename
                file_resp = requests.get(file_url, timeout=10)
                if file_resp.status_code == 200:
                    with open(filename, "wb") as f:
                        f.write(file_resp.content)
                    print(f"    -> Updated {filename}")
                else:
                    print(f"    [!] Failed to update {filename} (HTTP {file_resp.status_code})")

            # Step 4: Update local version record
            with open(LOCAL_VERSION_FILE, "w") as f:
                f.write(remote_version)

            updated = True
            print("[✓] Update complete. Please restart the tool to load latest changes.")
        else:
            print("[✓] Already running the latest version.")

    except Exception as e:
        print(f"[!] Update check failed: {e}")

    print("=== Update check complete ===\n")
    return updated

def is_valid_url(url):
    """Validate a given URL."""
    parsed_url = urlparse(url)
    return all([parsed_url.scheme, parsed_url.netloc])

def full_automation():
    logging.info("Running full automation...")

def automated_network_enumeration():
    logging.info("Running automated network enumeration...")

def main():
    # Perform the update check before running the main program
    check_for_updates()
    """Main function to execute the menu and handle user input."""
    check_zap_running()

    # Locate tools dynamically
    sqlmap_path = find_sqlmap()  # ✅ Find sqlmap
    nikto_path = find_nikto()  # ✅ Find Nikto
    zap_path = find_zap()

    # Ensure a valid target is set
    target = check_target_defined()

    # Display paths and target
    display_logo()
    print(f"\n🎯 Current Target: {target}")
    print(f"🛠 SQLMAP Path: {sqlmap_path if sqlmap_path else '❌ Not Found'}")
    print(f"🛠 Nikto Path: {nikto_path if nikto_path else '❌ Not Found'}")
    print(f"🛠 OWASP ZAP Path: {zap_path if zap_path else '❌ Not Found'}\n")

    def network_enumeration():
        """Prompt for scan type and run Nmap scan."""
        print("\n[🔍 Network Enumeration Options]")
        print("1️⃣ Fast Scan: Quick service discovery and fingerprinting")
        print("2️⃣ Thorough Scan: In-depth analysis including vulnerability detection")

        scan_type = input("\nSelect an option (1 or 2): ").strip()
        if scan_type not in ["1", "2"]:
            print("❌ Invalid selection. Returning to menu.")
            return

        target = check_target_defined()
        if isinstance(target, list):
            target = target[0]  # Ensure it's always a string

        run_bulk_nmap_scan(target, scan_type)

    actions = {
        "1": full_automation,
        "2": network_enumeration,
        "3": process_network_enumeration,
        "4": lambda: sqli_testing_automation(sqlmap_path),
        "5": change_target,  # ✅ New option for changing the target
    }

    while True:
        print("\n[ ⚙ Automated Security Testing Framework ⚙ ]")
        print("1️⃣ Full Automation - Not Available Yet")
        print("2️⃣ Network Enumeration & Vulnerability Assessment")
        print("3️⃣ Web Application Enumeration & Testing")
        print("4️⃣ SQLi Testing Automation")
        print("5️⃣ Change Target")
        print("6️⃣ Exit (or type 'exit')")

        choice = input("\n🔹 Select an option (1-6 or 'exit'): ").strip().lower()

        if choice in ("exit", "6"):
            purge_target_prompt()
            logging.info("🔚 Exiting program.")
            break

        action = actions.get(choice)
        if action:
            action()
        else:
            logging.error("❌ Invalid selection. Please try again.")

if __name__ == "__main__":
    main()
