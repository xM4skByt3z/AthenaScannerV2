#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Security Toolkit
=======================

A comprehensive tool for network scanning, vulnerability detection, and malicious file analysis.
Designed for security professionals and enthusiasts.

Features:
- Network scanning and device classification
- Open port detection and service analysis
- Vulnerability validation using AI
- Malicious file detection with VirusTotal
- Intrusion Detection System (IDS) with Snort
- Syscall analysis for suspicious activity

Author: xM4skByt3z
GitHub: https://github.com/xM4skByt3z
License: CUSTOM
"""

import os
import time
import socket
import requests
import ipaddress
import netifaces as ni
import nmap
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP
from rich.console import Console
from rich.spinner import Spinner
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from functools import wraps
import hashlib
import subprocess
from datetime import datetime

# ASCII Art for the tool
ascii_art = """

⠀     ⠀⠀⠀     ⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⣤⣤⣦⣶⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ▄▀▀▀▄ ▀▀█▀▀ █   █ █▀▀▀▀ █▄  █ ▄▀▀▀▄ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        █▀▀▀█   █   █▀▀▀█ █▀▀   █ ▀▄█ █▀▀▀█ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⣿⣿⡿⠿⠛⠛⠉⠉⠁⠀⠀⣀⣀⣀⣀⡀⠀⠀⠀⠈⠉⠛⠛⠿⢿⣿⣿⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀        ▀   ▀   ▀   ▀   ▀ ▀▀▀▀▀ ▀   ▀ ▀   ▀ 
⠀⠲⢶⣶⣶⣶⣶⣿⣿⣿⠿⠿⠛⠋⠉⠀⠀⣀⣠⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣀⠀⠀⠀⠉⠙⠻⠿⢿⣿⣷⣶⣦⣤⣤⣄⡄        ▄▀▀▀▀ ▄▀▀▀▀ ▄▀▀▀▄ █▄  █ █▄  █ █▀▀▀▀ █▀▀▀▄ 
⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⣀⣠⣴⣶⣿⣿⣿⠿⠿⠛⠋⣩⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⣶⣦⣄⣀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠁⠀         ▀▀▀▄ █     █▀▀▀█ █ ▀▄█ █ ▀▄█ █▀▀   █▀▀▀▄ 
⠀⠀⠀⠀⠀⠀⣀⣀⣤⣴⣶⣿⣿⣿⠿⠟⠋⠉⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠈⠉⠛⠿⢿⣿⣶⣶⣤⣄⣀⣀⣀⣀⡀⠀        ▀▀▀▀   ▀▀▀▀ ▀   ▀ ▀   ▀ ▀   ▀ ▀▀▀▀▀ ▀   ▀ 
⢰⣶⣶⣶⣾⣿⣿⣿⣿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⢉⣽⣿⣿⣿⣿⣿⣿⠃⠀        @xM4skByt3z - Deivid Kelven           v2.0
⢸⣿⡿⠛⠛⠻⢿⣿⣷⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⢀⣠⣴⣾⣿⠿⠛⠋⠁⠀⠀⠀⠀⠀        
⠘⠁⠀⠀⠀⠀⠀⠈⠛⠿⣿⣿⣿⣷⣦⣤⣄⣀⠀⠀⠀⠀⠀⠀⠈⠙⠻⠿⢿⣿⠿⠟⠛⠁⢀⣀⣤⣴⣾⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⠿⣿⣿⣿⣿⣷⣶⣶⣦⣤⣤⣤⣤⣤⣤⣤⣴⣶⣶⣿⣿⣿⣿⣿⠟⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠛⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⢋⣽⣿⡿⠏⠁⠀⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⠏⠁⠀⠀⠀⣿⣿⣧⡀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⠟⠁⠀⠀⠀⠀⠀⣿⣿⣿⣿⣷⣶⣶⣾⡟⠁⠀⠀⠀⠀        
⠀⠀⠀⠀⢀⣤⣴⣶⣶⣦⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⣴⣿⣿⠿⠛⠛⠻⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢰⣿⣿⠃⠀⣶⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢸⣿⣿⠀⠀⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢸⣿⣿⡀⠀⠙⠿⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⡿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⢿⣿⣿⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣾⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠻⣿⣿⣿⣷⣶⣤⣤⣶⣶⣿⣿⣿⡿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠛⠛⠛⠋⠉⠀
⠀⠀⠀⠀
"""

# Display ASCII Art using lolcat
os.system(f'echo "{ascii_art}" | lolcat')

# Initialize the console with rich
console = Console()

# Cache to store MAC vendor API results
mac_vendor_cache = {}

# Rate limiter to control the number of requests per second
class RateLimiter:
    def __init__(self, max_calls, period):
        self.max_calls = max_calls
        self.period = period
        self.timestamps = []
        self.lock = threading.Lock()

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with self.lock:
                now = time.time()
                # Remove timestamps older than the period
                self.timestamps = [t for t in self.timestamps if now - t < self.period]
                if len(self.timestamps) >= self.max_calls:
                    # Wait until the period expires
                    time_to_wait = self.period - (now - self.timestamps[0])
                    time.sleep(time_to_wait)
                    # Update the timestamps list
                    self.timestamps = self.timestamps[1:]
                self.timestamps.append(now)
            return func(*args, **kwargs)
        return wrapper

# Apply rate limiter: 1 request every 2 seconds
rate_limiter = RateLimiter(max_calls=1, period=2)

# Function to display a loading spinner
def show_loading(message):
    spinner = Spinner("dots", text=message, style="bold blue")
    return console.status(spinner)

# Function to query MAC address vendor with rate limiting
@rate_limiter
def get_mac_vendor(mac):
    if mac in mac_vendor_cache:
        return mac_vendor_cache[mac]

    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            vendor = response.text
        else:
            vendor = "Unknown"
    except requests.exceptions.RequestException:
        vendor = "Unknown"

    mac_vendor_cache[mac] = vendor
    return vendor

# Function to perform a network scan
def scan_network():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    interfaces = ni.interfaces()

    for interface in interfaces:
        try:
            addrs = ni.ifaddresses(interface)
            if ni.AF_INET in addrs:
                ip_info = addrs[ni.AF_INET][0]
                ip_address = ip_info['addr']
                netmask = ip_info['netmask']

                if ip_address.startswith('127.'):
                    continue

                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                result = f"""
------------------ NETWORK INFORMATION ------------------

  IP Address        : {ip_address}
  Netmask           : {netmask}
  Network           : {network.network_address}
  Broadcast         : {network.broadcast_address}
  HostMin           : {network.network_address + 1}
  HostMax           : {network.broadcast_address - 1}
  Hosts/Net         : {network.num_addresses - 2}  (Excludes network and broadcast)

-----------------------------------------------------------
                """
                return result, network
        except ValueError:
            continue

    return "No active network interface found.", None

# Function to identify the operating system based on TTL
def get_os_by_ttl(ttl):
    if ttl <= 64:
        return "[bold cyan]Linux  [/bold cyan]"
    elif ttl <= 128:
        return "[bold yellow]Windows[/bold yellow]"
    else:
        return "Unknown"

# Function to process a single IP
def process_ip(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    ans, _ = srp(arp_request_broadcast, timeout=2, verbose=False)

    if ans:
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            manufacturer = get_mac_vendor(mac)

            icmp_request = IP(dst=ip) / ICMP()
            icmp_response = sr1(icmp_request, timeout=2, verbose=False)

            if icmp_response:
                ttl = icmp_response.ttl
                os = get_os_by_ttl(ttl)

                manufacturer_lower = manufacturer.lower()
                if "samsung" in manufacturer_lower or "motorola" in manufacturer_lower:
                    device_type = "Notebook"
                elif "epson" in manufacturer_lower:
                    device_type = "Printer"
                elif "huawei" in manufacturer_lower:
                    device_type = "Router"
                elif "xiaomi" in manufacturer_lower:
                    device_type = "Android Phone"
                elif "intelbras" in manufacturer_lower:
                    device_type = "Cam"
                elif "apple" in manufacturer_lower:
                    device_type = "IOS Phone"
                elif "inpro" in manufacturer_lower:
                    device_type = "IP Camera"
                elif "intel" in manufacturer_lower:
                    device_type = "Desktop"
                elif "del" in manufacturer_lower:
                    device_type = "Notebook"
                elif "lenovo" in manufacturer_lower:
                    device_type = "Notebook"
                else:
                    device_type = "Desktop"

                return ip, mac, manufacturer, ttl, os, device_type

    return None

# Function to scan open ports and services using Nmap with decoy
def scan_ports_with_nmap(target_ip):
    nm = nmap.PortScanner()
    decoy_ips = "192.168.1.100,192.168.1.101"

    try:
        nm.scan(target_ip, arguments=f"-D {decoy_ips} --open --top-ports=100 -T4 -sV --host-timeout 2m")

        if target_ip in nm.all_hosts():
            port_info = {}
            for proto in nm[target_ip].all_protocols():
                ports = nm[target_ip][proto].keys()
                for port in ports:
                    state = nm[target_ip][proto][port]['state']
                    if state == "open":
                        service = nm[target_ip][proto][port]['name']
                        product = nm[target_ip][proto][port]['product']
                        version = nm[target_ip][proto][port]['version']
                        port_info[port] = f"{service} {version}".strip()
            return port_info
        else:
            return None
    except Exception as e:
        console.print(f"[bold red]Error scanning {target_ip}: {e}[/bold red]")
        return None

# Function to validate vulnerabilities using the Gemini API
def validate_vulnerability(ip, port, service):
    # Services that should not be considered vulnerable by default
    non_vulnerable_services = ["tcpwrapped", "unknown", "generic"]

    if any(non_vuln in service.lower() for non_vuln in non_vulnerable_services):
        return f"""
IP: {ip}
Port: {port}
Status: open
Service: {service}
Operating System: Linux
✅ The service {service} is not vulnerable.
"""

    # Check if the service has a specific version
    if " " not in service:  # If there is no version in the service name
        return f"""
IP: {ip}
Port: {port}
Status: open
Service: {service}
Operating System: Linux
✅ The service {service} is not vulnerable (version not specified).
"""

    api_key = "YOUR API KEY!" #ADD YOUR API KEY HERE!!
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    data = {
        "contents": [{
            "parts": [{
                "text": f"based on the version of the service {service} on port {port} of IP {ip} is vulnerable. Provide a direct answer: 'Yes, it is vulnerable' or 'No, it is not vulnerable'. If it is vulnerable, list known CVEs, exploitation methods, impact, and mitigation in an organized way and with few emojis"
            }]
        }]
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)  # Timeout of 10 seconds
        if response.status_code == 200:
            result = response.json()
            if "candidates" in result and len(result["candidates"]) > 0:
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                if "yes, it is vulnerable" in text.lower():
                    return f"""
IP: {ip}
Port: {port}
Status: open
Service: {service}
Operating System: Linux
[bold yellow]⚠ The service {service} is vulnerable![/bold yellow]

🔍 **Vulnerability details:**
{text}
"""
                else:
                    return f"""
IP: {ip}
Port: {port}
Status: open
Service: {service}
Operating System: Linux
✅ The service {service} is not vulnerable.
"""
        return f"""
IP: {ip}
Port: {port}
Status: open
Service: {service}
Operating System: Linux
❌ Could not validate the vulnerability.
"""
    except requests.exceptions.Timeout:
        return f"""
IP: {ip}
Port: {port}
Status: open
Service: {service}
Operating System: Linux
❌ Vulnerability validation timed out.
"""
    except Exception as e:
        return f"""
IP: {ip}
Port: {port}
Status: open
Service: {service}
Operating System: Linux
❌ Error validating vulnerability: {e}
"""

# Function to perform ARP Sweep and classify devices
def arp_sweep_and_classify(target_ip):
    network = ipaddress.IPv4Network(target_ip, strict=False)
    ip_list = [str(ip) for ip in network.hosts()]

    devices = []

    with show_loading("Performing ARP Sweep..."):
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(process_ip, ip) for ip in ip_list]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip, mac, manufacturer, ttl, os, device_type = result
                    devices.append(f"{'=' * 90}")
                    devices.append(f" IP: {ip:<15} | MAC: {mac:<20}    | Manufacturer: {manufacturer}")
                    devices.append(f" TTL: {ttl:<3}            | Operating System: {os:<10}    | Type: {device_type}")
                    devices.append(f"{'-' * 90}")

    if devices:
        console.print("\n".join(devices), style="bold white")
    else:
        console.print("[bold red]No hosts found.[/bold red]\n")

    console.print("\n[bold white]Starting open port scanning on found hosts...[/bold white]\n")

    host_ports = {}

    with show_loading("Scanning open ports..."):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(scan_ports_with_nmap, ip): ip for ip in [d.split("|")[0].split(":")[1].strip() for d in devices if "IP:" in d]}

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    port_info = future.result()
                    if port_info:
                        host_ports[ip] = port_info
                        console.print(f"[bold green]Scan completed for {ip}[/bold green]")
                except Exception as e:
                    console.print(f"[bold red]Error scanning {ip}: {e}[/bold red]")

    return host_ports

# Function to check malicious files using the VirusTotal API
def check_malicious_file(api_key):
    """
    Checks if a file is malicious using the VirusTotal API.

    :param api_key: VirusTotal API key.
    """
    # Ask the user for the file path
    file_path = input("Enter the full path of the file you want to check: ")

    # Check if the file exists
    try:
        with open(file_path, 'rb') as file:
            # Calculate the SHA-256 hash of the file
            hash_sha256 = hashlib.sha256(file.read()).hexdigest()
    except FileNotFoundError:
        console.print("[bold red]File not found. Check the path and try again.[/bold red]")
        return
    except Exception as e:
        console.print(f"[bold red]Error opening the file: {e}[/bold red]")
        return

    # Check if the file has been analyzed before
    report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': hash_sha256}

    try:
        response = requests.get(report_url, params=params)
        response.raise_for_status()  # Raise an exception for invalid HTTP status codes
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error connecting to VirusTotal: {e}[/bold red]")
        return

    if response.status_code == 200:
        result = response.json()
        if result.get('response_code') == 1:
            # The file has been analyzed before, display the result
            console.print(f"[bold green]Analysis result:[/bold green]")
            console.print(f"File: {file_path}")
            console.print(f"SHA-256 Hash: {hash_sha256}")
            console.print(f"Detections: {result['positives']}/{result['total']}")
            if result['positives'] > 0:
                console.print("[bold red]Malicious file detected![/bold red]")
                # Organize and display detailed information
                console.print("\n[bold yellow]🔍 Detailed Information:[/bold yellow]")
                console.print(f"First Submission: {result.get('scan_date', 'N/A')}")
                console.print(f"Last Analysis: {result.get('last_analysis_date', 'N/A')}")
                console.print(f"File Size: {result.get('size', 'N/A')} bytes")
                console.print(f"File Type: {result.get('type', 'N/A')}")
                console.print(f"Magic: {result.get('magic', 'N/A')}")
                console.print("\n[bold cyan]📊 Detection Breakdown:[/bold cyan]")
                for scanner, scan_result in result.get('scans', {}).items():
                    if scan_result.get('detected'):
                        console.print(f"  - {scanner}: {scan_result.get('result', 'N/A')}")
            else:
                console.print("[bold green]File is safe.[/bold green]")
        else:
            # The file has not been analyzed before, submit it for analysis
            console.print("[bold yellow]File not analyzed before. Submitting for analysis...[/bold yellow]")
            try:
                files = {'file': (file_path, open(file_path, 'rb'))}
                params = {'apikey': api_key}
                response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
                response.raise_for_status()

                if response.status_code == 200:
                    console.print("[bold green]File submitted successfully for analysis.[/bold green]")
                    console.print(f"Scan ID: {response.json()['scan_id']}")
                else:
                    console.print("[bold red]Error submitting the file for analysis.[/bold red]")
            except requests.exceptions.RequestException as e:
                console.print(f"[bold red]Error submitting the file for analysis: {e}[/bold red]")
            except Exception as e:
                console.print(f"[bold red]Unexpected error: {e}[/bold red]")
    else:
        console.print("[bold red]Error checking the file.[/bold red]")

# Function to install Snort silently
def install_snort():
    if not os.path.exists("/usr/local/bin/snort"):
        try:
            subprocess.run(["sudo", "apt-get", "update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "apt-get", "install", "-y", "snort"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Download additional rules for malware, ransomware, DDoS, etc.
            subprocess.run(["sudo", "wget", "-O", "/etc/snort/rules/emerging-all.rules", "https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-all.rules"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "sed", "-i", "s|^# include \\$RULE_PATH/emerging-all.rules|include \\$RULE_PATH/emerging-all.rules|", "/etc/snort/snort.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            console.print("[bold red]Failed to install or configure Snort.[/bold red]")
            return False
    return True

# Function to start Snort IDS with enhanced rules
def start_snort_ids():
    if not install_snort():
        return

    console.print("[bold cyan]Starting IDS...[/bold cyan]")
    time.sleep(1)

    # Basic Snort configuration
    snort_config = "/etc/snort/snort.conf"
    if not os.path.exists(snort_config):
        console.print(f"[bold red]Snort configuration file not found at {snort_config}.[/bold red]")
        return

    # Add custom rules to detect various threats
    custom_rules = """
    # Rules to detect reverse shells on various ports
    alert tcp any any -> any 4444 (msg:"Possible Reverse Shell Detected on Port 4444"; sid:1000002; rev:1;)
    alert tcp any any -> any 5555 (msg:"Possible Reverse Shell Detected on Port 5555"; sid:1000003; rev:1;)
    alert tcp any any -> any 6666 (msg:"Possible Reverse Shell Detected on Port 6666"; sid:1000004; rev:1;)

    # Rules to detect DDoS
    alert udp any any -> any any (msg:"Possible DDoS Attack - High UDP Traffic"; threshold:type both, track by_src, count 100, seconds 10; sid:1000005; rev:1;)

    # Rules to detect portscan
    alert tcp any any -> any any (msg:"Possible Port Scan Detected"; detection_filter:track by_src, count 20, seconds 10; sid:1000006; rev:1;)

    # Rules to detect ICMP ping flood
    alert icmp any any -> any any (msg:"Possible ICMP Ping Flood Detected"; threshold:type both, track by_src, count 50, seconds 5; sid:1000007; rev:1;)

    # Rules to detect exploits
    alert tcp any any -> any any (msg:"Possible Exploit Attempt"; content:"|90 90 90 90|"; sid:1000008; rev:1;)

    # Rules to detect ransomwares
    alert tcp any any -> any any (msg:"Possible Ransomware C2 Connection"; content:"ransom"; nocase; sid:1000009; rev:1;)

    # Rules to detect suspicious commands
    alert tcp any any -> any any (msg:"Possible Suspicious Command Execution"; content:"|2f 62 69 6e 2f 73 68|"; nocase; sid:1000010; rev:1;)
    """
    with open("/etc/snort/rules/local.rules", "w") as f:
        f.write(custom_rules)

    # Command to start Snort in monitoring mode with enhanced rules
    snort_command = f"sudo snort -A console -q -c {snort_config} -i {ni.gateways()['default'][ni.AF_INET][1]}"

    try:
        console.print("[bold green]IDS is now running. Monitoring network traffic...[/bold green]")
        console.print("[bold yellow]Press Ctrl+C to stop IDS.[/bold yellow]")
        os.system(snort_command)
    except KeyboardInterrupt:
        console.print("[bold red]IDS stopped.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error starting IDS: {e}[/bold red]")

# Function to analyze syscalls using auditd
def analyze_syscalls():
    console.print("[bold cyan]Starting syscall analysis...[/bold cyan]")
    time.sleep(1)

    # Install auditd if not installed
    if not os.path.exists("/usr/sbin/auditd"):
        console.print("[bold yellow]auditd not found. Installing...[/bold yellow]")
        subprocess.run(["sudo", "apt-get", "install", "-y", "auditd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Configure audit rules for suspicious syscalls
    audit_rules = """
    # Monitor execution of suspicious commands
    -a always,exit -F arch=b64 -S execve -k suspicious_commands

    # Monitor access to sensitive files
    -a always,exit -F path=/etc/passwd -F perm=rw -k sensitive_files
    """
    with open("/etc/audit/rules.d/syscall.rules", "w") as f:
        f.write(audit_rules)

    # Restart auditd to apply new rules
    subprocess.run(["sudo", "service", "auditd", "restart"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    console.print("[bold green]Syscall analysis is now running. Monitoring system calls...[/bold green]")
    console.print("[bold yellow]Press Ctrl+C to stop syscall analysis.[/bold yellow]")

    try:
        # Display audit logs in real-time
        os.system("sudo ausearch -k suspicious_commands | aureport -i")
    except KeyboardInterrupt:
        console.print("[bold red]Syscall analysis stopped.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error analyzing syscalls: {e}[/bold red]")

# Function to ask the user if they want to save logs
def ask_to_save_logs():
    save_logs = input("Do you want to save the logs? (y/n): ").strip().lower()
    return save_logs == 'y'

# Function to save logs to a file
def save_logs(log_content, log_type):
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Create subdirectory for the log type
    type_dir = os.path.join(log_dir, log_type)
    if not os.path.exists(type_dir):
        os.makedirs(type_dir)

    # Create a timestamped log file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(type_dir, f"{timestamp}.log")

    # Write the log content to the file
    with open(log_file, "w") as f:
        f.write(log_content)

    console.print(f"[bold green]Logs saved at: {log_file}[/bold green]")

# Main function
def main():
    api_key = 'YOUR KEY!'  # Replace with your VirusTotal API key

    # Display the initial menu
    console.print("1 - Vulnerability Scan", style="bold white")
    time.sleep(0.1)
    console.print("2 - Monitoring System (IDS)", style="bold white")
    time.sleep(0.1)
    console.print("3 - Malicious File Checker", style="bold white")
    time.sleep(0.1)
    console.print("4 - Analyze Syscalls", style="bold white")
    time.sleep(0.1)

    option = input("Enter an option: ")

    if option == "1":
        console.print("[bold cyan]You selected option 1 - Vulnerability Scan[/bold cyan]")
        time.sleep(0.5)
        console.print("\n[bold white]Collecting network information...[/bold white]")
        time.sleep(1.5)
        scan_result, network = scan_network()
        console.print(scan_result)
        time.sleep(0.5)

        if network:
            target_ip = f"{network.network_address}/{network.prefixlen}"
            console.print(f"\n[bold white]Performing ARP Sweep for:[/bold white] {target_ip}\n")
            host_ports = arp_sweep_and_classify(target_ip)

            console.print("\n[bold green]Open port scan result:[/bold green]")
            log_content = ""
            for ip, ports in host_ports.items():
                console.print(f"\n[bold cyan]{ip}:[/bold cyan]")
                log_content += f"\n{ip}:\n"
                for port, service in ports.items():
                    vulnerability_status = validate_vulnerability(ip, port, service)
                    console.print(vulnerability_status)
                    log_content += vulnerability_status + "\n"

            if ask_to_save_logs():
                save_logs(log_content, "vulnerability_scan")
        else:
            console.print("[bold red]Could not determine the network for scanning.[/bold red]")
    elif option == "2":
        console.print("[bold cyan]You selected option 2 - Monitoring System (IDS)[/bold cyan]")
        start_snort_ids()  # Call the function to start Snort IDS
    elif option == "3":
        console.print("[bold cyan]You selected option 3 - Malicious File Checker[/bold cyan]")
        check_malicious_file(api_key)
    elif option == "4":
        console.print("[bold cyan]You selected option 4 - Analyze Syscalls[/bold cyan]")
        analyze_syscalls()
    else:
        console.print("[bold red]Invalid option[/bold red]")

# Run the program
if __name__ == "__main__":
    main()
