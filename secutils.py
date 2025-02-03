import requests
import whois
import nmap
import socket
import ssl
import json
import os
import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import re
import time
from androguard.core import androconf
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis import analysis
from androguard.decompiler import decompiler

# Setting up logger for production-level logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def decompile_dex(dex_file):
    decompiler = decompiler(dex_file)
    decompiled_code = decompiler.get_code()
    return decompiled_code

# Utility function to check if the input is a valid URL
def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.))' # domain...
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Utility function to get the HTTP response from a URL
def get_http_response(url, retries=3, timeout=10):
    """Get HTTP response with retry and timeout."""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()  # Raise an exception for HTTP errors (4xx, 5xx)
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Attempt {attempt + 1} failed to fetch {url}: {e}")
            if attempt == retries - 1:
                return None
            time.sleep(2 ** attempt)  # Exponential backoff for retries

# Utility function to get the HTTP response from a URL
def get_http_response(url, retries=3, timeout=10):
    attempt = 0
    while attempt < retries:
        try:
            response = requests.get(url, timeout=timeout)  # Set a timeout to avoid hanging
            response.raise_for_status()  # Raise an exception for HTTP errors (4xx, 5xx)
            return response
        except requests.exceptions.RequestException as e:
            attempt += 1
            print(f"Error fetching {url} (Attempt {attempt}/{retries}): {e}")
            if attempt < retries:
                time.sleep(2)  # Wait for 2 seconds before retrying
            else:
                print("Max retries reached. Could not fetch the URL.")
                return None

# Function to detect open ports and services
def detect_open_ports(url):
    try:
        # Extract the hostname (domain) from the URL
        target_hostname = urlparse(url).hostname
        
        # Resolve the domain to an IP address
        target_ip = socket.gethostbyname(target_hostname)
        
        # Initialize Nmap PortScanner
        nm = nmap.PortScanner()
        
        # Perform a simple port scan on the target (1-1024 ports)
        nm.scan(target_ip, '1-1024')
        open_ports = []
        
        # Loop through all protocols (TCP/UDP)
        for protocol in nm[target_ip].all_protocols():
            lport = nm[target_ip][protocol].keys()
            for port in lport:
                open_ports.append({'Port': port, 'State': nm[target_ip][protocol][port]['state']})
        
        return open_ports

    except Exception as e:
        logger.error(f"Error detecting open ports for {url}: {e}")
        return None


# Function to detect OS (using Nmap)
def detect_os(url):
    try:
        # Extract the hostname (domain) from the URL
        target_hostname = urlparse(url).hostname
        
        # Resolve the domain to an IP address
        target_ip = socket.gethostbyname(target_hostname)
        
        # Initialize Nmap PortScanner
        nm = nmap.PortScanner()
        
        # Perform a simple port scan on the target (1-1024 ports)
        nm.scan(target_ip, '1-1024')
        
        # Get OS match info (if available)
        os_info = nm[target_ip].get('osmatch', 'N/A')
        return os_info

    except Exception as e:
        logger.error(f"Error detecting OS for {url}: {e}")
        return 'N/A'

# Function to collect website metadata including domain info, SSL, CDN, and more
def collect_website_info(url):
    """Collect website metadata including domain info, SSL, CDN, OS, open ports, and HTTP headers."""
    result = {}

    # Parse domain info using WHOIS
    try:
        domain_info = whois.whois(url)
        result['Domain'] = domain_info.domain_name if domain_info.domain_name else 'N/A'
    except Exception as e:
        logger.error(f"Error fetching WHOIS data for {url}: {e}")
        result['Domain'] = 'N/A'

    # Get the HTTP Response
    response = get_http_response(url)
    if not response:
        return result  # Return the result so far if no response

    # Extract Title from HTML
    soup = BeautifulSoup(response.text, 'html.parser')
    title = soup.find('title')
    result['Title'] = title.text if title else 'N/A'

    # Extract additional metadata from headers (e.g., X-Powered-By, Content-Length, Server)
    result['X-Powered-By'] = response.headers.get('X-Powered-By', 'N/A')
    result['Content-Length'] = response.headers.get('Content-Length', 'N/A')
    result['Server'] = response.headers.get('Server', 'N/A')

    # Check SSL certificate info
    cert = None
    try:
        cert = ssl.get_server_certificate((urlparse(url).hostname, 443))
        result['SSL Certificate'] = cert
    except Exception as e:
        result['SSL Certificate'] = 'Not Available'

    # Detect CDN (via headers or other means)
    cdn_providers = ['Cloudflare', 'Akamai', 'Fastly', 'AWS']
    cdn = next((provider for provider in cdn_providers if provider in response.headers.get('Server', '')), 'None')
    result['CDN'] = cdn

    # Check the HTTP Status Code
    result['HTTP Status Code'] = response.status_code

    # Detect Open Ports
    open_ports = detect_open_ports(url)
    if open_ports:
        result['Open Ports'] = open_ports
    else:
        result['Open Ports'] = 'N/A'

    # Detect OS Information
    os_info = detect_os(url)
    result['OS'] = os_info

    return result

def network_scan(target):
    """Perform network scan to gather open ports, services, OS, and other info."""
    nm = nmap.PortScanner()

    # Perform an aggressive scan (-A) with service version detection (-sV) and default safe scripts
    try:
        nm.scan(target, '1-65535', arguments='-A -sV --script=default,safe')
    except nmap.nmap.PortScannerError as e:
        logger.error(f"Network scan failed for {target}: {e}")
        return {}

    result = {}

    for host in nm.all_hosts():
        result[host] = {}

        # Host Information
        result[host]['HostName'] = nm[host].hostname() if nm[host].hostname() else 'N/A'
        result[host]['State'] = nm[host].state()

        # Protocols Detected
        result[host]['Protocol'] = nm[host].all_protocols()

        # Open Ports and their Service Versions
        result[host]['Ports'] = []
        for protocol in ['tcp', 'udp']:
            if protocol in nm[host]:
                for port in nm[host][protocol].keys():
                    port_info = {
                        'Port': port,
                        'State': nm[host][protocol][port]['state'],
                        'Service': nm[host][protocol][port].get('name', 'N/A'),
                        'Version': nm[host][protocol][port].get('version', 'N/A')
                    }
                    result[host]['Ports'].append(port_info)

        # OS Detection
        result[host]['OS'] = nm[host].get('osmatch', 'N/A')

        # Traceroute Information
        result[host]['Traceroute'] = nm[host].get('hostnames', 'N/A')

        # MAC Address Detection (for local networks)
        result[host]['MAC Address'] = nm[host].get('addresses', {}).get('mac', 'N/A')

        # Adding Scripts Output (for vulnerabilities, or specific services)
        result[host]['Scripts'] = nm[host].get('script', 'N/A')

    return result


def analyze_apk(apk_path):
    """Perform static analysis on APK file to extract sensitive information."""
    result = {}

    if not os.path.exists(apk_path):
        logger.error(f"APK file {apk_path} not found.")
        return result  # Return empty result if APK is not found

    try:
        # Load the APK using Androguard
        apk = APK(apk_path)

        # Extract basic metadata
        result['APK Path'] = apk_path
        result['Package Name'] = apk.get_package()  # Extract package name
        result['Version'] = apk.get_androidversion_name()  # Extract version
        result['Permissions'] = apk.get_permissions()  # Extract permissions
        result['Activities'] = apk.get_activities()  # List of activities
        result['Services'] = apk.get_services()  # List of services
        result['Receivers'] = apk.get_receivers()  # List of broadcast receivers
        result['Providers'] = apk.get_providers()  # List of content providers

        # Check for hardcoded sensitive data such as API keys or secrets
        sensitive_keywords = ['api_key', 'password', 'secret', 'token']
        result['Sensitive Information'] = check_sensitive_data(apk, sensitive_keywords)

        # Get the manifest data (AndroidManifest.xml)
        result['Manifest'] = apk.get_android_manifest()  # Corrected method for manifest

        # Analyze certificate information
        cert_fingerprints = apk.get_certificates()
        result['Certificate Fingerprints'] = cert_fingerprints

        # Analyze the decompiled code for sensitive patterns or hardcoded credentials
        dex_code = apk.get_dex()
        decompiler = DecompdilerDAD(dex_code)  # Corrected use of DecompilerDAD
        decompiled_code = decompiler.get_code()
        result['Decompiled Code'] = decompiled_code

        # Log successful analysis
        logger.info(f"Successfully analyzed APK: {apk_path}")

    except Exception as e:
        logger.error(f"Failed to analyze APK {apk_path}: {e}")
        result['Error'] = f"Failed to analyze APK: {e}"

    return result

def check_sensitive_data(apk, keywords):
    """Search for sensitive keywords in the APK's decompiled files."""
    sensitive_data = []

    # Get the DEX code
    dex_code = apk.get_dex()

    try:
        # Decompile DEX to readable format
        decompiler = DecompilerDAD(dex_code)
        decompiled = decompiler.get_code()

        # Check for keywords in the decompiled code
        for keyword in keywords:
            if keyword in decompiled:
                sensitive_data.append(keyword)
    except Exception as e:
        logger.warning(f"Failed to scan for sensitive data: {e}")
    
    return sensitive_data


def detect_target_type(target):
    target_type = 'unknown'

    # Check if it's a valid URL
    if is_valid_url(target):
        logger.info(f"Valid URL detected: {target}")
        if target.lower().endswith(('apk', 'ipa')):  # If it's an APK or IPA file
            target_type = 'mobile_app'
        else:
            target_type = 'website'
    
    # Check if it's a valid file path (for .apk files)
    elif os.path.isfile(target) and target.lower().endswith('.apk'):
        target_type = 'mobile_app'
    
    # Check if it's an IP address (simple check)
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', target):  # If it's an IP address
        target_type = 'network'
    
    else:
        logger.warning(f"Unrecognized target type: {target}")

    return target_type


def collect_info(target):
    """Collect data based on the detected target type."""
    result = {}
    target_type = detect_target_type(target)

    if target_type == 'mobile_app':
        logger.info(f"Analyzing mobile app: {target}")
        result['Mobile App Info'] = analyze_apk(target)
    elif target_type == 'website':
        logger.info(f"Collecting website information for: {target}")
        result['Website Info'] = collect_website_info(target)
    elif target_type == 'network':
        logger.info(f"Performing network scan for: {target}")
        result['Network Scan'] = network_scan(target)
    else:
        logger.warning(f"Unrecognized target type: {target}")
        result['Error'] = 'Unrecognized target type.'

    return result


def save_results(results, output_file='scan_results.json'):
    """Save the results to a JSON file."""
    try:
        with open(output_file, 'w') as outfile:
            json.dump(results, outfile, indent=4)
        logger.info(f"Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")


if __name__ == "__main__":
    target = input("Enter the target (URL, IP, or file path): ")
    results = collect_info(target)
    save_results(results)
