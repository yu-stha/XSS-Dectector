#!/usr/bin/env python3
"""
XSS Vulnerability Scanner - A tool to detect XSS vulnerabilities in web forms.
"""

import os
import platform
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import colorama
import requests

# XSS payloads for testing
xss_payloads = [
    "<script>alert('XSS');</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<img src=1 href=1 onerror='javascript:alert(1)'></img>",
    "<audio src=1 href=1 onerror='javascript:alert(1)'></audio>",
    "<video src=1 href=1 onerror='javascript:alert(1)'></video>"
    # Add more payloads as needed
]

def clear_screen():
    """Clear terminal screen based on the operating system."""
    system = platform.system()
    if system == "Windows":
        os.system("cls")
    elif system == "Linux":
        os.system("clear")

def get_all_forms(url):
    """Extract all forms from the URL."""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """Extract form details including action, method and inputs."""
    details = {}
    # Get the form action (target URL)
    action = form.attrs.get("action", "")
    if action:
        action = action.lower()
    
    # Get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    
    # Get all form inputs
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    """Submit the form with the given payload value."""
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
    
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    return requests.get(target_url, params=data)

def scan_xss(url):
    """Scan for XSS vulnerabilities in the target URL."""
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    for form in forms:
        form_details = get_form_details(form)
        
        for payload in xss_payloads:
            response = submit_form(form_details, url, payload)
            if payload in response.content.decode():
                print(colorama.Fore.RED + f"[!] XSS Detected on {url}")
                print(colorama.Fore.YELLOW + f"[*] Form details:")
                pprint(form_details)
                break
            else:
                print(f"[-] No XSS Detected on {url}")
                break

if __name__ == "__main__":
    #clear_screen()  # Commented out as in your original code
    colorama.init()
    url = input("Enter the target URL: ")
    scan_xss(url)
    colorama.deinit()