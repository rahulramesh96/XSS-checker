import requests
import re
import urllib.parse
import json
import random
import string
import argparse

def generate_payload():
    """
    Generates a random XSS payload using various obfuscation techniques.

    Returns:
        str: A randomly generated XSS payload.
    """
    # Generate random JavaScript function name
    function_name = "".join(random.choice(string.ascii_letters) for i in range(10))

    # Define JavaScript function that alerts the current URL
    js_function = f"function {function_name}(){{alert(window.location.href);}}"

    # Add HTML tags to execute JavaScript function
    html_tag = f"<img src=1 onerror={function_name}()>"

    # URL-encode the payload
    encoded_payload = urllib.parse.quote(html_tag, safe='')

    return encoded_payload

def check_xss(url, auth=None):
    """
    Checks a web application for potential XSS vulnerabilities using advanced payloads.

    Args:
        url (str): The URL of the web application.
        auth (tuple): A tuple containing the user ID and password for authentication. Default: None (unauthenticated scan)

    Returns:
        None. Prints any potential vulnerabilities found.
    """
    # Send a GET request to the URL with authentication headers if provided
    session = requests.Session()
    if auth is not None:
        session.auth = auth
    response = session.get(url)

    # Check the response headers and content for potential XSS vulnerabilities
    if 'Content-Security-Policy' not in response.headers:
        print(f"Error: no Content-Security-Policy header found in {url}")
    if re.search(r"<script>.*</script>", response.text):
        print(f"Possible XSS vulnerability found in {url}: <script> tag detected")
    if re.search(r"javascript:", response.text):
        print(f"Possible XSS vulnerability found in {url}: javascript: protocol detected")

    # Send a POST request with random payload to each input field in any forms on the page
    forms = re.findall(r"<form .*?>.*?</form>", response.text, re.DOTALL)
    for form in forms:
        inputs = re.findall(r"<input .*?>", form, re.DOTALL)
        data = {}
        for input_tag in inputs:
            input_name = re.search(r"name=['\"](.*?)['\"]", input_tag).group(1)
            data[input_name] = generate_payload()
        response = session.post(url, data=data)
        for payload in data.values():
            if payload in response.text:
                print(f"Possible reflected XSS vulnerability found in {url} with payload {payload}")
                print("Remediation: Use proper output encoding to prevent untrusted data from being interpreted as code.")

    # Scan all links on the page for potential DOM-based XSS vulnerabilities
    links = re.findall(r"<a .*?>", response.text)
    for link in links:
        href = re.search(r"href=['\"](.*?)['\"]", link).group(1)
        if "javascript:" in href:
            print(f"Possible DOM-based XSS vulnerability found in {url}: {link}")
            print("Remediation: Use proper input validation and sanitization to prevent untrusted data from being executed as script.")

    # Check any JavaScript files included in the response for potential vulnerabilities
    scripts = re.findall(r"<script .*?>.*?</script>", response.text, re.DOTALL)
    for script in scripts:
        if "document.cookie" in script or "window.location" in script:
            print(f"Possible stored XSS vulnerability found in {url}: {script[:50]}...")
            print("Remediation: Use proper input validation and sanitization to prevent untrusted data from being executed as script.")

    # Check for potential XSS vulnerabilities in any JSON data returned by the application
    json_data = re.findall(r"{.*?}", response.text)
    for data in json_data:
        try:
            decoded_data = json.loads(data)
        except:
            continue
        for key, value in decoded_data.items():
            if isinstance(value, str):
                encoded_value = urllib.parse.quote(value, safe='')
                attack_strings = [
                    f"<script>{value}</script>",
                    f"<img src=x onerror=alert({value})>",
                    f"'{value}",
                    f'"{value}"',
                    f'{value}; alert(1)//',
                    f'"><svg/onload=alert({value})>'
                ]
                for attack in attack_strings:
                    if attack in data or encoded_value in data:
                        print(f"Possible reflected XSS vulnerability found in {url} with JSON key {key} and data {data[:50]}...")

if __name__ == "__main__":
    # Set up command line argument
