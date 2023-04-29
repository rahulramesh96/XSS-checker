import requests
import re
import urllib.parse
import json
import random
import string

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

def check_xss(url):
    """
    Checks a web application for potential XSS vulnerabilities using advanced payloads.

    Args:
        url (str): The URL of the web application.

    Returns:
        None. Prints any potential vulnerabilities found.
    """
    # Send a GET request to the URL
    response = requests.get(url)

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
        response = requests.post(url, data=data)
        for payload in data.values():
            if payload in response.text:
                print(f"Possible reflected XSS vulnerability found in {url} with payload {payload}")

if __name__ == "__main__":
    help_message = """
    Welcome to the advanced XSS vulnerability checker!

    Usage:
        python xss_checker.py [url]

    Arguments:
        url (str): The URL of the web application to test.

    Example usage:
        python xss_checker.py "http://example.com/myapp"
    """
    if len(sys.argv) < 2:
        print(help_message)
    else:
        url = sys.argv[1]
        check_xss(url)
