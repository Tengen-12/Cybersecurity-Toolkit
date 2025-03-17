import requests
import json
import re
from urllib.parse import urlparse
from enum import Enum

# ANSI Color Codes
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_RESET = "\033[0m"

class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"

def colored_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}"

def validate_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

def validate_json(input_str: str) -> bool:
    try:
        json.loads(input_str)
        return True
    except json.JSONDecodeError:
        return False

def get_valid_input(prompt: str, validation_func, error_msg: str) -> str:
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input):
            return user_input
        print(colored_text(f"Invalid input: {error_msg}", COLOR_RED))

def select_http_method() -> HttpMethod:
    print(colored_text("Select HTTP Method:", COLOR_CYAN))
    for i, method in enumerate(HttpMethod, 1):
        print(f"{i}. {method.value}")
    
    while True:
        choice = input(colored_text("Enter choice (1-5): ", COLOR_YELLOW))
        if choice.isdigit() and 1 <= int(choice) <= len(HttpMethod):
            return list(HttpMethod)[int(choice)-1]
        print(colored_text("Invalid choice! Please select 1-5", COLOR_RED))

def format_headers(headers_str: str) -> dict:
    try:
        return json.loads(headers_str) if headers_str else {}
    except json.JSONDecodeError:
        print(colored_text("Warning: Headers not in valid JSON format. Using empty headers.", COLOR_YELLOW))
        return {}

def test_api():
    print(colored_text("\n=== API Testing Interface ===", COLOR_MAGENTA))
    
    # Get user inputs with validation
    method = select_http_method()
    url = get_valid_input(
        colored_text("Enter API URL: ", COLOR_YELLOW),
        validate_url,
        "Must be a valid URL starting with http:// or https://"
    )
    
    headers = {}
    if input(colored_text("Add custom headers? (y/N): ", COLOR_YELLOW)).lower() == 'y':
        headers_str = get_valid_input(
            colored_text("Enter headers as JSON (e.g., {\"Content-Type\":\"application/json\"}): ", COLOR_YELLOW),
            lambda x: x == '' or validate_json(x),
            "Must be valid JSON or empty"
        )
        headers = format_headers(headers_str)
    
    params = {}
    if input(colored_text("Add URL parameters? (y/N): ", COLOR_YELLOW)).lower() == 'y':
        params_str = get_valid_input(
            colored_text("Enter parameters as JSON (e.g., {\"key\":\"value\"}): ", COLOR_YELLOW),
            lambda x: x == '' or validate_json(x),
            "Must be valid JSON or empty"
        )
        params = json.loads(params_str) if params_str else {}
    
    data = None
    if method != HttpMethod.GET and input(colored_text("Add request body? (y/N): ", COLOR_YELLOW)).lower() == 'y':
        data_str = get_valid_input(
            colored_text("Enter request body as JSON: ", COLOR_YELLOW),
            validate_json,
            "Must be valid JSON"
        )
        data = json.loads(data_str)

    # Execute request
    try:
        response = requests.request(
            method=method.value,
            url=url,
            headers=headers,
            params=params,
            json=data,
            timeout=10
        )

        print(colored_text("\n=== Response Details ===", COLOR_BLUE))
        print(colored_text(f"Status Code: {response.status_code}", 
              COLOR_GREEN if response.ok else COLOR_RED))
        print(colored_text(f"Response Time: {response.elapsed.total_seconds():.2f}s", COLOR_CYAN))
        
        try:
            formatted_json = json.dumps(response.json(), indent=2)
            print(colored_text("\nResponse Body:", COLOR_BLUE))
            print(formatted_json)
        except json.JSONDecodeError:
            print(colored_text("\nResponse Body (non-JSON):", COLOR_BLUE))
            print(response.text)

    except requests.exceptions.RequestException as e:
        print(colored_text(f"\nRequest failed: {str(e)}", COLOR_RED))

def main():
    while True:
        test_api()
        if input(colored_text("\nTest another API? (y/N): ", COLOR_YELLOW)).lower() != 'y':
            break

if __name__ == "__main__":
    main()