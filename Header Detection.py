import requests

def check_missing_security_headers(url):
    """
    Checks for missing security headers and provides descriptions for each missing header.

    Parameters:
        url (str): The URL of the target website.
    """
    # Comprehensive list of headers and their descriptions
    security_headers = {
        "Content-Security-Policy": (
            "Helps to prevent Cross-Site Scripting (XSS) and other code injection attacks by specifying trusted sources for content."
        ),
        "Strict-Transport-Security": (
            "Enforces secure (HTTPS) connections to the server to prevent protocol downgrade attacks."
        ),
        "X-Frame-Options": (
            "Protects against clickjacking attacks by controlling whether the site can be embedded in an iframe."
        ),
        "X-Content-Type-Options": (
            "Prevents MIME type sniffing to mitigate attacks based on MIME type confusion."
        ),
        "Referrer-Policy": (
            "Controls how much referrer information is included with requests to prevent leaking sensitive URLs."
        ),
        "Permissions-Policy": (
            "Controls access to browser features such as camera, microphone, or geolocation to protect user privacy."
        ),
        "Access-Control-Allow-Origin": (
            "Restricts which domains can access the site's resources to mitigate CORS issues."
        ),
        "Expect-CT": (
            "Helps monitor and enforce Certificate Transparency for HTTPS connections."
        ),
        "Cross-Origin-Embedder-Policy": (
            "Ensures resources cannot be loaded cross-origin unless explicitly allowed."
        ),
        "Cross-Origin-Resource-Policy": (
            "Restricts cross-origin access to resources to mitigate data leaks."
        ),
        "Cross-Origin-Opener-Policy": (
            "Isolates browsing contexts to mitigate cross-origin attacks."
        ),
        "Cache-Control": (
            "Specifies caching mechanisms to optimize performance."
        ),
        "Expires": (
            "Sets expiration dates for resources to reduce load time."
        ),
        "ETag": (
            "Tracks changes to resources for efficient conditional requests."
        ),
        "Last-Modified": (
            "Indicates when a resource was last changed to support caching."
        ),
        "Vary": (
            "Adjusts cache based on request headers like language or user-agent."
        ),
        "Connection": (
            "Controls whether the connection remains open (e.g., 'keep-alive')."
        ),
        "Transfer-Encoding": (
            "Specifies how the response payload is encoded (e.g., chunked)."
        ),
        "Content-Encoding": (
            "Indicates compression methods like gzip or Brotli for the response."
        ),
        "Content-Length": (
            "Specifies the size of the response body."
        ),
        "Accept-Ranges": (
            "Allows partial content delivery for large files (e.g., video streaming)."
        ),
        "Content-Type": (
            "Specifies the media type of the resource (e.g., text/html, application/json)."
        ),
        "Content-Language": (
            "Specifies the language of the content for localization."
        ),
        "Server": (
            "Identifies the web server software (can be omitted for security reasons)."
        ),
        "Set-Cookie": (
            "Stores session and user-specific data for stateful interactions."
        ),
        "X-Powered-By": (
            "Indicates the technology powering the website (can be omitted for security reasons)."
        ),
        "Location": (
            "Specifies the URL to which the client should be redirected."
        ),
        "Retry-After": (
            "Indicates when the client should retry a failed request."
        ),
    }

    try:
        response = requests.get(url)
        headers = response.headers

        print(f"[*] Checking missing headers for: {url}\n")
        missing_headers = False

        for header, description in security_headers.items():
            if header not in headers:
                print(f"[-] Missing: {header}")
                print(f"    Description: {description}\n")
                missing_headers = True

        if not missing_headers:
            print("[+] All headers are present.")

    except Exception as e:
        print(f"[!] Error checking headers: {e}")

# Example usage:
if __name__ == "__main__":
    target_url = "www.example.com"  # Replace with the target URL
    check_missing_security_headers(target_url)
