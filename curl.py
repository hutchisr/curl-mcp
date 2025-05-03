#!/usr/bin/env python3
"""
Simple MCP server for making HTTP requests.
"""

import json as json_module
import logging
import os
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse, urlunparse

import requests
from fastmcp import FastMCP
from requests_oauthlib import OAuth2Session

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("curl-mcp")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

class CurlMCPServer(FastMCP):
    """MCP server that provides HTTP request capabilities."""

    def __init__(self):
        super().__init__(
            name="curl-mcp",
            description="MCP server for making HTTP requests",
        )

        # Token cache to store OAuth2 tokens
        # Structure: {client_id: {"token": token_dict, "token_type": token_type}}
        self.token_cache = {}

        # OAuth2 callback server
        self.callback_server = None
        self.callback_server_thread = None
        self.pending_oauth_requests = {}  # {state: {client_id, token_url, etc.}}

        # Register tools
        self.add_tool(
            fn=self.http_request,
            name="http_request",
            description="Make an HTTP request to a specified URL"
        )


        self.add_tool(
            fn=self.oauth2_authorize_and_fetch_token,
            name="oauth2_authorize_and_fetch_token",
            description="Create an OAuth2 authorization URL, open browser, and automatically fetch token"
        )

        # Register resources
        self.add_resource_fn(
            fn=self.get_readme,
            uri="http-client://readme",
            description="Documentation for the HTTP client"
        )

    def http_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json: Optional[Union[Dict[str, Any], List[Any]]] = None,
        timeout: float = 30,
        client_id: Optional[str] = None,
    ) -> str:
        """
        Make an HTTP request to the specified URL.

        Args:
            url: The URL to send the request to
            method: The HTTP method to use (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
            headers: HTTP headers to include in the request
            params: URL parameters to include in the request
            data: Data to send in the request body
            json: JSON data to send in the request body
            timeout: Request timeout in seconds
            client_id: OAuth2 client ID to use for token lookup (if provided and token exists in cache)

        Returns:
            A string containing the response details
        """
        logger.info(f"Making {method} request to {url}")

        # Initialize headers if None
        if headers is None:
            headers = {}

        # Use cached token if client_id is provided and token exists in cache
        if client_id and client_id in self.token_cache:
            cached_data = self.token_cache[client_id]
            token = cached_data["token"]
            token_type = cached_data["token_type"]

            # Always use the cached token if client_id is provided
            if "access_token" in token:
                auth_header = f"{token_type} {token['access_token']}"
                headers["Authorization"] = auth_header
                logger.info(f"Using cached token for client {client_id}")
        # Failsafe: If no client_id is specified but there's only one token in the cache, use it
        elif not client_id and len(self.token_cache) == 1:
            # Get the only client_id in the cache
            auto_client_id = list(self.token_cache.keys())[0]
            cached_data = self.token_cache[auto_client_id]
            token = cached_data["token"]
            token_type = cached_data["token_type"]

            if "access_token" in token:
                auth_header = f"{token_type} {token['access_token']}"
                headers["Authorization"] = auth_header
                logger.info(f"Failsafe: Using the only cached token (client {auto_client_id})")

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json,
                timeout=timeout,
            )

            # Try to parse response as JSON
            try:
                response_json = response.json()
                response_body = json_module.dumps(response_json, indent=2)
            except ValueError:
                # Not JSON, return text
                response_body = response.text

            result = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
            }

            return json_module.dumps(result, indent=2)

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return json_module.dumps({"error": str(e)}, indent=2)


    def get_readme(self) -> str:
        """Return documentation for the HTTP client."""
        return """
# HTTP Client MCP Server

This MCP server provides tools for making HTTP requests to external services, including OAuth2 authorization code flow support.

## Available Tools

### http_request

Make an HTTP request to a specified URL.

If oauth2_authorize_and_fetch_token has been used then a bearer token
associated with the client_id will be cached in memory.

Parameters:
- url (required): The URL to send the request to
- method: The HTTP method to use (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
- headers: HTTP headers to include in the request
- params: URL parameters to include in the request
- data: Data to send in the request body
- json: JSON data to send in the request body
- timeout: Request timeout in seconds (default: 30)
- client_id: OAuth2 client ID to use for token lookup (if provided and token exists in cache)
            If not provided but there's only one token in the cache, that token will be used automatically
            **IMPORTANT**: Always include the same client_id used in oauth2_authorize_and_fetch_token to ensure
            the correct token is used, especially when multiple tokens are cached

Example:
```json
{
  "url": "https://api.example.com/data",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json",
    "Authorization": "Bearer token123"
  },
  "json": {
    "name": "Example",
    "value": 42
  },
  "client_id": "your-client-id"
}
```

Response:
```json
{
  "status_code": 200,
  "headers": {
    "Content-Type": "application/json",
    "Server": "Example Server"
  },
  "body": "{\n  \"success\": true,\n  \"id\": 123\n}"
}
```

"""


    def oauth2_authorize_and_fetch_token(
        self,
        client_id: str,
        authorization_url: str,
        token_url: str,
        redirect_uri: str,
        client_secret: Optional[str] = None,
        scope: Optional[List[str]] = None,
        open_browser: bool = True,
        port: int = 3001,
        path: str = "/callback",
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create an OAuth2 authorization URL, start a callback server, open browser, and automatically fetch token.

        Args:
            client_id: OAuth2 client ID
            authorization_url: Authorization endpoint URL
            token_url: Token endpoint URL
            redirect_uri: Redirect URI for the OAuth2 flow
            client_secret: OAuth2 client secret (optional for public clients)
            scope: List of scopes to request
            open_browser: Whether to automatically open the browser
            port: Port to run the callback server on
            path: Path for the callback endpoint
            kwargs: Additional parameters to include in the authorization URL

        Returns:
            A JSON string containing the authorization URL and state
        """
        logger.info(f"Starting OAuth2 flow with automatic token fetch for client {client_id}")

        if scope is None:
            scope = ["openid"]

        # Parse the redirect_uri to ensure it matches our callback server
        parsed_uri = urlparse(redirect_uri)
        callback_host = parsed_uri.hostname
        callback_port = parsed_uri.port or 80
        callback_path = parsed_uri.path

        # Start the callback server if not already running
        if self.callback_server is None:
            actual_port = self._start_callback_server(callback_port)

            # If the actual port is different from the requested port, update the redirect_uri
            if actual_port != callback_port:
                parsed_parts = list(parsed_uri)
                netloc_parts = parsed_uri.netloc.split(':')
                if len(netloc_parts) > 1:
                    netloc_parts[1] = str(actual_port)
                else:
                    netloc_parts.append(str(actual_port))
                parsed_parts[1] = ':'.join(netloc_parts)
                redirect_uri = urlunparse(parsed_parts)
                logger.info(f"Updated redirect_uri to use port {actual_port}: {redirect_uri}")

        # Create OAuth2 session
        oauth = OAuth2Session(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
        )

        # Create authorization URL
        if kwargs:
            auth_url, state = oauth.authorization_url(
                authorization_url,
                **kwargs
            )
        else:
            auth_url, state = oauth.authorization_url(
                authorization_url
            )

        # Store the request details for when the callback is received
        self.pending_oauth_requests[state] = {
            "client_id": client_id,
            "token_url": token_url,
            "redirect_uri": redirect_uri,
            "client_secret": client_secret,
        }

        # Open the browser if requested
        if open_browser:
            logger.info(f"Opening browser for authorization: {auth_url}")
            webbrowser.open(auth_url)

        result = {
            "authorization_url": auth_url,
            "state": state,
            "message": "Authorization URL opened in browser. Waiting for callback...",
            "callback_server": f"http://{callback_host}:{callback_port}{callback_path}"
        }

        return json_module.dumps(result, indent=2)

    def _start_callback_server(self, port: int, max_retries: int = 5) -> int:
        """
        Start an HTTP server to handle OAuth2 callbacks.

        Args:
            port: Port to run the server on
            max_retries: Maximum number of port numbers to try if the specified port is in use

        Returns:
            The port number that the server is running on
        """
        # Create a request handler that will capture the authorization code
        outer_self = self

        class OAuthCallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    # Parse the query parameters
                    parsed_url = urlparse(self.path)
                    query_params = parse_qs(parsed_url.query)

                    logger.info(f"Received callback: {self.path}")
                    logger.info(f"Query parameters: {query_params}")

                    # Extract the authorization code and state
                    code = query_params.get("code", [""])[0]
                    state = query_params.get("state", [""])[0]

                    logger.info(f"Extracted code: {code[:5]}... and state: {state}")

                    # Send a response to the browser
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()

                    if not code or not state:
                        error_message = "Error: Missing code or state parameter"
                        logger.error(error_message)
                        self.wfile.write(f"<html><body><h1>{error_message}</h1></body></html>".encode())
                        return

                    # Check if we have a pending request for this state
                    if state not in outer_self.pending_oauth_requests:
                        error_message = f"Error: No pending OAuth request found for state: {state}"
                        logger.error(error_message)
                        logger.error(f"Available states: {list(outer_self.pending_oauth_requests.keys())}")
                        self.wfile.write(f"<html><body><h1>{error_message}</h1></body></html>".encode())
                        return

                    # Get the request details
                    request_details = outer_self.pending_oauth_requests[state]

                    outer_self._fetch_token_from_callback(code, state, request_details)

                    # Send a success message to the browser
                    self.wfile.write("""
                    <html>
                        <body>
                            <h1>Authorization Successful</h1>
                            <p>You can close this window now.</p>
                        </body>
                    </html>
                    """.encode())

                except Exception as e:
                    logger.error(f"Error handling callback: {str(e)}")
                    self.send_response(500)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(f"<html><body><h1>Error: {str(e)}</h1></body></html>".encode())

        # Try to start the server, incrementing the port number if it's already in use
        current_port = port
        for attempt in range(max_retries):
            try:
                self.callback_server = HTTPServer(("localhost", current_port), OAuthCallbackHandler)
                self.callback_server_thread = threading.Thread(
                    target=self.callback_server.serve_forever,
                    daemon=True
                )
                self.callback_server_thread.start()
                logger.info(f"OAuth2 callback server started on port {current_port}")
                return current_port
            except OSError as e:
                if e.errno == 48:  # Address already in use
                    logger.warning(f"Port {current_port} is already in use, trying port {current_port + 1}")
                    current_port += 1
                else:
                    logger.error(f"Failed to start callback server: {str(e)}")
                    raise

        # If we've exhausted all retries, raise an exception
        error_msg = f"Failed to find an available port after {max_retries} attempts"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    def _fetch_token_from_callback(self, code: str, state: str, request_details: Dict[str, Any]) -> None:
        """
        Fetch an OAuth2 token using the authorization code from the callback.

        Args:
            code: Authorization code
            state: State parameter
            request_details: Dictionary containing the request details
        """
        try:
            # Extract the request details
            client_id = request_details["client_id"]
            token_url = request_details["token_url"]
            redirect_uri = request_details["redirect_uri"]
            client_secret = request_details.get("client_secret")

            logger.info(f"Fetching token for client {client_id} from callback")
            logger.info(f"Token URL: {token_url}")
            logger.info(f"Redirect URI: {redirect_uri}")
            logger.info(f"Using client secret: {bool(client_secret)}")

            # Create OAuth2 session
            oauth = OAuth2Session(
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
            )

            # Fetch token
            fetch_kwargs = {"code": code}

            # Add client_secret if provided
            if client_secret:
                fetch_kwargs["client_secret"] = client_secret

            token = oauth.fetch_token(
                token_url=token_url,
                **fetch_kwargs
            )

            # Cache the token
            token_type = token.get("token_type", "Bearer")
            self.token_cache[client_id] = {
                "token": token,
                "token_type": token_type
            }

            logger.info(f"Token successfully fetched and cached for client {client_id}")
            logger.info(f"Token type: {token_type}")
            logger.info(f"Token value: {token.get('access_token', 'N/A')}")
            logger.info(f"Token expires in: {token.get('expires_in', 'N/A')} seconds")
            logger.info(f"Token scope: {token.get('scope', 'N/A')}")
        finally:
            # Clean up
            if state in self.pending_oauth_requests:
                del self.pending_oauth_requests[state]

def main():
    """Run the MCP server."""
    logger.info("Starting curl-mcp server...")
    server = CurlMCPServer()
    # server.run(transport="sse", host="localhost", port=9090)
    server.run()


if __name__ == "__main__":
    main()
