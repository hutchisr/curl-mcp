"""
Simple MCP server for making HTTP requests.
"""

import atexit
import json as json_module
import logging
import os
import asyncio
import webbrowser
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse, urlunparse

import httpx
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("curl-mcp")

# Create FastMCP instance
mcp = FastMCP(
    name="curl-mcp",
    description="MCP server for making HTTP requests",
)


@dataclass
class State:
    """Class to hold the state of the MCP server."""
    # Token cache to store OAuth2 tokens
    # Structure: {client_id: {"token": token_dict, "token_type": token_type}}
    token_cache: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # OAuth2 callback server
    callback_server: Optional[Any] = None
    callback_server_task: Optional[asyncio.Task] = None

    # Pending OAuth requests
    # Structure: {state: {client_id, token_url, etc.}}
    pending_oauth_requests: Dict[str, Dict[str, Any]] = field(default_factory=dict)


# Create a state instance
app_state = State()


@mcp.tool(
    name="http_request",
    description="Make an HTTP request to a specified URL"
)
async def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Union[Dict[str, Any], str]] = None,
    json: Optional[Union[Dict[str, Any], List[Any]]] = None,
    timeout: float = 30,
    client_id: Optional[str] = None,
) -> dict:
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
    if client_id and client_id in app_state.token_cache:
        cached_data = app_state.token_cache[client_id]
        token = cached_data["token"]
        token_type = cached_data["token_type"]

        # Always use the cached token if client_id is provided
        if "access_token" in token:
            auth_header = f"{token_type} {token['access_token']}"
            headers["Authorization"] = auth_header
            logger.info(f"Using cached token for client {client_id}")
    # Failsafe: If no client_id is specified but there's only one token in the cache, use it
    elif not client_id and len(app_state.token_cache) == 1:
        # Get the only client_id in the cache
        auto_client_id = list(app_state.token_cache.keys())[0]
        cached_data = app_state.token_cache[auto_client_id]
        token = cached_data["token"]
        token_type = cached_data["token_type"]

        if "access_token" in token:
            auth_header = f"{token_type} {token['access_token']}"
            headers["Authorization"] = auth_header
            logger.info(f"Failsafe: Using the only cached token (client {auto_client_id})")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
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
                response_body = response.json()
            except ValueError:
                # Not JSON, return text
                response_body = response.text

            result = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
            }

            return result

    except httpx.RequestError as e:
        logger.error(f"Request failed: {str(e)}")
        return {"error": str(e)}


@mcp.resource(
    uri="http-client://readme",
    description="Documentation for the HTTP client"
)
def get_readme() -> str:
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

### oauth2_authorize_and_fetch_token

Create an OAuth2 authorization URL, start a callback server, open browser, and automatically fetch token when the callback is received.

Parameters:
- client_id (required): OAuth2 client ID
- authorization_url (required): Authorization endpoint URL
- token_url (required): Token endpoint URL
- redirect_uri (required): Redirect URI for the OAuth2 flow
- client_secret: OAuth2 client secret (optional for public clients)
- scope: List of scopes to request (default: ["openid"])
- open_browser: Whether to automatically open the browser (default: true)
- force: Whether to fetch a new token even if we already have one for this client_id (default: false)

Example:
```json
{
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "authorization_url": "https://example.com/oauth2/authorize",
  "token_url": "https://example.com/oauth2/token",
  "redirect_uri": "http://localhost:3001/callback",
  "scope": ["profile", "email"],
  "open_browser": true
}
```

Response:
```json
{
  "authorization_url": "https://example.com/oauth2/authorize?response_type=code&client_id=your-client-id&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&scope=profile+email&state=abc123",
  "state": "abc123",
  "message": "Authorization URL opened in browser. Waiting for callback...",
  "callback_server": "http://localhost:3001/callback"
}
```
"""


@mcp.tool(
    name="oauth2_authorize_and_fetch_token",
    description="Create an OAuth2 authorization URL, open browser, and automatically fetch token"
)
async def oauth2_authorize_and_fetch_token(
    client_id: str,
    authorization_url: str,
    token_url: str,
    redirect_uri: str,
    client_secret: Optional[str] = None,
    scope: Optional[List[str]] = None,
    open_browser: bool = True,
    force: bool = False
) -> dict:
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
        force: Whether to reauthorize even if we already have a token

    Returns:
        A JSON string containing the authorization URL and state or a string message if a token is already cached.
    """
    if client_id in app_state.token_cache and not force:
        logger.info(f"We already have a token for {client_id}")
        return "We already have a token. Call again with force set to true to get a new one if required."

    logger.info(f"Starting OAuth2 flow with automatic token fetch for client {client_id}")

    if scope is None:
        scope = ["openid"]

    # Parse the redirect_uri to ensure it matches our callback server
    parsed_uri = urlparse(redirect_uri)
    callback_host = parsed_uri.hostname
    callback_port = parsed_uri.port
    callback_path = parsed_uri.path

    # Start the callback server if not already running
    if app_state.callback_server is None and callback_host and callback_port:
        actual_port = await _start_callback_server(callback_port)

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

    # Generate a random state
    import secrets
    state = secrets.token_urlsafe(16)

    # Create authorization URL with parameters
    from urllib.parse import urlencode
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'state': state,
    }

    if scope:
        params['scope'] = ' '.join(scope)

    auth_url = f"{authorization_url}?{urlencode(params)}"

    # Store the request details for when the callback is received
    app_state.pending_oauth_requests[state] = {
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

    return result


async def _start_callback_server(port: int, max_retries: int = 5) -> int:
    """
    Start an HTTP server to handle OAuth2 callbacks.

    Args:
        port: Port to run the server on
        max_retries: Maximum number of port numbers to try if the specified port is in use

    Returns:
        The port number that the server is running on
    """
    # Create a request handler that will process the callback
    async def handle_callback(request):
        from aiohttp import web

        try:
            # Parse the query parameters
            query_params = request.query

            logger.info(f"Received callback: {request.path_qs}")
            logger.info(f"Query parameters: {query_params}")

            # Extract the authorization code and state
            code = query_params.get("code", "")
            state = query_params.get("state", "")

            if code:
                logger.info(f"Extracted code: {code[:5]}... and state: {state}")

            # Prepare response
            if not code or not state:
                error_message = "Error: Missing code or state parameter"
                logger.error(error_message)
                return web.Response(
                    text=f"<html><body><h1>{error_message}</h1></body></html>",
                    content_type="text/html"
                )

            # Check if we have a pending request for this state
            if state not in app_state.pending_oauth_requests:
                error_message = f"Error: No pending OAuth request found for state: {state}"
                logger.error(error_message)
                logger.error(f"Available states: {list(app_state.pending_oauth_requests.keys())}")
                return web.Response(
                    text=f"<html><body><h1>{error_message}</h1></body></html>",
                    content_type="text/html"
                )

            # Get the request details
            request_details = app_state.pending_oauth_requests[state]

            # Process the token asynchronously
            await _fetch_token_from_callback(code, state, request_details)

            # Send a success message to the browser
            return web.Response(
                text="""
                <html>
                    <body>
                        <h1>Authorization Successful</h1>
                        <p>You can close this window now.</p>
                    </body>
                </html>
                """,
                content_type="text/html"
            )

        except Exception as e:
            logger.error(f"Error handling callback: {str(e)}")
            return web.Response(
                text=f"<html><body><h1>Error: {str(e)}</h1></body></html>",
                content_type="text/html",
                status=500
            )

    # Try to start the server, incrementing the port number if it's already in use
    from aiohttp import web
    current_port = port

    for attempt in range(max_retries):
        try:
            app = web.Application()
            app.router.add_get('/{path:.*}', handle_callback)

            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, 'localhost', current_port)
            await site.start()

            app_state.callback_server = {
                'runner': runner,
                'site': site
            }

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


async def _fetch_token_from_callback(code: str, state: str, request_details: Dict[str, Any]) -> None:
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

        # Prepare token request data
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
        }

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        # Add client_secret if provided
        if client_secret:
            data['client_secret'] = client_secret

        # Make the token request
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=data,
                headers=headers
            )

            response.raise_for_status()
            token = response.json()

        # Cache the token
        token_type = token.get("token_type", "Bearer")
        app_state.token_cache[client_id] = {
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
        if state in app_state.pending_oauth_requests:
            del app_state.pending_oauth_requests[state]

async def cleanup():
    """Clean up the callback server and token cache."""
    if app_state.callback_server:
        if 'runner' in app_state.callback_server:
            await app_state.callback_server['runner'].cleanup()
        app_state.callback_server = None
        logger.info("Callback server shut down successfully")
    if app_state.callback_server_task:
        app_state.callback_server_task.cancel()
        try:
            await app_state.callback_server_task
        except asyncio.CancelledError:
            pass
        app_state.callback_server_task = None
        logger.info("Callback server task cancelled successfully")


def main():
    """Run the MCP server."""
    logger.info("Starting curl-mcp server...")

    # Register cleanup to be run at exit
    async def async_cleanup():
        await cleanup()

    atexit.register(lambda: asyncio.run(async_cleanup()))

    # mcp.run(transport="sse", host="localhost", port=9090)
    mcp.run()


if __name__ == "__main__":
    main()
