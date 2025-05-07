# curl-mcp

A simple MCP (Model Context Protocol) server for making HTTP requests, including OAuth2 authorization code flow support. Uses httpx for HTTP requests and async/await for improved performance.

## Installation

```bash
pip install -e .
```

## Usage

### Starting the Server

```bash
python curl.py
```

Or use the installed script:

```bash
curl-mcp
```

### Making HTTP Requests

See `test_client.py` for examples of making HTTP requests using the MCP server.

```bash
python test_client.py
```

## Available Tools

### http_request

Make an asynchronous HTTP request to a specified URL using httpx.

### oauth2_authorize_and_fetch_token

Create an OAuth2 authorization URL, start an async callback server, open browser, and automatically fetch token when the callback is received.


## OAuth2 Authorization Code Flow

The OAuth2 authorization code flow involves the following steps:

### Automatic Flow (with Callback Server)

1. Create an authorization URL, start a callback server, and open the browser using `oauth2_authorize_and_fetch_token`
2. The user authorizes the application in the browser
3. The callback server automatically receives the authorization code and exchanges it for a token
4. Make authenticated requests using `http_request` with the client_id parameter to use the cached token
   - If no client_id is specified but there's only one token in the cache, that token will be used automatically

> **IMPORTANT**: Always include the same `client_id` in your `http_request` calls that you used with `oauth2_authorize_and_fetch_token`. Failing to include the `client_id` parameter may result in unauthorized requests if multiple tokens are cached.

## Example OAuth2 Flow

```python
# Step 1: Create authorization URL, start callback server, and open browser
auth_result = await client.call_tool(
    "oauth2_authorize_and_fetch_token",
    {
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "authorization_url": "https://example.com/oauth2/authorize",
        "token_url": "https://example.com/oauth2/token",
        "redirect_uri": "http://localhost:3001/callback",
        "scope": ["profile", "email"],
        "open_browser": True,
    }
)

# Step 2: Wait for the user to authorize the application in the browser
# The token will be automatically fetched when the callback is received

# Step 3: Make authenticated requests using the cached token
api_result = await client.call_tool(
    "http_request",
    {
        "url": "https://example.com/api/user",
        "method": "GET",
        "client_id": "your-client-id"  # IMPORTANT: Always include the same client_id used in oauth2_authorize_and_fetch_token
    }
)
```

See `test_oauth2_auto.py` for a complete example of using the automatic OAuth2 flow with the callback server.

```bash
python test_oauth2_auto.py
```

## License

MIT
