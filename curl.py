#!/usr/bin/env python3
"""
Simple MCP server for making HTTP requests.
"""

import json as json_module
import logging
from typing import Any, Dict, List, Optional, Union

import requests
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("curl-mcp")

class CurlMCPServer(FastMCP):
    """MCP server that provides HTTP request capabilities."""

    def __init__(self):
        super().__init__(
            name="curl-mcp",
            description="MCP server for making HTTP requests",
        )

        # Register tools
        self.add_tool(
            fn=self.http_request,
            name="http_request",
            description="Make an HTTP request to a specified URL"
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

        Returns:
            A string containing the response details
        """
        logger.info(f"Making {method} request to {url}")

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

This MCP server provides a tool for making HTTP requests to external services.

## Available Tools

### http_request

Make an HTTP request to a specified URL.

Parameters:
- url (required): The URL to send the request to
- method: The HTTP method to use (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
- headers: HTTP headers to include in the request
- params: URL parameters to include in the request
- data: Data to send in the request body
- json: JSON data to send in the request body
- timeout: Request timeout in seconds (default: 30)

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
  }
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


def main():
    """Run the MCP server."""
    logger.info("Starting curl-mcp server...")
    server = CurlMCPServer()
    # server.run(transport="sse", host="localhost", port=8080)
    server.run()


if __name__ == "__main__":
    main()
