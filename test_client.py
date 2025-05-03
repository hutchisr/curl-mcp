#!/usr/bin/env python3
"""
Simple client to test the curl-mcp server.
"""

import asyncio
import json
from fastmcp import Client

async def main():
    """Run the test client."""
    # Use the client as an async context manager
    async with Client("curl.py") as client:
        # List available tools
        tools = await client.list_tools()
        print(f"Available tools: {[tool.name for tool in tools]}")

        # List available resources
        resources = await client.list_resources()
        print(f"Available resources: {[resource.uri for resource in resources]}")

        # Access the readme resource
        readme = await client.read_resource("http-client://readme")
        print("\nReadme resource:")
        print(readme)

        # Make an HTTP request using the tool
        print("\nMaking an HTTP request to httpbin.org...")
        result = await client.call_tool(
            "http_request",
            {
                "url": "https://httpbin.org/get",
                "params": {"test": "value"}
            }
        )

        # Parse and pretty-print the result
        result_text = result[0].text
        try:
            result_json = json.loads(result_text)
            print("\nHTTP request result:")
            print(json.dumps(result_json, indent=2))
        except (json.JSONDecodeError, KeyError):
            print("\nHTTP request result (not JSON):")
            print(result_text)

        # Make a POST request
        print("\nMaking a POST request to httpbin.org...")
        post_result = await client.call_tool(
            "http_request",
            {
                "url": "https://httpbin.org/post",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "json": {"name": "Test", "value": 42}
            }
        )

        # Parse and pretty-print the result
        post_result_text = post_result[0].text
        try:
            post_result_json = json.loads(post_result_text)
            print("\nPOST request result:")
            print(json.dumps(post_result_json, indent=2))
        except (json.JSONDecodeError, KeyError):
            print("\nPOST request result (not JSON):")
            print(post_result_text)

    print("\nDisconnected from curl-mcp server.")

if __name__ == "__main__":
    asyncio.run(main())
