#!/usr/bin/env python3
"""
Test client for the automatic OAuth2 authorization code flow in curl-mcp.
This version uses the callback server to automatically fetch the token.
"""
import os
import asyncio
import json
import time
from fastmcp import Client

# Replace these with your OAuth2 provider details
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORIZATION_URL = os.getenv("AUTHORIZATION_URL")
TOKEN_URL = os.getenv("TOKEN_URL")
REDIRECT_URI = os.getenv("REDIRECT_URI")
SCOPES = os.getenv("SCOPES").split()
API_URL = os.getenv("API_URL")

async def main():
    """Run the OAuth2 test client with automatic token fetching."""
    print("Starting OAuth2 test client with automatic token fetching...")

    # Connect to the curl-mcp server
    async with Client("curl.py") as client:
        # Step 1: Create the authorization URL, start callback server, and open browser
        print("\nStep 1: Starting OAuth2 flow with automatic token fetching...")
        auth_result = await client.call_tool(
            "oauth2_authorize_and_fetch_token",
            {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "authorization_url": AUTHORIZATION_URL,
                "token_url": TOKEN_URL,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPES,
                "open_browser": True,
            }
        )

        auth_data = json.loads(auth_result[0].text)
        print("Authorization URL:", auth_data["authorization_url"])
        print("State:", auth_data["state"])
        print("Message:", auth_data["message"])
        print("Callback server:", auth_data["callback_server"])

        # Step 2: Wait for the user to authorize the application
        print("\nStep 2: Waiting for authorization in browser...")
        print("Please authorize the application in your browser.")
        print("The token will be automatically fetched when the callback is received.")

        # Wait for the user to complete the authorization
        # In a real application, you might implement a polling mechanism to check if the token has been fetched
        wait_time = 60  # Increased wait time to give more time for authorization
        print(f"Waiting up to {wait_time} seconds for authorization...")

        token_fetched = False
        for i in range(wait_time):
            time.sleep(1)
            print(f"Waiting... {i+1}/{wait_time}", end="\r")

            # Check if the token has been cached
            try:
                # Step 3: Make an authenticated API request using the cached token
                print("\n\nStep 3: Making an authenticated API request...")
                api_result = await client.call_tool(
                    "http_request",
                    {
                        "url": API_URL,
                        "method": "GET",
                        "client_id": CLIENT_ID
                    }
                )

                api_response = json.loads(api_result[0].text)
                status_code = api_response.get("status_code")

                if status_code == 200:
                    print("API request successful!")
                    print("API response:")
                    print(json.dumps(api_response, indent=2))
                    token_fetched = True

                    # Step 4: Test the failsafe by making a request without client_id
                    print("\n\nStep 4: Testing failsafe - Making an authenticated API request without client_id...")
                    failsafe_result = await client.call_tool(
                        "http_request",
                        {
                            "url": API_URL,
                            "method": "GET"
                            # No client_id specified - should use the only cached token
                        }
                    )

                    failsafe_response = json.loads(failsafe_result[0].text)
                    failsafe_status_code = failsafe_response.get("status_code")

                    if failsafe_status_code == 200:
                        print("Failsafe test successful!")
                        print("API response:")
                        print(json.dumps(failsafe_response, indent=2))
                    else:
                        print(f"Failsafe test failed with status code: {failsafe_status_code}")
                        print("Response:", json.dumps(failsafe_response, indent=2))

                    break
                elif status_code == 401:
                    print(f"Attempt {i+1}: Token not yet available or invalid (401 Unauthorized)")
                    print("Response:", json.dumps(api_response, indent=2))
                    # Continue waiting
                else:
                    print(f"Unexpected status code: {status_code}")
                    print("Response:", json.dumps(api_response, indent=2))
            except Exception as e:
                print(f"Error checking token: {str(e)}")
                # Token might not be ready yet
                continue

        if not token_fetched:
            print("\nTimeout waiting for authorization. Please check:")
            print("1. Did you complete the authorization in the browser?")
            print("2. Is the callback URL correct? (http://localhost:3001/callback)")
            print("3. Is the OAuth2 provider configured correctly?")
            return

    print("\nOAuth2 test completed.")

if __name__ == "__main__":
    asyncio.run(main())
