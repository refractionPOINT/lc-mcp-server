#!/usr/bin/env python3
"""Test script to verify MCP server deployment"""

import httpx
import asyncio
import json
import sys

async def test_server(base_url="http://localhost:8080"):
    async with httpx.AsyncClient() as client:
        print(f"Testing MCP server at {base_url}\n")
        
        # Test 1: Health check
        print("1. Health check...")
        try:
            resp = await client.get(f"{base_url}/", timeout=5)
            print(f"   Status: {resp.status_code}")
            if resp.status_code == 200:
                print(f"   Response: {resp.json()}")
            else:
                print(f"   Error: {resp.text}")
        except Exception as e:
            print(f"   Failed: {e}")
            return False
        
        # Test 2: Initialize MCP
        print("\n2. Initialize MCP...")
        try:
            resp = await client.post(
                f"{base_url}/mcp/",
                headers={
                    "Accept": "application/json, text/event-stream"
                },
                json={
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "test-client",
                            "version": "1.0.0"
                        }
                    },
                    "id": 1
                },
                timeout=10
            )
            print(f"   Status: {resp.status_code}")
            if resp.status_code == 200:
                result = resp.json()
                print(f"   Server: {result['result']['serverInfo']['name']}")
                print(f"   Version: {result['result']['serverInfo']['version']}")
            else:
                print(f"   Error: {resp.text}")
                return False
        except Exception as e:
            print(f"   Failed: {e}")
            return False
        
        # Test 3: List tools (with auth)
        print("\n3. List tools (testing auth)...")
        headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer test-key:test-oid",
            "x-lc-oid": "test-oid"
        }
        try:
            resp = await client.post(
                f"{base_url}/mcp/",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {},
                    "id": 2
                },
                timeout=10
            )
            print(f"   Status: {resp.status_code}")
            if resp.status_code == 200:
                result = resp.json()
                tools = result.get('result', {}).get('tools', [])
                print(f"   Number of tools: {len(tools)}")
                if tools:
                    print(f"   Example tools: {', '.join(t['name'] for t in tools[:5])}...")
            else:
                print(f"   Error: {resp.text}")
        except Exception as e:
            print(f"   Failed: {e}")
        
        print("\n✓ All tests completed!")
        return True

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    success = asyncio.run(test_server(url))
    sys.exit(0 if success else 1)