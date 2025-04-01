import asyncio
import json
import sys

async def main():
    # Initialize request
    init_request = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "1.0",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"}
        },
        "id": 1
    }
    
    # List tools request
    list_request = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 2
    }
    
    # Write requests
    sys.stdout.write(json.dumps(init_request) + "\n")
    sys.stdout.write(json.dumps(list_request) + "\n")
    sys.stdout.flush()
    
    # Read responses
    while True:
        try:
            line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            response = json.loads(line)
            print(f"Received response: {json.dumps(response, indent=2)}", file=sys.stderr)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            break

if __name__ == "__main__":
    asyncio.run(main())