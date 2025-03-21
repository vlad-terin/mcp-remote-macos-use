# MCP VNC macOS Use Server

A MCP (Model Context Protocol) server that provides access to remote computer screens via VNC.

## Features

- Capture screenshots from VNC servers
- Simple authentication with password (and optional username for specific auth types)
- Compatible with standard VNC servers

## Prerequisites

- Python 3.10 or higher
- Network access to VNC server

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-vnc-macos-use.git
cd mcp-vnc-macos-use

# Install dependencies
pip install -e .
```

## Docker

### Building the Docker Image

```bash
# Build the Docker image
docker build -t mcp-vnc-macos-use .
```

## Usage with Claude Desktop

### Docker Usage

You can configure Claude Desktop to use the Docker image by adding the following to your Claude configuration:

```json
{
  "mcpServers": {
    "vnc-macos-use": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "buryhuang/mcp-vnc-macos-use:latest"
      ]
    }
  }
}
```

### Local Python Usage

If you prefer to run the server directly with Python, you can use this configuration:

```json
{
  "mcpServers": {
    "vnc-client": {
      "command": "python",
      "args": ["-m", "mcp_server_vnc_macos_use.server"],
      "env": {
        "PYTHONPATH": "/path/to/your/mcp-vnc-macos-use"
      }
    }
  }
}
```

## Cross-Platform Publishing

To publish the Docker image for multiple platforms, you can use the `docker buildx` command. Follow these steps:

1. **Create a new builder instance** (if you haven't already):
   ```bash
   docker buildx create --use
   ```

2. **Build and push the image for multiple platforms**:
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t buryhuang/mcp-vnc-macos-use:latest --push .
   ```

3. **Verify the image is available for the specified platforms**:
   ```bash
   docker buildx imagetools inspect buryhuang/mcp-vnc-macos-use:latest
   ```

## Usage

The server provides VNC functionality through MCP tools.

### Starting the Server

```bash
mcp_server_vnc_macos_use
```

### Using the Tools

#### Capturing a Screenshot with vnc_get_screen

```json
{
  "host": "vnc-server-hostname",
  "port": 5900,
  "password": "your-vnc-password",
  "username": "optional-username"
}
```

The response includes:
- A base64-encoded screenshot from the VNC server
- Additional metadata about the connection

## Limitations

- **Authentication Support**: 
  - Standard VNC password authentication is supported but uses a placeholder implementation
  - Username+password authentication types (like VeNCrypt or Tight Unix Login) are not fully implemented
  - Advanced security types (TLS, X509, SASL) are not supported
- Currently only supports capturing screenshots; does not support mouse or keyboard input
- Performance may vary depending on network conditions and VNC server configuration

## Security Note

Always use secure, authenticated connections when accessing remote VNC servers. This tool should only be used with servers you trust and have permission to access.

## License

See the LICENSE file for details. 
