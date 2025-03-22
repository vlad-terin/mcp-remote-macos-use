# MCP Server - Vnc MacOs Use
Remote control any macOS machine with LLM without Any Host Setup

**Support Any MacOS Version (If apple documentation doesn't lie)**
**Apple authentication is hectic, you know them...you only other option is commercial closed-source RealVnc!**

The only MCP (Model Context Protocol) server that remote control MacOS natively via Vnc to Apple Authentication. No configuration on MacOs except for enabling sharing.

## Why so Critical
- You can use any LLM with this MCP server. You don't have to stick to Claude computer-use.
- No Host setup at all! As long as Screen Sharing is enabled, you can control any Mac machine using LLM. All current computer-use variants requires running a python app in the background. Hectic!


## Features
- Support for Apple Authentication (protocol 30) only for now
- Compatible with macOS Screen Sharing

## Prerequisites

- Python 3.11 or higher
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
  "host": "vnc-server-hostname-or-ip",
  "port": 5900,
  "password": "your-vnc-password",
  "username": "optional-username"
}
```


## Limitations

- **Authentication Support**: 
  - Only Apple Authentication (protocol 30) is supported
- Currently only supports capturing screenshots; does not support mouse or keyboard input

## Security Note

https://support.apple.com/guide/remote-desktop/encrypt-network-data-apdfe8e386b/mac
https://cafbit.com/post/apple_remote_desktop_quirks/

We only support protocol 30, which uses the Diffie-Hellman key agreement protocol with a 512-bit prime. This protocol is used by macOS 11 to macOS 12 when communicating with OS X 10.11 or earlier clients.

Here's the information converted to a markdown table:

| macOS version running Remote Desktop | macOS client version | Authentication | Control and Observe | Copy items or install package | All other tasks | Protocol Version |
|--------------------------------------|----------------------|----------------|---------------------|-------------------------------|----------------|----------------|
| macOS 13 | macOS 13 | 2048-bit RSA host keys | 2048-bit RSA host keys | 2048-bit RSA host keys to authenticate, then 128-bit AES | 2048-bit RSA host keys | 36 |
| macOS 13 | macOS 10.12 | Secure Remote Password (SRP) protocol for local only. Diffie-Hellman (DH) if bound to LDAP or macOS server is version 10.11 or earlier | SRP or DH,128-bit AES | SRP or DH to authenticate, then 128-bit AES | 2048-bit RSA host keys | 35 |
| macOS 11 to macOS 12 | macOS 10.12 to macOS 13 | Secure Remote Password (SRP) protocol for local only, Diffie-Hellman if bound to LDAP | SRP or DH 1024-bit, 128-bit AES | 2048-bit RSA host keys macOS 13 to macOS 10.13 | 2048-bit RSA host keys macOS 10.13 or later |  33 |
| macOS 11 to macOS 12 | OS X 10.11 or earlier | DH 1024-bit | DH 1024-bit, 128-bit AES | Diffie-Hellman Key agreement protocol with a 512-bit prime | Diffie-Hellman Key agreement protocol with a 512-bit prime |  30 |


Always use secure, authenticated connections when accessing remote VNC servers. This tool should only be used with servers you trust and have permission to access.

## License

See the LICENSE file for details. 
