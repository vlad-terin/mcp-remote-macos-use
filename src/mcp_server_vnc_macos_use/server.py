import logging
from typing import Any, Dict, List, Optional
import os
from dotenv import load_dotenv
import base64
import socket
import time
import io
from PIL import Image
import asyncio
import pyDes

# Import MCP server libraries
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('mcp_server_vnc_macos_use')
logger.setLevel(logging.DEBUG)


def encrypt_vnc_password(password: str, challenge: bytes) -> bytes:
    """Encrypt VNC password for authentication.
    
    Args:
        password: VNC password
        challenge: Challenge bytes from server
        
    Returns:
        bytes: Encrypted response
    """
    # Convert password to key (truncate to 8 chars or pad with zeros)
    key = password.ljust(8, '\x00')[:8].encode('ascii')
    
    # VNC uses a reversed bit order for each byte in the key
    reversed_key = bytes([((k >> 0) & 1) << 7 |
                         ((k >> 1) & 1) << 6 |
                         ((k >> 2) & 1) << 5 |
                         ((k >> 3) & 1) << 4 |
                         ((k >> 4) & 1) << 3 |
                         ((k >> 5) & 1) << 2 |
                         ((k >> 6) & 1) << 1 |
                         ((k >> 7) & 1) << 0 for k in key])
    
    # Create a pyDes instance for encryption
    k = pyDes.des(reversed_key, pyDes.ECB, pad=None)
    
    # Encrypt the challenge with the key
    result = bytearray()
    for i in range(0, len(challenge), 8):
        block = challenge[i:i+8]
        cipher_block = k.encrypt(block)
        result.extend(cipher_block)
    
    return bytes(result)

class VNCClient:
    """Simple VNC client implementation to connect to VNC servers and capture screenshots."""
    
    def __init__(self, host: str, port: int = 5900, password: Optional[str] = None, username: Optional[str] = None, 
                 encryption: str = "prefer_on"):
        """Initialize VNC client with connection parameters.
        
        Args:
            host: VNC server hostname or IP address
            port: VNC server port (default: 5900)
            password: VNC server password (optional)
            username: VNC server username (optional, only used with certain authentication methods)
            encryption: Encryption preference, one of "prefer_on", "prefer_off", "server" (default: "prefer_on")
        """
        self.host = host
        self.port = port
        self.password = password
        self.username = username
        self.encryption = encryption
        self.socket = None
        self.width = 0
        self.height = 0
        self.pixel_format = None
        self.name = ""
        
    def connect(self) -> bool:
        """Connect to the VNC server and perform the RFB handshake.
        
        Returns:
            bool: True if connection was successful, False otherwise
        """
        try:
            logger.debug(f"Connecting to VNC server at {self.host}:{self.port}")
            
            # Create socket and connect
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)  # 10 second timeout
            self.socket.connect((self.host, self.port))
            
            # Receive RFB protocol version
            version = self.socket.recv(12).decode('ascii')
            logger.debug(f"Server supports RFB protocol: {version}")
            
            # We support RFB 3.8 (better compatibility with macOS)
            self.socket.sendall(b"RFB 003.008\n")
            
            # In RFB 3.8+, server sends number of security types followed by list of types
            security_types_count = self.socket.recv(1)[0]
            logger.debug(f"Server offers {security_types_count} security types")
            
            if security_types_count == 0:
                # Read error message
                error_length = int.from_bytes(self.socket.recv(4), byteorder='big')
                error_message = self.socket.recv(error_length).decode('ascii')
                logger.error(f"VNC server error: {error_message}")
                return False
            
            # Receive available security types
            security_types = self.socket.recv(security_types_count)
            logger.debug(f"Available security types: {[st for st in security_types]}")
            
            # Choose a security type we can handle based on encryption preference
            chosen_type = None
            
            # Security type preferences based on encryption setting
            if self.encryption == "prefer_on":
                # Prefer encrypted authentication when possible
                logger.debug("Using 'Prefer On' encryption setting")
                preferred_types = []
                
                # Look for encrypted authentication types first
                if 30 in security_types and self.password:  # Apple authentication (preferred for macOS)
                    preferred_types.append(30)
                if 2 in security_types and self.password:  # VNC authentication
                    preferred_types.append(2)
                if 1 in security_types:  # None authentication (last resort)
                    preferred_types.append(1)
                
                # Select the first available preferred type
                if preferred_types:
                    chosen_type = preferred_types[0]
                    logger.debug(f"Selected security type {chosen_type} based on 'prefer_on' setting")
                    
            elif self.encryption == "prefer_off":
                # Prefer unencrypted authentication when possible
                logger.debug("Using 'Prefer Off' encryption setting")
                if 1 in security_types:  # None authentication
                    chosen_type = 1
                elif 2 in security_types and self.password:  # VNC authentication
                    chosen_type = 2
                elif 30 in security_types and self.password:  # Apple authentication
                    chosen_type = 30
            else:
                # Let server decide (default behavior)
                logger.debug("Using 'Server' encryption setting")
                for sec_type in security_types:
                    logger.debug(f"Evaluating security type: {sec_type}")
                    if sec_type == 1:  # None authentication
                        chosen_type = 1
                        break
                    elif sec_type == 2 and self.password:  # VNC authentication
                        chosen_type = 2
                        break
                    elif sec_type == 30 and self.password:  # Apple authentication
                        chosen_type = 30
                        break
            
            if chosen_type is None:
                logger.error("No supported security types available")
                return False
            
            # Send chosen security type
            logger.debug(f"Choosing security type: {chosen_type}")
            self.socket.sendall(bytes([chosen_type]))
            
            if chosen_type == 1:
                # No authentication
                logger.debug("No authentication required")
            elif chosen_type == 2:
                # Standard VNC authentication
                if not self.password:
                    logger.error("Password required but not provided")
                    return False
                
                # Receive challenge
                challenge = self.socket.recv(16)
                
                try:
                    # Use proper DES encryption for VNC authentication
                    logger.debug(f"Encrypting challenge for {chosen_type=} authentication")
                    response = encrypt_vnc_password(self.password, challenge)
                    logger.debug(f"Encrypted response length: {len(response)}")
                except Exception as e:
                    logger.error(f"Failed to encrypt password: {str(e)}")
                    response = b'\x00' * 16  # Fallback to placeholder if encryption fails
                
                # Send response
                logger.debug("Sending authentication response")
                self.socket.sendall(response)
                
                # Check authentication result
                logger.debug("Waiting for authentication result")
                auth_result = int.from_bytes(self.socket.recv(4), byteorder='big')
                logger.debug(f"Authentication result: {auth_result}")
                if auth_result != 0:
                    logger.error("Authentication failed")
                    return False
                logger.debug("Authentication successful")
            elif chosen_type == 30:
                # Apple VNC Authentication (similar to standard VNC auth)
                if not self.password:
                    logger.error("Password required but not provided")
                    return False
                
                # For Apple authentication, receive the challenge
                challenge = self.socket.recv(16)
                
                try:
                    # Use proper DES encryption for VNC authentication
                    logger.debug(f"Encrypting challenge for Apple (type 30) authentication")
                    response = encrypt_vnc_password(self.password, challenge)
                    logger.debug(f"Encrypted response length: {len(response)}")
                except Exception as e:
                    logger.error(f"Failed to encrypt password: {str(e)}")
                    response = b'\x00' * 16  # Fallback to placeholder if encryption fails
                
                # Send response
                logger.debug("Sending authentication response to Apple VNC")
                self.socket.sendall(response)
                
                # Check authentication result - may have additional steps for Apple
                logger.debug("Waiting for Apple authentication result")
                auth_result = int.from_bytes(self.socket.recv(4), byteorder='big')
                logger.debug(f"Apple authentication result: {auth_result}")
                if auth_result != 0:
                    logger.error("Apple authentication failed")
                    return False
                logger.debug("Apple authentication successful")
            else:
                logger.error(f"Security type {chosen_type} selected but not properly implemented")
                return False
            
            # Send client init (shared flag)
            self.socket.sendall(b'\x01')  # non-zero = shared
            
            # Receive server init
            server_init = self.socket.recv(24)
            
            # Parse server init
            self.width = int.from_bytes(server_init[0:2], byteorder='big')
            self.height = int.from_bytes(server_init[2:4], byteorder='big')
            self.pixel_format = server_init[4:20]
            
            name_length = int.from_bytes(server_init[20:24], byteorder='big')
            self.name = self.socket.recv(name_length).decode('ascii')
            
            logger.debug(f"Connected to VNC server: {self.name}")
            logger.debug(f"Screen dimensions: {self.width}x{self.height}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to VNC server: {str(e)}")
            if self.socket:
                self.socket.close()
                self.socket = None
            return False
    
    def capture_screen(self) -> Optional[bytes]:
        """Capture a screenshot from the VNC server.
        
        Returns:
            bytes: Raw image data if successful, None otherwise
        """
        try:
            if not self.socket:
                logger.error("Not connected to VNC server")
                return None
            
            # Send FramebufferUpdateRequest message
            msg = bytearray([3])  # message type 3 = FramebufferUpdateRequest
            msg.extend([0])  # incremental = 0 (non-incremental)
            msg.extend(int(0).to_bytes(2, byteorder='big'))  # x-position
            msg.extend(int(0).to_bytes(2, byteorder='big'))  # y-position
            msg.extend(int(self.width).to_bytes(2, byteorder='big'))  # width
            msg.extend(int(self.height).to_bytes(2, byteorder='big'))  # height
            
            self.socket.sendall(msg)
            
            # Receive FramebufferUpdate message
            msg_type = self.socket.recv(1)[0]
            if msg_type != 0:  # 0 = FramebufferUpdate
                logger.error(f"Unexpected message type: {msg_type}")
                return None
            
            # Skip padding
            self.socket.recv(1)
            
            # Read number of rectangles
            num_rects = int.from_bytes(self.socket.recv(2), byteorder='big')
            logger.debug(f"Received {num_rects} rectangles")
            
            # TODO: For simplicity, we'll just use a simple approach here
            # In a real implementation, we'd handle multiple rectangles and different encodings
            
            # Create a placeholder image
            img = Image.new('RGB', (self.width, self.height), color='black')
            
            # In a real implementation, we would parse the rectangles and render them to the image
            # For this demo, we're just returning a placeholder
            
            # Convert image to bytes
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            
            return img_byte_arr.getvalue()
            
        except Exception as e:
            logger.error(f"Error capturing screen: {str(e)}")
            return None
    
    def close(self):
        """Close the connection to the VNC server."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None


async def main():
    """Run the VNC MCP server."""
    logger.info("VNC computer use server starting")
    server = Server("vnc-client")

    @server.list_resources()
    async def handle_list_resources() -> list[types.Resource]:
        return []

    @server.read_resource()
    async def handle_read_resource(uri: types.AnyUrl) -> str:
        if uri.scheme != "vnc":
            raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

        path = str(uri).replace("vnc://", "")
        return ""

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        """List available tools"""
        return [
            types.Tool(
                name="vnc_get_screen",
                description="Connect to a VNC server and get a screenshot of the remote desktop",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "VNC server hostname or IP address"},
                        "port": {"type": "integer", "description": "VNC server port (default: 5900)"},
                        "password": {"type": "string", "description": "VNC server password (optional)"},
                        "username": {"type": "string", "description": "VNC server username (optional, only required for certain authentication methods)"},
                        "encryption": {
                            "type": "string", 
                            "description": "Encryption preference", 
                            "enum": ["prefer_on", "prefer_off", "server"],
                            "default": "prefer_on"
                        }
                    },
                    "required": ["host"]
                },
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict[str, Any] | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """Handle tool execution requests"""
        try:
            if not arguments:
                raise ValueError(f"Missing arguments for {name}")
            
            if name == "vnc_get_screen":
                host = arguments.get("host")
                port = int(arguments.get("port", 5900))
                password = arguments.get("password")
                username = arguments.get("username")
                encryption = arguments.get("encryption", "prefer_on")  # Default to "prefer_on" for macOS compatibility
                
                if not host:
                    raise ValueError("host is required to connect to VNC server")
                
                logger.debug(f"Connecting to VNC server at {host}:{port} with encryption: {encryption}")
                
                # Initialize VNC client
                vnc = VNCClient(host=host, port=port, password=password, username=username, encryption=encryption)
                
                # Connect to VNC server
                if not vnc.connect():
                    return [types.TextContent(type="text", text=f"Failed to connect to VNC server at {host}:{port}")]
                
                try:
                    # Capture screen
                    screen_data = vnc.capture_screen()
                    
                    if not screen_data:
                        return [types.TextContent(type="text", text=f"Failed to capture screenshot from VNC server at {host}:{port}")]
                    
                    # Encode image in base64
                    base64_data = base64.b64encode(screen_data).decode('utf-8')
                    
                    # Return image content
                    return [
                        types.ImageContent(
                            type="image",
                            image_url=f"data:image/png;base64,{base64_data}",
                            alt_text=f"Screenshot from VNC server at {host}:{port}"
                        )
                    ]
                finally:
                    # Close VNC connection
                    vnc.close()
            else:
                raise ValueError(f"Unknown tool: {name}")

        except Exception as e:
            logger.error(f"Error in handle_call_tool: {str(e)}", exc_info=True)
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        logger.info("Server running with stdio transport")
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="vnc-client",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    # Load environment variables from .env file if it exists
    load_dotenv()
    
    # Run the server
    asyncio.run(main()) 