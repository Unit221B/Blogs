#!/usr/bin/env python3
"""
Trae Token Capture Script - Automatically capture authentication tokens from Trae API traffic

This script sets up a proxy server that captures and extracts JWT tokens from Trae traffic.
It works with any app that uses the Trae API, including Cursor.

Usage:
    python3 trae_auth_capture.py
"""

import os
import sys
import re
import json
import base64
import argparse
import signal
import datetime
import traceback
from pathlib import Path
from datetime import datetime

try:
    from mitmproxy import http
    from mitmproxy import ctx
    from mitmproxy.tools.main import mitmdump
except ImportError:
    print("Error: mitmproxy is required. Install it with 'pip install mitmproxy'")
    sys.exit(1)

# Configuration
OUTPUT_DIR = os.path.expanduser('~/.config/trae-claude/tokens')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Global variables
captured_tokens = set()

def timestamp():
    """Get a formatted timestamp for the current time."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

class TraeTokenExtractor:
    """Extract authentication tokens from Trae API traffic."""
    
    def __init__(self):
        """Initialize the token extractor."""
        self.token_patterns = [
            r'Authorization:\s*Cloud-IDE-JWT\s+([a-zA-Z0-9_\-\.]+)',
            r'x-cloudide-token:\s*([a-zA-Z0-9_\-\.]+)',
            r'"token"\s*:\s*"([a-zA-Z0-9_\-\.]+)"'
        ]
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Process HTTP requests to extract tokens."""
        if 'trae-api' in flow.request.pretty_host:
            ctx.log.info(f"Captured request to {flow.request.pretty_host}")
            self._extract_token_from_headers(flow.request.headers)
            self._extract_token_from_content(flow.request.content)
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Process HTTP responses to extract tokens."""
        if 'trae-api' in flow.request.pretty_host:
            ctx.log.info(f"Captured response from {flow.request.pretty_host}")
            self._extract_token_from_headers(flow.response.headers)
            self._extract_token_from_content(flow.response.content)
    
    def _extract_token_from_headers(self, headers):
        """Extract token from HTTP headers."""
        for key, value in headers.items():
            if key.lower() == 'authorization' and 'cloud-ide-jwt' in value.lower():
                token = value.split()[-1]
                self._save_token(token)
            elif key.lower() == 'x-cloudide-token':
                self._save_token(value)
    
    def _extract_token_from_content(self, content):
        """Extract token from HTTP content."""
        if not content:
            return
            
        try:
            # Try to decode content as UTF-8
            content_str = content.decode('utf-8', errors='ignore')
            
            # Look for tokens in the content
            for pattern in self.token_patterns:
                matches = re.findall(pattern, content_str)
                for token in matches:
                    if self._is_valid_jwt(token):
                        self._save_token(token)
                        
            # Try to parse JSON
            try:
                data = json.loads(content_str)
                self._extract_token_from_json(data)
            except json.JSONDecodeError:
                pass
                
        except Exception as e:
            ctx.log.error(f"Error extracting token from content: {str(e)}")
    
    def _extract_token_from_json(self, data, path=""):
        """Recursively extract tokens from JSON data."""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                if key == "token" and isinstance(value, str) and self._is_valid_jwt(value):
                    self._save_token(value)
                    ctx.log.info(f"Found token in JSON at path: {current_path}")
                
                if isinstance(value, (dict, list)):
                    self._extract_token_from_json(value, current_path)
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                if isinstance(item, (dict, list)):
                    self._extract_token_from_json(item, current_path)
    
    def _is_valid_jwt(self, token):
        """Check if a string appears to be a valid JWT token."""
        if not token or len(token) < 30:
            return False
            
        # Check JWT format (header.payload.signature)
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        try:
            # Try to decode header
            header_raw = parts[0]
            # Fix padding
            header_raw += '=' * (4 - len(header_raw) % 4) if len(header_raw) % 4 else ''
            # Replace URL-safe characters
            header_raw = header_raw.replace('-', '+').replace('_', '/')
            
            # Try to decode
            header = json.loads(base64.b64decode(header_raw).decode('utf-8'))
            
            # Check for typical JWT header fields
            if not ('alg' in header and 'typ' in header):
                return False
                
            return True
            
        except Exception:
            return False
    
    def _save_token(self, token):
        """Save the token to a file if it's new."""
        global captured_tokens
        
        if token in captured_tokens:
            return
            
        captured_tokens.add(token)
        
        # Decode token to check expiration and get info
        token_info = self._decode_jwt(token)
        
        # Save token to file
        token_file = os.path.join(OUTPUT_DIR, f"trae_token_{timestamp()}.txt")
        with open(token_file, 'w') as f:
            f.write(token)
        
        # Print info
        ctx.log.info(f"Captured new Trae token!")
        ctx.log.info(f"Token saved to {token_file}")
        ctx.log.info(f"Token issuer: {token_info.get('iss', 'unknown')}")
        ctx.log.info(f"Token subject: {token_info.get('sub', 'unknown')}")
        
        # Print JWT details
        if 'exp' in token_info:
            exp_time = datetime.fromtimestamp(token_info['exp'])
            ctx.log.info(f"Token expires: {exp_time}")
        
        # Print usage instructions
        ctx.log.info("\nTo use this token with the Trae Claude CLI:")
        ctx.log.info(f"python3 src/trae_claude_cli.py login --token \"{token}\"")
    
    def _decode_jwt(self, token):
        """Decode JWT token to extract expiration time and other details."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {}
                
            # Decode payload
            payload_raw = parts[1]
            # Fix padding
            payload_raw += '=' * (4 - len(payload_raw) % 4) if len(payload_raw) % 4 else ''
            # Replace URL-safe characters
            payload_raw = payload_raw.replace('-', '+').replace('_', '/')
            
            # Try to decode
            payload = json.loads(base64.b64decode(payload_raw).decode('utf-8'))
            return payload
            
        except Exception:
            return {}

def run_proxy(port):
    """Run the mitmproxy to capture tokens."""
    print(f"Starting Trae token capture proxy on port {port}")
    print(f"Configure your application to use this proxy: 127.0.0.1:{port}")
    print("Press Ctrl+C to stop the proxy")
    
    # Command-line arguments for mitmproxy
    args = [
        '--listen-port', str(port),
        '--set', 'flow_detail=0',
        '--quiet',
        '-s', __file__,  # Use this file as the script
    ]
    
    try:
        mitmdump(args)
    except KeyboardInterrupt:
        print("\nProxy stopped by user")
    except Exception as e:
        print(f"Error running proxy: {str(e)}")
        if os.environ.get("TRAE_DEBUG"):
            traceback.print_exc()

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Trae Token Capture - Extract JWT tokens from Trae API traffic")
    parser.add_argument('--port', type=int, default=8080, help='Port to run the proxy on (default: 8080)')
    args = parser.parse_args()
    
    # Print introduction
    print("\n=== Trae Token Capture ===")
    print("This tool captures authentication tokens from Trae API traffic")
    print("Use this to obtain tokens for the Trae Claude CLI")
    print("\nSetup instructions:")
    print("1. Start an app that uses Trae API (e.g., Cursor)")
    print(f"2. Configure the app to use HTTP proxy: 127.0.0.1:{args.port}")
    print("3. Interact with the app until you see 'Captured new Trae token!'")
    print("4. Use the captured token with trae_claude_cli.py\n")
    
    run_proxy(args.port)

# For mitmproxy
addons = [TraeTokenExtractor()]

if __name__ == "__main__":
    main() 