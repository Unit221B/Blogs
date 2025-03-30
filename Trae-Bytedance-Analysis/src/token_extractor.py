#!/usr/bin/env python3
"""
Token Extractor for Trae API

This script extracts JWT authentication tokens from network logs captured from Cursor or other
clients that interact with the Trae API.

Usage:
    python3 token_extractor.py [log_file]

If no log file is provided, it will prompt you to enter a file path.
"""

import sys
import os
import re
import json
import base64
from datetime import datetime, timedelta

def extract_token_from_log(log_file):
    """Extract JWT token from network log file."""
    if not os.path.exists(log_file):
        print(f"Error: File '{log_file}' does not exist.")
        return None
        
    print(f"Reading log file: {log_file}")
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Try different patterns to extract token
    token = None
    patterns = [
        # Pattern for Authorization header
        r'Authorization:\s*Cloud-IDE-JWT\s+([a-zA-Z0-9_\-\.]+)',
        # Pattern for x-cloudide-token header
        r'x-cloudide-token:\s*([a-zA-Z0-9_\-\.]+)',
        # Pattern for Bearer authorization
        r'Bearer\s+([a-zA-Z0-9_\-\.]+)',
        # Pattern for token field in JSON
        r'"token"\s*:\s*"([a-zA-Z0-9_\-\.]+)"'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content)
        if matches:
            # Use the longest token (most likely to be complete)
            token = sorted(matches, key=len, reverse=True)[0]
            print(f"Found token using pattern: {pattern}")
            break
    
    if not token:
        print("No token found in the log file.")
        return None
        
    return token

def decode_jwt(token):
    """Decode JWT token and display contents."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            print("Warning: Not a standard JWT token (should have 3 parts)")
            return {}
            
        # Decode header and payload
        header_raw = parts[0]
        payload_raw = parts[1]
        
        # Fix padding for base64 decoding
        header_raw += '=' * (4 - len(header_raw) % 4)
        payload_raw += '=' * (4 - len(payload_raw) % 4)
        
        # Replace URL-safe characters
        header_raw = header_raw.replace('-', '+').replace('_', '/')
        payload_raw = payload_raw.replace('-', '+').replace('_', '/')
        
        # Decode
        try:
            header = json.loads(base64.b64decode(header_raw).decode('utf-8'))
            payload = json.loads(base64.b64decode(payload_raw).decode('utf-8'))
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2][:10] + '...'  # First 10 chars of signature
            }
        except Exception as e:
            print(f"Error decoding token parts: {str(e)}")
            return {}
            
    except Exception as e:
        print(f"Error parsing token: {str(e)}")
        return {}

def check_token_expiration(decoded_token):
    """Check if token is expired or will expire soon."""
    try:
        payload = decoded_token.get('payload', {})
        exp_time = payload.get('exp')
        
        if not exp_time:
            print("Token has no expiration date")
            return "unknown"
            
        exp_date = datetime.fromtimestamp(exp_time)
        now = datetime.now()
        
        if exp_date < now:
            print(f"Token EXPIRED on {exp_date}")
            return "expired"
        else:
            time_left = exp_date - now
            print(f"Token valid until: {exp_date} ({time_left.days} days, {time_left.seconds // 3600} hours left)")
            
            if time_left < timedelta(days=7):
                return "expiring_soon"
            else:
                return "valid"
                
    except Exception as e:
        print(f"Error checking expiration: {str(e)}")
        return "unknown"

def save_token_to_file(token):
    """Save token to a file for easy use."""
    try:
        filename = "trae_token.txt"
        with open(filename, 'w') as f:
            f.write(token)
        print(f"Token saved to {filename}")
    except Exception as e:
        print(f"Error saving token: {str(e)}")

def main():
    """Main function."""
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = input("Enter path to network log file: ")
    
    token = extract_token_from_log(log_file)
    if not token:
        return
    
    print("\n" + "=" * 80)
    print("EXTRACTED TOKEN:")
    print(token)
    print("=" * 80 + "\n")
    
    # Decode and analyze token
    decoded = decode_jwt(token)
    if decoded:
        print("TOKEN DETAILS:")
        print(json.dumps(decoded, indent=2))
        print("\n" + "=" * 80)
        
        # Check expiration
        status = check_token_expiration(decoded)
        print("\n" + "=" * 80)
        
        # Save token to file
        save_token_to_file(token)
        
        # Print usage instructions
        print("\nUSAGE INSTRUCTIONS:")
        print(f"python3 src/trae_claude_cli.py login --token \"{token}\"")
        print("python3 src/trae_claude_cli.py chat \"Hello, what can you do for me?\"")
        
if __name__ == "__main__":
    main() 