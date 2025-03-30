#!/usr/bin/env python3
"""
Trae Embedded CLI - Command-line interface for Trae AI API with embedded authentication
Based on reverse engineering of the Trae API traffic
"""

import os
import sys
import json
import argparse
import uuid
import requests
from pathlib import Path
from datetime import datetime

# Embedded JWT token from captured traffic (valid for approximately 72 hours from 2025-03-25)
EMBEDDED_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoiNzQ4NDA4MzU3NzI0OTYxMjgwNSIsInNvdXJjZSI6InJlZnJlc2hfdG9rZW4iLCJzb3VyY2VfaWQiOiI2UWR3TjNHTVVka05tRjZUUjVNbUQtWnBlRnVQU3RZNUtfb3Z2MkRBMV9nPS4xODJmYmE2ZDRjYjRkNWFiIiwidGVuYW50X2lkIjoiN28yZDg5NHA3ZHIwbzQiLCJ0eXBlIjoidXNlciJ9LCJleHAiOjE3NDMwNzU3NTksImlhdCI6MTc0MjgxNjU1OX0.mXQn1IWkG7AHjB22J8136278SVaAAALXTFPICQOoRoORDzwZJympy0DrvAvBRutWu0xdTUW93CYegnhU7V0jJZ-bq4V4lzzu2gghdURrioPsZoXjSy0JLNsaff-lpx7yfiSOGQF2LnSWC1A8wcN06F7KY3bHi4OjBOCDcbueTCd5XO4XhdjPlBtZG7B5GMbRSxttnDgBUbsxKRljcjOls3ltXw1HuSCDNxTFUdWhNNVFPVyf0eYpAbsEI-GnTK1pRTFm2p0e73gOn6zSu3EpKlby0mJwZZLux1TKEO399_pDDQ7BT_l0tNCmYraGuEnp1QxxvcAjkEP8tLiLKVFpvqiybMVg-dF6Dm_u-BepD-lTL2IvndO1ouzKC6w2a17H8OrM5ZujKgMF13DJ0o-WOkxLtv1FGkZTxQUj5AWWHrBCXAFxc3ymIWi4XTV_FRyOYHowdbEINw9JbtYCIZ9MakcFDh21uFkrmERrNlguPzVIbeWxKyYhpU3YEzApGbcjH1axzXnaVOufkn4bOW2SzcaCYZfWEm7y8nts3UtCSPhUSr3L6N8U11_T5akO2hfMGiiD8hQITK6Inbis4b9EiCGb1uuF3xxLwYNEF2WECOqYX0J7DS8w-4tduCBq4mOQYIlGhArAnNe5pCdk7n1tszQ_yYg7iplKfi2ZJRgVC6M"

# API endpoints
US_ENDPOINT = "https://trae-api-us.mchost.guru"
SG_ENDPOINT = "https://trae-api-sg.mchost.guru"
CHECK_LOGIN_ENDPOINT = "https://api-us-east.trae.ai/cloudide/api/v3/trae/CheckLogin"

# Default config
DEFAULT_CONFIG = {
    "region": "us",  # or 'sg'
    "app_id": "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8",
    "version": "1.0.9698",
    "device_id": str(uuid.uuid4()).replace('-', '')
}

class TraeEmbeddedAPI:
    """Trae API client with embedded token authentication."""
    
    def __init__(self, region=None):
        """Initialize the API client with embedded credentials."""
        self.config = DEFAULT_CONFIG
        if region:
            self.config["region"] = region
        
        self.base_url = US_ENDPOINT if self.config.get('region', 'us') == 'us' else SG_ENDPOINT
        
        # Verify the embedded token is working
        if not self._check_token():
            print("Warning: Embedded token may have expired. Please update the token in the script.")
    
    def _check_token(self):
        """Check if the embedded token is valid."""
        try:
            headers = {
                "x-cloudide-token": EMBEDDED_TOKEN,
                "User-Agent": "trae-cli/1.0.0",
                "Content-Type": "application/json"
            }
            
            response = requests.get(CHECK_LOGIN_ENDPOINT, headers=headers)
            
            if response.status_code == 200:
                return True
            return False
        except Exception as e:
            print(f"Error checking token: {e}")
            return False
    
    def _get_auth_headers(self, with_content_type=True):
        """Get authentication headers with the embedded token."""
        headers = {
            "authorization": f"Cloud-IDE-JWT {EMBEDDED_TOKEN}",
            "x-tt-logid": f"02{int(datetime.now().timestamp() * 1000):020d}ffffac1104c{uuid.uuid4().hex[:8]}",
            "x-device-id": self.config.get("device_id"),
            "user-agent": "trae-cli/1.0.0"
        }
        
        if with_content_type:
            headers["content-type"] = "application/json"
            
        return headers
    
    def chat(self, message, model="gpt-4-turbo", temperature=0.7, max_tokens=4096):
        """Send a chat message to Trae AI."""
        if not message:
            print("Error: Message is required")
            return
        
        url = f"{self.base_url}/api/ide/v1/llm_raw_chat"
        
        request_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        
        payload = {
            "conversation_id": request_id,
            "session_id": session_id,
            "user_message": message,
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "region": "us" if self.base_url == US_ENDPOINT else "sg",
            "env": {
                "ide_type": "native",
                "app_id": self.config.get("app_id"),
                "app_version": self.config.get("version")
            }
        }
        
        try:
            headers = self._get_auth_headers()
            response = requests.post(url, headers=headers, json=payload, stream=True)
            
            if response.status_code != 200:
                print(f"Error: {response.status_code} - {response.text}")
                return
            
            # Handle streaming response
            print("\nTrae AI Response:\n")
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line.decode('utf-8'))
                        if 'content' in data:
                            print(data['content'], end='', flush=True)
                    except json.JSONDecodeError:
                        print(line.decode('utf-8'), end='', flush=True)
            print("\n")  # Final newlines
        except Exception as e:
            print(f"Error: {e}")
    
    def complete(self, code=None, file_path=None, language=None, model="gpt-4-turbo", temperature=0.7, max_tokens=1024):
        """Get code completions."""
        if not code and not file_path:
            print("Error: Either code or file_path is required")
            return
        
        # Read from stdin if no code provided but file path is
        if not code and file_path:
            if not sys.stdin.isatty():
                code = sys.stdin.read()
            else:
                try:
                    with open(file_path, 'r') as f:
                        code = f.read()
                except Exception as e:
                    print(f"Error reading file: {e}")
                    return
        
        url = f"{self.base_url}/api/ide/v1/llm_code_completion"
        
        # Use a random request ID and session ID
        request_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        
        if not language and file_path:
            language = self._detect_language(file_path)
        elif not language:
            language = "python"  # Default to Python
        
        payload = {
            "conversation_id": request_id,
            "session_id": session_id,
            "code_context": code,
            "file_path": file_path or "snippet.py",
            "language": language,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "model": model,
            "region": "us" if self.base_url == US_ENDPOINT else "sg",
            "env": {
                "ide_type": "native",
                "app_id": self.config.get("app_id"),
                "app_version": self.config.get("version")
            }
        }
        
        try:
            headers = self._get_auth_headers()
            response = requests.post(url, headers=headers, json=payload, stream=True)
            
            if response.status_code != 200:
                print(f"Error: {response.status_code} - {response.text}")
                return
            
            # Handle streaming response for code completion
            print("\nTrae AI Code Completion:\n")
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line.decode('utf-8'))
                        if 'completion' in data:
                            print(data['completion'], end='', flush=True)
                    except json.JSONDecodeError:
                        print(line.decode('utf-8'), end='', flush=True)
            print("\n")  # Final newlines
        except Exception as e:
            print(f"Error: {e}")
    
    def _detect_language(self, file_path):
        """Detect programming language from file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.html': 'html',
            '.css': 'css',
            '.scss': 'scss',
            '.json': 'json',
            '.md': 'markdown',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.java': 'java',
            '.rb': 'ruby',
            '.go': 'go',
            '.php': 'php',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.sh': 'bash',
            '.bash': 'bash',
            '.sql': 'sql'
        }
        
        return language_map.get(ext, 'plaintext')


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Trae Embedded CLI - Command-line interface for Trae AI with embedded authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Chat with Trae AI
  ./trae_embedded_cli.py chat "Write a Python function to calculate Fibonacci numbers"
  
  # Get code completion for a specific file
  ./trae_embedded_cli.py complete --file path/to/your/file.py
  
  # Get code completion with custom code input
  ./trae_embedded_cli.py complete --code "def fibonacci(n):"
  
  # Pipe code from a file to get completion
  cat path/to/file.py | ./trae_embedded_cli.py complete --file path/to/file.py
  
  # Use a specific model and temperature
  ./trae_embedded_cli.py chat "Explain quantum computing" --model gpt-4-turbo --temperature 0.9
"""
    )
    
    # Add subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Chat command
    chat_parser = subparsers.add_parser('chat', help='Chat with Trae AI')
    chat_parser.add_argument('message', help='Message to send')
    chat_parser.add_argument('--model', default='gpt-4-turbo', help='AI model to use (default: gpt-4-turbo)')
    chat_parser.add_argument('--temperature', type=float, default=0.7, help='Temperature for generating responses (default: 0.7)')
    chat_parser.add_argument('--max-tokens', type=int, default=4096, help='Maximum number of tokens in the response (default: 4096)')
    chat_parser.add_argument('--region', choices=['us', 'sg'], default=None, help='API region to use (default: us)')
    
    # Complete command
    complete_parser = subparsers.add_parser('complete', help='Get code completions')
    complete_parser.add_argument('--file', help='File path for context')
    complete_parser.add_argument('--code', help='Code for completion')
    complete_parser.add_argument('--language', help='Programming language (if not specified, detected from file extension)')
    complete_parser.add_argument('--model', default='gpt-4-turbo', help='AI model to use (default: gpt-4-turbo)')
    complete_parser.add_argument('--temperature', type=float, default=0.7, help='Temperature for generating completions (default: 0.7)')
    complete_parser.add_argument('--max-tokens', type=int, default=1024, help='Maximum number of tokens in the completion (default: 1024)')
    complete_parser.add_argument('--region', choices=['us', 'sg'], default=None, help='API region to use (default: us)')
    
    args = parser.parse_args()
    
    # Create API client
    api = TraeEmbeddedAPI(region=args.region if hasattr(args, 'region') and args.region else None)
    
    if args.command == 'chat':
        api.chat(
            message=args.message,
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens
        )
    elif args.command == 'complete':
        api.complete(
            code=args.code,
            file_path=args.file,
            language=args.language,
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens
        )
    else:
        parser.print_help()


if __name__ == '__main__':
    main() 