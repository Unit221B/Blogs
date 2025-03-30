#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Trae CLI - Command-line interface for Trae AI API
Based on reverse engineering of the Trae API traffic
"""

import os
import sys
import json
import argparse
import getpass
import uuid
import requests
from pathlib import Path
from datetime import datetime

# Configuration
CONFIG_DIR = os.path.expanduser('~/.config/trae-cli')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
CREDENTIALS_FILE = os.path.join(CONFIG_DIR, 'credentials.json')

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

class TraeAPI:
    """Trae API client."""
    
    def __init__(self, config_path=None):
        """Initialize the API client."""
        self.config = self._load_config(config_path)
        self.credentials = self._load_credentials()
        self.base_url = US_ENDPOINT if self.config.get('region', 'us') == 'us' else SG_ENDPOINT
        
    def _load_config(self, config_path=None):
        """Load configuration from file or create default."""
        if config_path:
            config_file = config_path
        else:
            config_file = CONFIG_FILE
            
        # Create config directory if it doesn't exist
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}")
                return DEFAULT_CONFIG
        else:
            # Create default config
            with open(config_file, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            return DEFAULT_CONFIG
    
    def _load_credentials(self):
        """Load credentials from file."""
        if os.path.exists(CREDENTIALS_FILE):
            try:
                with open(CREDENTIALS_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading credentials: {e}")
                return {}
        return {}
    
    def _save_credentials(self, credentials):
        """Save credentials to file."""
        os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
        with open(CREDENTIALS_FILE, 'w') as f:
            json.dump(credentials, f, indent=2)
        self.credentials = credentials
    
    def login(self, token=None):
        """Save authentication token."""
        if not token:
            token = getpass.getpass("Enter your JWT token: ")
        
        if not token:
            print("Error: Token is required")
            return False
        
        # Test the token with a check login request
        if self._check_token(token):
            credentials = {
                "token": token,
                "timestamp": datetime.now().isoformat()
            }
            self._save_credentials(credentials)
            print("Authentication successful")
            return True
        else:
            print("Authentication failed. Invalid token.")
            return False
    
    def _check_token(self, token):
        """Check if token is valid."""
        try:
            headers = {
                "x-cloudide-token": token,
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
        """Get authentication headers."""
        if not self.credentials or 'token' not in self.credentials:
            print("Error: Not authenticated. Please run 'login' command first.")
            sys.exit(1)
        
        headers = {
            "authorization": f"Cloud-IDE-JWT {self.credentials['token']}",
            "x-tt-logid": f"02{int(datetime.now().timestamp() * 1000):020d}ffffac1104c{uuid.uuid4().hex[:8]}",
            "x-device-id": self.config.get("device_id"),
            "user-agent": "trae-cli/1.0.0"
        }
        
        if with_content_type:
            headers["content-type"] = "application/json"
            
        return headers
    
    def chat(self, message):
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
            "model": "gpt-4-turbo",
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
            
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line.decode('utf-8'))
                        if 'content' in data:
                            print(data['content'], end='', flush=True)
                    except json.JSONDecodeError:
                        print(line.decode('utf-8'), end='', flush=True)
            print()  # Final newline
        except Exception as e:
            print(f"Error: {e}")
    
    def complete(self, code, file_path):
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
        
        language = self._detect_language(file_path) if file_path else "python"
        
        payload = {
            "conversation_id": request_id,
            "session_id": session_id,
            "code_context": code,
            "file_path": file_path or "snippet.py",
            "language": language,
            "max_tokens": 512,
            "model": "gpt-4-turbo",
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
            
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line.decode('utf-8'))
                        if 'completion' in data:
                            print(data['completion'], end='', flush=True)
                    except json.JSONDecodeError:
                        print(line.decode('utf-8'), end='', flush=True)
            print()  # Final newline
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
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Trae CLI - Command-line interface for Trae AI')
    
    # Global arguments
    parser.add_argument('--config', help='Path to config file')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Login command
    login_parser = subparsers.add_parser('login', help='Login with JWT token')
    login_parser.add_argument('--token', help='JWT token')
    
    # Chat command
    chat_parser = subparsers.add_parser('chat', help='Chat with Trae AI')
    chat_parser.add_argument('message', help='Message to send', nargs='?')
    
    # Complete command
    complete_parser = subparsers.add_parser('complete', help='Get code completions')
    complete_parser.add_argument('--file', help='File path for context')
    complete_parser.add_argument('--code', help='Code for completion')
    
    args = parser.parse_args()
    
    # Create API client
    api = TraeAPI(config_path=args.config)
    
    if args.command == 'login':
        api.login(args.token)
    elif args.command == 'chat':
        api.chat(args.message)
    elif args.command == 'complete':
        api.complete(args.code, args.file)
    else:
        parser.print_help()


if __name__ == '__main__':
    main() 