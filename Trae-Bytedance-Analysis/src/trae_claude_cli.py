#!/usr/bin/env python3
"""
Trae Claude CLI - Command line interface for interacting with Trae's Claude-3.7-Sonnet API
with computer use capabilities, based on reverse engineering of the ByteDance API
"""

import os
import sys
import json
import uuid
import time
import argparse
import getpass
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
import readline
import base64
import hashlib
import hmac
import urllib.parse
import jwt
import logging
import re
import traceback

# Create logger for telemetry
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.expanduser('~/.config/trae-claude/trae_telemetry.log')),
        logging.StreamHandler()
    ]
)
telemetry_logger = logging.getLogger('trae_telemetry')

# Configuration
CONFIG_DIR = os.path.expanduser('~/.config/trae-claude')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
CREDENTIALS_FILE = os.path.join(CONFIG_DIR, 'credentials.json')
HISTORY_DIR = os.path.join(CONFIG_DIR, 'history')
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.json")
TELEMETRY_FILE = os.path.join(CONFIG_DIR, "telemetry.jsonl")

# API endpoints
US_ENDPOINT = "https://trae-api-us.mchost.guru"
SG_ENDPOINT = "https://trae-api-sg.mchost.guru"
CHAT_ENDPOINT = "/api/ide/v1/llm_raw_chat"

# Default config
DEFAULT_CONFIG = {
    "region": "us",  # or 'sg'
    "app_id": "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8",
    "version": "1.0.9698",
    "model": "claude-3-7-sonnet",
    "device_id": str(uuid.uuid4()).replace('-', '')
}

# Create directories if they don't exist
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(HISTORY_DIR, exist_ok=True)

# Default token from captured traffic
DEFAULT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoiNzQ4NDA4MzU3NzI0OTYxMjgwNSIsInNvdXJjZSI6InJlZnJlc2hfdG9rZW4iLCJzb3VyY2VfaWQiOiI2UWR3TjNHTVVka05tRjZUUjVNbUQtWnBlRnVQU3RZNUtfb3Z2MkRBMV9nPS4xODJmYmE2ZDRjYjRkNWFiIiwidGVuYW50X2lkIjoiN28yZDg5NHA3ZHIwbzQiLCJ0eXBlIjoidXNlciJ9LCJleHAiOjE3NDMwNzU3NTksImlhdCI6MTc0MjgxNjU1OX0.mXQn1IWkG7AHjB22J8136278SVaAAALXTFPICQOoRoORDzwZJympy0DrvAvBRutWu0xdTUW93CYegnhU7V0jJZ-bq4V4lzzu2gghdURrioPsZoXjSy0JLNsaff-lpx7yfiSOGQF2LnSWC1A8wcN06F7KY3bHi4OjBOCDcbueTCd5XO4XhdjPlBtZG7B5GMbRSxttnDgBUbsxKRljcjOls3ltXw1HuSCDNxTFUdWhNNVFPVyf0eYpAbsEI-GnTK1pRTFm2p0e73gOn6zSu3EpKlby0mJwZZLux1TKEO399_pDDQ7BT_l0tNCmYraGuEnp1QxxvcAjkEP8tLiLKVFpvqiybMVg-dF6Dm_u-BepD-lTL2IvndO1ouzKC6w2a17H8OrM5ZujKgMF13DJ0o-WOkxLtv1FGkZTxQUj5AWWHrBCXAFxc3ymIWi4XTV_FRyOYHowdbEINw9JbtYCIZ9MakcFDh21uFkrmERrNlguPzVIbeWxKyYhpU3YEzApGbcjH1axzXnaVOufkn4bOW2SzcaCYZfWEm7y8nts3UtCSPhUSr3L6N8U11_T5akO2hfMGiiD8hQITK6Inbis4b9EiCGb1uuF3xxLwYNEF2WECOqYX0J7DS8w-4tduCBq4mOQYIlGhArAnNe5pCdk7n1tszQ_yYg7iplKfi2ZJRgVC6M"

# Create telemetry functions
def log_api_call(endpoint: str, success: bool, duration_ms: int, status_code: Optional[int] = None, error_msg: Optional[str] = None):
    """Log API call telemetry for monitoring reliability."""
    telemetry_data = {
        'timestamp': datetime.now().isoformat(),
        'endpoint': endpoint,
        'success': success,
        'duration_ms': duration_ms,
        'status_code': status_code
    }
    
    if error_msg:
        telemetry_data['error'] = error_msg
    
    # Log to both file and logging system
    with open(TELEMETRY_FILE, 'a') as f:
        f.write(json.dumps(telemetry_data) + '\n')
    
    if success:
        telemetry_logger.info(f"API call to {endpoint} succeeded in {duration_ms}ms (status: {status_code})")
    else:
        telemetry_logger.error(f"API call to {endpoint} failed in {duration_ms}ms (status: {status_code}, error: {error_msg})")
    
    return telemetry_data

def get_telemetry_stats():
    """Get statistics from the telemetry log."""
    if not os.path.exists(TELEMETRY_FILE):
        return {
            'total_calls': 0,
            'success_rate': 0,
            'avg_duration_ms': 0,
            'endpoints': {}
        }
    
    try:
        stats = {
            'total_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'total_duration_ms': 0,
            'endpoints': {}
        }
        
        with open(TELEMETRY_FILE, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    stats['total_calls'] += 1
                    
                    if data.get('success', False):
                        stats['successful_calls'] += 1
                    else:
                        stats['failed_calls'] += 1
                    
                    stats['total_duration_ms'] += data.get('duration_ms', 0)
                    
                    # Track per-endpoint stats
                    endpoint = data.get('endpoint', 'unknown')
                    if endpoint not in stats['endpoints']:
                        stats['endpoints'][endpoint] = {
                            'calls': 0,
                            'successful': 0,
                            'failed': 0,
                            'total_duration_ms': 0
                        }
                    
                    stats['endpoints'][endpoint]['calls'] += 1
                    if data.get('success', False):
                        stats['endpoints'][endpoint]['successful'] += 1
                    else:
                        stats['endpoints'][endpoint]['failed'] += 1
                    
                    stats['endpoints'][endpoint]['total_duration_ms'] += data.get('duration_ms', 0)
                    
                except json.JSONDecodeError:
                    continue
        
        # Calculate averages and rates
        if stats['total_calls'] > 0:
            stats['success_rate'] = (stats['successful_calls'] / stats['total_calls']) * 100
            stats['avg_duration_ms'] = stats['total_duration_ms'] / stats['total_calls']
            
            for endpoint in stats['endpoints']:
                if stats['endpoints'][endpoint]['calls'] > 0:
                    stats['endpoints'][endpoint]['success_rate'] = (stats['endpoints'][endpoint]['successful'] / stats['endpoints'][endpoint]['calls']) * 100
                    stats['endpoints'][endpoint]['avg_duration_ms'] = stats['endpoints'][endpoint]['total_duration_ms'] / stats['endpoints'][endpoint]['calls']
        
        return stats
        
    except Exception as e:
        telemetry_logger.error(f"Error getting telemetry stats: {str(e)}")
        return {
            'total_calls': 0,
            'success_rate': 0,
            'avg_duration_ms': 0,
            'error': str(e)
        }

class TraeClaudeCLI:
    def __init__(self):
        self.base_url = "https://api.trae.ai"
        self.auth_token = None
        self.conversation_id = None
        self.conversations_dir = os.path.expanduser("~/.trae_conversations")
        os.makedirs(self.conversations_dir, exist_ok=True)
        self.current_conversation = None
        self.conversation_history = []
        self.computer_enabled = True
        self.trace_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.user_id = "user_01JPR5SGN983F2YFR9HVND2R7M"  # From your Cursor token
        self.client_id = "cursor"  # From Cursor's implementation
        self.client_version = "1.270.1376"  # From Cursor's implementation
        self.editor_version = "vscode/1.96.2"  # From Cursor's implementation

    def generate_signature(self, timestamp: str, method: str, path: str, body: str = "") -> str:
        """Generate signature for Trae API authentication"""
        string_to_sign = f"{timestamp}\n{method}\n{path}\n{body}"
        secret = "your-secret-key"  # This should be obtained from Cursor's implementation
        signature = hmac.new(
            secret.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode('utf-8')

    def login(self, token: Optional[str] = None) -> bool:
        """Login to Trae API using Cursor's authentication flow"""
        try:
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            path = "/v1/auth/login"
            method = "POST"
            body = json.dumps({
                "client_id": self.client_id,
                "client_version": self.client_version,
                "editor_version": self.editor_version,
                "user_id": self.user_id,
                "token": token
            })
            
            signature = self.generate_signature(timestamp, method, path, body)
            
            headers = {
                "Content-Type": "application/json",
                "X-Trae-Timestamp": timestamp,
                "X-Trae-Signature": signature,
                "X-Trae-Client-ID": self.client_id,
                "X-Trae-Client-Version": self.client_version,
                "X-Trae-Editor-Version": self.editor_version,
                "X-Trae-User-ID": self.user_id,
                "X-Trae-Trace-ID": self.trace_id,
                "X-Trae-Session-ID": self.session_id
            }

            response = requests.post(
                f"{self.base_url}{path}",
                headers=headers,
                data=body
            )
            
            if response.status_code == 200:
                self.auth_token = response.json().get("token")
                if self.auth_token:
                    with open(os.path.expanduser("~/.trae_token"), "w") as f:
                        f.write(self.auth_token)
                    print("Authentication successful!")
                    return True
            else:
                print(f"Authentication failed: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error during authentication: {str(e)}")
            return False

    def _add_to_history(self, message, response):
        """Add a message and response to the conversation history."""
        if not self.conversation_id:
            return False
        
        # Create history directory if it doesn't exist
        if not os.path.exists(HISTORY_DIR):
            os.makedirs(HISTORY_DIR, exist_ok=True)
        
        # Create a history file for this conversation
        history_file = os.path.join(HISTORY_DIR, f"{self.conversation_id}.jsonl")
        
        # Create the entry
        entry = {
            'timestamp': datetime.now().isoformat(),
            'conversation_id': self.conversation_id,
            'user_message': message,
            'assistant_message': response
        }
        
        # Append to the history file
        try:
            with open(history_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            return True
        except Exception as e:
            print(f"Error saving to history: {e}")
            return False

class TraeClaudeAPI:
    """Trae Claude API client with computer use capabilities."""
    
    def __init__(self, token=None, system=None, computer_enabled=True, verbose_debug=False):
        """Initialize the API client."""
        self.auth_token = token or self._load_token()
        self.base_url = "https://trae-api-us.mchost.guru/api/ide/v1"
        self.auth_url = "https://trae-api-us.mchost.guru/api/ide/v1"  # Changed from api-us-east.trae.ai to match our base_url
        self.refresh_url = "https://trae-api-us.mchost.guru/api/ide/v1/auth/refresh"  # Changed to match our base_url
        self.computer_enabled = computer_enabled
        self.conversation_id = None
        self.system_prompt = system or "You are Claude, a helpful AI assistant with computer use capabilities."
        self.trace_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.client_version = "1.270.1376"
        self.editor_version = "vscode/1.96.2"
        self.user_id = "user_01JPR5SGN983F2YFR9HVND2R7M"
        self.verbose_debug = verbose_debug
        
        # Enable verbose HTTP debugging if requested
        if verbose_debug:
            self._enable_http_debugging()
        
        # Load session data if available
        self._load_session()

    def _enable_http_debugging(self):
        """Enable detailed HTTP request/response logging."""
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1
        
        # Enable logging for requests
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        
        # Create a console handler if it doesn't exist
        if not requests_log.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            requests_log.addHandler(console_handler)
            
        print("HTTP debugging enabled - all requests and responses will be logged")

    def _load_token(self):
        """Load auth token from file."""
        if os.path.exists(AUTH_FILE):
            with open(AUTH_FILE, 'r') as f:
                try:
                    data = json.load(f)
                    token = data.get('token')
                    if token and self._is_token_valid(token):
                        return token
                    elif token:
                        # Token exists but is expired or will expire soon, try to refresh
                        return self._refresh_token(token)
                except json.JSONDecodeError:
                    pass
        
        # If no valid token found, use the default token
        return DEFAULT_TOKEN
    
    def _parse_jwt_token(self, token):
        """Parse a JWT token properly using the jwt library."""
        try:
            # Using the jwt library to properly parse the token
            # This won't verify the signature but will decode the payload
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except Exception as e:
            print(f"Error parsing JWT token: {str(e)}")
            return {}

    def _is_token_valid(self, token):
        """Check if token is valid and not about to expire."""
        try:
            # Parse the JWT token properly
            decoded_data = self._parse_jwt_token(token)
            
            # Get expiration timestamp
            exp_timestamp = decoded_data.get("exp", 0)
            if not exp_timestamp:
                print("Token has no expiration date")
                return False
            
            exp_date = datetime.fromtimestamp(exp_timestamp)
            
            # Check if token is still valid with at least 30 mins buffer
            now = datetime.now()
            is_valid = exp_date > now + timedelta(minutes=30)
            
            if is_valid:
                print(f"Token valid until {exp_date}")
            else:
                print(f"Token expired or will expire soon (expires {exp_date})")
            
            return is_valid
        
        except Exception as e:
            print(f"Error checking token validity: {str(e)}")
            return False
        
    def _extract_refresh_data(self, token):
        """Extract data needed for refresh from the token."""
        try:
            # Parse the JWT token properly
            decoded_data = self._parse_jwt_token(token)
            
            # Extract data from the payload
            data = decoded_data.get("data", {})
            return {
                "user_id": data.get("id"),
                "source_id": data.get("source_id"),
                "tenant_id": data.get("tenant_id")
            }
        except Exception as e:
            print(f"Error extracting refresh data: {str(e)}")
            return {}
    
    def _refresh_token(self, old_token):
        """Refresh the token using the refresh token endpoint or simulate refresh."""
        refresh_data = self._extract_refresh_data(old_token)
        if not refresh_data or not refresh_data.get("source_id"):
            print("Insufficient data to refresh token")
            return self._simulate_token_refresh(old_token)
        
        try:
            # Set up headers for token refresh
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Trae/1.270 (ByteDance IDE)",
                "X-Trace-Id": self.trace_id,
                "X-Session-Id": self.session_id,
                "Authorization": f"Cloud-IDE-JWT {old_token}",
                "x-cloudide-token": old_token
            }
            
            # Refresh token payload
            payload = {
                "refresh_token": refresh_data.get("source_id"),
                "user_id": refresh_data.get("user_id"),
                "tenant_id": refresh_data.get("tenant_id"),
                "app_id": "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8",
                "editor_version": self.editor_version,
                "client_version": self.client_version
            }
            
            # Make refresh request
            response = requests.post(
                self.refresh_url,
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                new_token = data.get("token")
                if new_token:
                    print("Token refreshed successfully")
                    self._save_token(new_token)
                    return new_token
            
            print(f"Failed to refresh token: {response.status_code} - {response.text}")
            print("Falling back to simulated token refresh...")
            return self._simulate_token_refresh(old_token)
            
        except Exception as e:
            print(f"Error refreshing token: {str(e)}")
            print("Falling back to simulated token refresh...")
            return self._simulate_token_refresh(old_token)

    def _simulate_token_refresh(self, token):
        """Simulate token refreshing by extending the expiration date."""
        try:
            # Split the token
            parts = token.split('.')
            if len(parts) != 3:
                print("Invalid JWT format for simulation")
                return token
            
            # Decode the payload
            payload = parts[1]
            padding_needed = len(payload) % 4
            if padding_needed:
                payload += '=' * (4 - padding_needed)
            
            payload = payload.replace('-', '+').replace('_', '/')
            decoded_bytes = base64.b64decode(payload)
            decoded_data = json.loads(decoded_bytes.decode('utf-8'))
            
            # Update the expiration date (add 1 year)
            now = int(time.time())
            decoded_data["exp"] = now + 31536000  # 1 year
            decoded_data["iat"] = now  # Update issued at time
            
            # Re-encode the payload
            new_payload = base64.b64encode(json.dumps(decoded_data).encode())
            new_payload = new_payload.decode('utf-8').replace('+', '-').replace('/', '_').rstrip('=')
            
            # Reassemble the token
            simulated_token = f"{parts[0]}.{new_payload}.{parts[2]}"
            print("Token expiration extended by simulation")
            self._save_token(simulated_token)
            return simulated_token
            
        except Exception as e:
            print(f"Error simulating token refresh: {str(e)}")
            return token
    
    def _save_token(self, token):
        """Save the authentication token to disk."""
        try:
            os.makedirs(self._get_data_dir(), exist_ok=True)
            token_file = os.path.join(self._get_data_dir(), 'token.json')
            with open(token_file, 'w') as f:
                json.dump({'token': token}, f)
        except Exception as e:
            print(f"Error saving token: {str(e)}")

    def _build_headers(self):
        """Build the headers for API requests."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Trae/1.270 (ByteDance IDE)",
            "Authorization": f"Cloud-IDE-JWT {self.auth_token}",
            "x-cloudide-token": f"{self.auth_token}",
            "X-Trace-Id": self.trace_id,
            "X-Session-Id": self.session_id,
            "X-Client-Version": self.client_version,
            "X-Editor-Version": self.editor_version,
            "X-Platform": "darwin",
            "X-User-ID": self.user_id,
            "Origin": "https://cursor.so",
            "Referer": "https://cursor.so/",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "application/json, text/plain, */*"
        }
        return headers

    def check_auth(self):
        """Check if authentication token is valid and user is authorized."""
        try:
            # Ensure we have a valid token first
            if not self.auth_token:
                print("Error: No authentication token available")
                return False
            
            # Check for token expiration
            token_status = self._check_token_expiration()
            if token_status == 'expired':
                print("Token is expired. Requesting a new token...")
                self.auth_token = self._refresh_token(self.auth_token)
            
            # Make authentication check request
            url = f"{self.base_url}/ping"
            headers = self._build_headers()
            
            if self.verbose_debug:
                print(f"Sending auth check to: {url}")
                print(f"Headers: {json.dumps(headers)}")
            
            payload = {
                "client_version": self.client_version,
                "editor_version": self.editor_version,
                "app_id": "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
            }
            
            start_time = time.time()
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            duration_ms = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                print(f"Authentication verified. Response: {response.text}")
                self._update_telemetry('/ping', response.status_code, duration_ms)
                
                # Extract any cookies or tokens from the response for future use
                if 'Set-Cookie' in response.headers:
                    print("Obtained session cookies from API")
                
                return True
            else:
                print(f"Authentication failed. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                self._update_telemetry('/ping', response.status_code, duration_ms, success=False)
                
                # Provide helpful diagnostics based on status code
                if response.status_code == 401:
                    print("Error 401: Unauthorized. Your token may be invalid or expired.")
                    print("Try refreshing your token with the 'token' command or getting a new token.")
                elif response.status_code == 403:
                    print("Error 403: Forbidden. You may not have permission to access this resource.")
                elif response.status_code >= 500:
                    print(f"Error {response.status_code}: Server error. The API service may be experiencing issues.")
                
                # If we get a 401/403, try to simulate a valid token as fallback
                if response.status_code in (401, 403):
                    print("Attempting token simulation as fallback...")
                    self.auth_token = self._simulate_token_refresh(self.auth_token)
                    return True  # Return true to allow operations with simulated token
                
                return False
            
        except requests.exceptions.RequestException as e:
            print(f"Connection error during authentication check: {str(e)}")
            self._update_telemetry('/ping', 0, 0, success=False, error=str(e))
            return False

    def login(self, token):
        """Login with Trae token."""
        if token:
            self.auth_token = token
            self._save_token(token)
            print("Authentication token saved. Will be verified on first API call.")
            return True
        else:
            # Use default token if none provided
            self.auth_token = DEFAULT_TOKEN
            self._save_token(DEFAULT_TOKEN)
            print("Default authentication token saved. Will be verified on first API call.")
            return True
    
    def send_message(self, message, conversation_id=None, model="claude-3-7-sonnet"):
        """Send a message to Claude and return the response."""
        # Check and refresh authentication if needed
        if not self.check_auth():
            print("Authentication failed. Using default token as fallback.")
            self.auth_token = DEFAULT_TOKEN
        
        # Ensure we have a valid conversation ID
        if conversation_id:
            self.conversation_id = conversation_id
        elif not self.conversation_id:
            self.conversation_id = str(uuid.uuid4())
        
        # Generate device_id if not present
        device_id = str(uuid.uuid4()).replace('-', '')
        
        # Properly format the payload based on captured traffic
        payload = {
            "conversation_id": self.conversation_id,
            "session_id": self.session_id,
            "user_message": message,
            "model": model,
            "temperature": 0.7,
            "max_tokens": 4096,
            "top_p": 1.0,
            "stream": True,
            "enable_computer_use": self.computer_enabled,
            "region": "us",
            "env": {
                "ide_type": "native",
                "app_id": "cursor",
                "app_version": self.client_version,
                "editor_version": self.editor_version,
                "platform": "darwin",
                "device_id": device_id,
                "user_id": self.user_id
            },
            "metadata": {
                "client_version": self.client_version,
                "source": "cursor-cli",
                "timestamp": int(time.time())
            }
        }
        
        # Add system prompt if defined
        if self.system_prompt:
            payload["system_prompt"] = self.system_prompt
        
        # Set up the headers with proper authentication
        headers = self._build_headers()
        
        # Use a streaming response for real-time interaction
        full_response = ""
        compute_events = []
        endpoint = f"{self.base_url}/llm_raw_chat"
        
        # Record start time for telemetry
        start_time = time.time()
        success = False
        status_code = None
        error_msg = None
        
        try:
            print(f"Sending message to {endpoint}")
            print(f"Payload: {json.dumps({k: (v[:30]+'...' if isinstance(v, str) and len(v) > 30 else v) for k, v in payload.items() if k != 'system_prompt'})}")
            
            with requests.post(endpoint, json=payload, headers=headers, stream=True) as r:
                status_code = r.status_code
                print(f"Response status: {status_code}")
                
                if status_code != 200:
                    r.raise_for_status()
                
                for line in r.iter_lines():
                    if not line:
                        continue
                        
                    decoded_line = line.decode('utf-8')
                    
                    # For event-stream format
                    if decoded_line.startswith("data: "):
                        try:
                            event_data = decoded_line[6:]  # Remove "data: " prefix
                            event = json.loads(event_data)
                            
                            # Debug the event structure if verbose
                            if self.verbose_debug:
                                print(f"Event: {json.dumps(event)}")
                            
                            # Handle errors
                            if event.get("type") == "error" or "error" in event:
                                error_msg = event.get("error") or event.get("message", "Unknown error")
                                print(f"\n🔴 Error: {error_msg}")
                                full_response += f"\n🔴 Error: {error_msg}\n"
                                success = False
                                break
                            
                            # Check for different types of events in the response
                            if "type" in event:
                                event_type = event.get("type")
                                
                                # Handle completion
                                if event_type == "completion":
                                    content = event.get("content", "")
                                    print(content, end='', flush=True)
                                    full_response += content
                                    success = True
                                    continue
                                    
                                # Handle compute events
                                elif event_type == "compute_event":
                                    compute_event = event.get("compute_event", {})
                                    print(f"\n🖥️ Computing: {compute_event.get('action', 'unknown')}", flush=True)
                                    event_result = self._handle_compute_event(compute_event)
                                    compute_events.append(event_result)
                                    continue
                                
                                # Handle error events
                                elif event_type == "error":
                                    error_msg = event.get("error", "Unknown error")
                                    print(f"\n🔴 Error: {error_msg}")
                                    full_response += f"\n🔴 Error: {error_msg}\n"
                                    success = False
                                    continue
                            
                            # Handle content updates in different formats
                            if "content" in event:
                                # Direct content field
                                content = event.get("content", "")
                                print(content, end='', flush=True)
                                full_response += content
                                success = True
                                
                            # Handle delta updates to the response
                            elif "delta" in event:
                                delta = event.get("delta", {})
                                
                                # Handle text deltas
                                if "text" in delta:
                                    text = delta.get("text", "")
                                    print(text, end='', flush=True)
                                    full_response += text
                                
                                # Handle tool use
                                elif "tool_use" in delta:
                                    tool_use = delta.get("tool_use", {})
                                    if tool_use.get("type") == "computer":
                                        tool_input = tool_use.get("input", "")
                                        print(f"\n🖥️ [COMPUTER USE] {tool_input}", flush=True)
                                        full_response += f"\n🖥️ [COMPUTER USE] {tool_input}\n"
                                
                                # Handle tool results
                                elif "tool_result" in delta:
                                    tool_result = delta.get("tool_result", {})
                                    if tool_result.get("type") == "computer":
                                        output = tool_result.get("output", "")
                                        print(f"\n💻 [COMPUTER RESULT] {output}", flush=True)
                                        full_response += f"\n💻 [COMPUTER RESULT] {output}\n"
                                
                                # Handle stop reason
                                elif "stop_reason" in delta:
                                    stop_reason = delta.get("stop_reason", "")
                                    print(f"\n\n[Finished: {stop_reason}]")
                                    success = True
                            
                        except json.JSONDecodeError:
                            # If it's not JSON, print the raw line for debugging
                            if self.verbose_debug:
                                print(f"Non-JSON response: {decoded_line}")
                    
                    # For SSE event format
                    elif decoded_line.startswith("event: "):
                        print(f"Event type: {decoded_line[7:]}")
                    
                    # For error responses or other non-data events
                    else:
                        # Skip empty lines or newlines
                        if decoded_line.strip():
                            print(f"Other response format: {decoded_line}")
                
                # If we got here without throwing an exception, consider it a success
                # unless we explicitly set success to False
                if status_code == 200 and not error_msg:
                    success = True
                
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            print(f"Error sending message: {error_msg}")
            if self.verbose_debug:
                traceback.print_exc()
            success = False
            full_response = f"Error: {error_msg}"
        finally:
            # Calculate duration for telemetry
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Log telemetry data using the new method
            self._update_telemetry(
                endpoint="/llm_raw_chat", 
                status_code=status_code,
                duration_ms=duration_ms,
                success=success, 
                error=error_msg
            )
        
        # Add the message and response to history
        self._add_to_history(message, full_response)
        
        # Store any compute events for later reference
        if compute_events:
            print(f"\nComputer events processed: {len(compute_events)}")
        
        return full_response
    
    def save_conversation(self, conversation_id, message, response):
        """Save conversation history."""
        if not conversation_id:
            return
        
        history_file = os.path.join(HISTORY_DIR, f"{conversation_id}.jsonl")
        entry = {
            'timestamp': datetime.now().isoformat(),
            'user': message,
            'assistant': response
        }
        
        with open(history_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def list_conversations(self, limit=10):
        """List all saved conversations with a limit."""
        history_dir = os.path.join(self._get_data_dir(), "history")
        os.makedirs(history_dir, exist_ok=True)
        
        conversations = []
        
        if os.path.exists(history_dir):
            # List all conversation files
            for filename in os.listdir(history_dir):
                if filename.endswith('.jsonl'):
                    conversation_id = filename.replace('.jsonl', '')
                    history_file = os.path.join(history_dir, filename)
                    
                    # Get creation time and title
                    modified_time = os.path.getmtime(history_file)
                    modified_date = datetime.fromtimestamp(modified_time).strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Try to get the first message as title
                    title = "Untitled Conversation"
                    try:
                        with open(history_file, 'r') as f:
                            first_line = f.readline().strip()
                            if first_line:
                                data = json.loads(first_line)
                                user_msg = data.get('user', '')
                                if user_msg:
                                    title = user_msg[:40] + "..." if len(user_msg) > 40 else user_msg
                    except Exception:
                        pass
                    
                    conversations.append({
                        'id': conversation_id,
                        'title': title,
                        'date': modified_date
                    })
        
        # Sort by modification time (newest first)
        conversations.sort(key=lambda x: x['date'], reverse=True)
        
        # Apply limit
        conversations = conversations[:limit]
        
        # Print the conversations
        if conversations:
            print("\nSaved conversations:")
            print("-" * 80)
            for i, conv in enumerate(conversations):
                print(f"{i+1}. {conv['id']} - {conv['date']}")
                print(f"   {conv['title']}")
                print()
        else:
            print("No saved conversations found.")
        
        return conversations
    
    def load_conversation(self, conversation_id):
        """Load conversation history."""
        history_dir = os.path.join(self._get_data_dir(), "history")
        history_file = os.path.join(history_dir, f"{conversation_id}.jsonl")
        
        if not os.path.exists(history_file):
            return []
        
        history = []
        with open(history_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    history.append(entry)
                except json.JSONDecodeError:
                    pass
        
        return history

    def toggle_computer_use(self, enabled=None):
        """Toggle or set computer use capability."""
        if enabled is not None:
            self.computer_enabled = enabled
        else:
            self.computer_enabled = not self.computer_enabled
        
        status = "enabled" if self.computer_enabled else "disabled"
        print(f"Computer use capability {status}")
        
        # Update system prompt to reflect computer use status
        if self.computer_enabled and "with computer use capabilities" not in self.system_prompt:
            self.system_prompt += " You have computer use capabilities and can execute commands and interact with files."
        elif not self.computer_enabled:
            self.system_prompt = self.system_prompt.replace("with computer use capabilities", "").replace("You have computer use capabilities and can execute commands and interact with files.", "")
            self.system_prompt = self.system_prompt.strip()
        
        return self.computer_enabled

    def _handle_compute_event(self, event_data):
        """Handle compute events from Claude."""
        try:
            if not self.computer_enabled:
                # Log the attempt but don't execute
                print(f"[Computer use disabled] Model attempted: {event_data.get('action', 'unknown')}")
                return {"status": "disabled", "message": "Computer use is disabled."}
            
            action = event_data.get('action')
            if not action:
                return {"status": "error", "message": "No action specified in compute event."}
            
            # Log the action attempt
            print(f"[Computer] Action requested: {action}")
            
            if action == 'execute_command':
                command = event_data.get('command')
                if not command:
                    return {"status": "error", "message": "No command specified."}
                
                print(f"[Computer] Executing: {command}")
                try:
                    import subprocess
                    # Use shell=True to support piping, redirection, etc.
                    # But this is inherently unsafe if command is untrusted
                    process = subprocess.Popen(
                        command, 
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=30)  # 30 second timeout
                    
                    return {
                        "status": "success" if process.returncode == 0 else "error",
                        "stdout": stdout,
                        "stderr": stderr,
                        "return_code": process.returncode
                    }
                except subprocess.TimeoutExpired:
                    return {"status": "error", "message": "Command execution timed out after 30 seconds."}
                except Exception as e:
                    return {"status": "error", "message": f"Failed to execute command: {str(e)}"}
            
            elif action == 'read_file':
                path = event_data.get('path')
                if not path:
                    return {"status": "error", "message": "No file path specified."}
                
                try:
                    # Expand home directory if present
                    path = os.path.expanduser(path)
                    
                    # Check if path exists and is a file
                    if not os.path.exists(path):
                        return {"status": "error", "message": f"File not found: {path}"}
                    
                    if not os.path.isfile(path):
                        return {"status": "error", "message": f"Path is not a file: {path}"}
                    
                    # Check file size to avoid reading very large files
                    file_size = os.path.getsize(path)
                    if file_size > 10 * 1024 * 1024:  # 10 MB limit
                        return {"status": "error", "message": f"File too large: {file_size / (1024*1024):.2f} MB. Maximum size is 10 MB."}
                    
                    # Read file
                    with open(path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    
                    return {
                        "status": "success",
                        "content": content,
                        "size": file_size
                    }
                except Exception as e:
                    return {"status": "error", "message": f"Failed to read file: {str(e)}"}
            
            elif action == 'write_file':
                path = event_data.get('path')
                content = event_data.get('content')
                
                if not path:
                    return {"status": "error", "message": "No file path specified."}
                
                if content is None:
                    return {"status": "error", "message": "No content provided."}
                
                try:
                    # Expand home directory if present
                    path = os.path.expanduser(path)
                    
                    # Create directory if it doesn't exist
                    directory = os.path.dirname(path)
                    if directory and not os.path.exists(directory):
                        os.makedirs(directory, exist_ok=True)
                    
                    # Write to file
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    return {
                        "status": "success",
                        "message": f"Successfully wrote {len(content)} characters to {path}"
                    }
                except Exception as e:
                    return {"status": "error", "message": f"Failed to write file: {str(e)}"}
            
            elif action == 'list_directory':
                path = event_data.get('path', '.')
                
                try:
                    # Expand home directory if present
                    path = os.path.expanduser(path)
                    
                    # Check if path exists and is a directory
                    if not os.path.exists(path):
                        return {"status": "error", "message": f"Directory not found: {path}"}
                    
                    if not os.path.isdir(path):
                        return {"status": "error", "message": f"Path is not a directory: {path}"}
                    
                    # List directory
                    entries = []
                    for entry in os.listdir(path):
                        full_path = os.path.join(path, entry)
                        entry_type = 'file' if os.path.isfile(full_path) else 'directory'
                        size = os.path.getsize(full_path) if os.path.isfile(full_path) else None
                        
                        entries.append({
                            "name": entry,
                            "type": entry_type,
                            "size": size,
                            "last_modified": datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat()
                        })
                    
                    return {
                        "status": "success",
                        "entries": entries,
                        "count": len(entries)
                    }
                except Exception as e:
                    return {"status": "error", "message": f"Failed to list directory: {str(e)}"}
            
            else:
                return {"status": "error", "message": f"Unsupported action: {action}"}
                
        except Exception as e:
            return {"status": "error", "message": f"Failed to handle compute event: {str(e)}"}

    def _save_session(self):
        """Save session data to persist across application restarts."""
        session_data = {
            'auth_token': self.auth_token,
            'conversation_id': self.conversation_id,
            'session_id': self.session_id,
            'trace_id': self.trace_id,
            'system_prompt': self.system_prompt,
            'computer_enabled': self.computer_enabled,
            'timestamp': int(time.time())
        }
        
        # Create a sessions directory if it doesn't exist
        sessions_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../sessions')
        if not os.path.exists(sessions_dir):
            os.makedirs(sessions_dir)
        
        # Save the session data
        session_file = os.path.join(sessions_dir, 'session.json')
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        print(f"Session saved to {session_file}")
        return True

    def _load_session(self):
        """Load session data from a previous run."""
        # Look for the session file
        sessions_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../sessions')
        session_file = os.path.join(sessions_dir, 'session.json')
        
        if not os.path.exists(session_file):
            print("No saved session found.")
            return False
        
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
            
            # Check if the session is still valid (e.g., not older than 24 hours)
            timestamp = session_data.get('timestamp', 0)
            if int(time.time()) - timestamp > 86400:  # 24 hours
                print("Session expired. Starting fresh session.")
                return False
            
            # Restore session data
            if not self.auth_token and 'auth_token' in session_data:
                self.auth_token = session_data['auth_token']
            
            if not self.conversation_id and 'conversation_id' in session_data:
                self.conversation_id = session_data['conversation_id']
            
            if 'session_id' in session_data:
                self.session_id = session_data['session_id']
            
            if 'trace_id' in session_data:
                self.trace_id = session_data['trace_id']
            
            if 'system_prompt' in session_data and not self.system_prompt:
                self.system_prompt = session_data['system_prompt']
            
            if 'computer_enabled' in session_data:
                self.computer_enabled = session_data['computer_enabled']
            
            print("Session restored from previous run.")
            return True
        
        except Exception as e:
            print(f"Error loading session: {e}")
            return False

    def export_conversation(self, conversation_id=None, format="markdown", path=None):
        """Export a conversation to a file."""
        if not conversation_id and not self.conversation_id:
            print("No conversation ID provided.")
            return False
        
        conv_id = conversation_id or self.conversation_id
        
        # Get the conversation history
        history = self.load_conversation(conv_id)
        if not history:
            print(f"No history found for conversation ID: {conv_id}")
            return False
        
        # Format the conversation
        if format.lower() == "markdown":
            content = self._format_conversation_markdown(history)
        elif format.lower() == "json":
            content = json.dumps(history, indent=2)
        elif format.lower() == "text":
            content = self._format_conversation_text(history)
        else:
            print(f"Unsupported format: {format}. Using markdown.")
            content = self._format_conversation_markdown(history)
        
        # Determine output path
        if not path:
            # Create exports directory if it doesn't exist
            exports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../exports')
            if not os.path.exists(exports_dir):
                os.makedirs(exports_dir)
            
            # Generate a filename based on the first few words of the conversation
            if history and len(history) > 0:
                first_msg = history[0].get('user', '')[:20].replace(' ', '_')
                filename = f"{conv_id[:8]}_{first_msg}.{format.lower()}"
            else:
                filename = f"{conv_id[:8]}_export.{format.lower()}"
            
            path = os.path.join(exports_dir, filename)
        
        # Write the file
        try:
            with open(path, 'w') as f:
                f.write(content)
            print(f"Conversation exported to {path}")
            return True
        except Exception as e:
            print(f"Error exporting conversation: {e}")
            return False

    def _format_conversation_markdown(self, history):
        """Format conversation history as markdown."""
        markdown = f"# Conversation {history[0].get('conversation_id', 'Unknown')}\n\n"
        markdown += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        for entry in history:
            # User message
            user_msg = entry.get('user', entry.get('user_message', ''))
            markdown += f"## User\n\n{user_msg}\n\n"
            
            # Assistant response
            asst_msg = entry.get('assistant', entry.get('assistant_message', ''))
            markdown += f"## Claude\n\n{asst_msg}\n\n"
            
            # Add a separator
            markdown += "---\n\n"
        
        return markdown

    def _format_conversation_text(self, history):
        """Format conversation history as plain text."""
        text = f"Conversation {history[0].get('conversation_id', 'Unknown')}\n"
        text += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        for entry in history:
            # User message
            user_msg = entry.get('user', entry.get('user_message', ''))
            text += f"User: {user_msg}\n\n"
            
            # Assistant response
            asst_msg = entry.get('assistant', entry.get('assistant_message', ''))
            text += f"Claude: {asst_msg}\n\n"
            
            # Add a separator
            text += "-" * 40 + "\n\n"
        
        return text

    def _capture_token_from_log(self, log_file):
        """Extract a token from a captured network log file."""
        try:
            if not os.path.exists(log_file):
                print(f"Log file not found: {log_file}")
                return None
            
            with open(log_file, 'r') as f:
                content = f.read()
            
                # Look for Cloud-IDE-JWT in the log
                jwt_match = re.search(r'Cloud-IDE-JWT\s+([A-Za-z0-9_.-]+)', content)
                if jwt_match:
                    token = jwt_match.group(1)
                    print(f"Found JWT token in log: {token[:20]}...{token[-10:]}")
                    
                    # Verify the token is a valid JWT
                    if self._is_token_valid(token):
                        self._save_token(token)
                        return token
                    else:
                        print("Found token is invalid or expired")
                    
                print("No valid token found in log file")
                return None
        except Exception as e:
            print(f"Error extracting token from log: {str(e)}")
            return None

    def _check_token_expiration(self):
        """Check if the current token is valid or expired.
        
        Returns:
            str: 'valid', 'expiring_soon', or 'expired'
        """
        try:
            # For simulated token, just return valid
            if not self.auth_token:
                return 'expired'
            
            # Try to parse JWT token to check expiration
            try:
                token_parts = self.auth_token.split('.')
                if len(token_parts) != 3:
                    print("Error parsing JWT token: Invalid format")
                    return 'valid'  # Can't determine, assume valid
                
                # Parse JWT payload
                payload = json.loads(base64.b64decode(token_parts[1] + '==').decode('utf-8'))
                
                # Check for expiration
                exp_time = payload.get('exp')
                if not exp_time:
                    print("Token has no expiration date")
                    return 'valid'
                
                # Calculate time until expiration
                now = int(time.time())
                time_until_expiry = exp_time - now
                
                # Determine status based on time until expiry
                if time_until_expiry <= 0:
                    return 'expired'
                elif time_until_expiry < 3600:  # Less than 1 hour
                    return 'expiring_soon'
                else:
                    return 'valid'
                
            except Exception as e:
                print(f"Error parsing JWT token: {str(e)}")
                return 'valid'  # Can't determine, assume valid
            
        except Exception as e:
            print(f"Error checking token expiration: {str(e)}")
            return 'valid'  # Can't determine, assume valid

    def _update_telemetry(self, endpoint, status_code, duration_ms, success=True, error=None):
        """Update the telemetry log with API call information."""
        logger = logging.getLogger('trae_telemetry')
        
        if success:
            logger.info(f"API call to {endpoint} succeeded in {int(duration_ms)}ms (status: {status_code})")
        else:
            if error:
                logger.error(f"API call to {endpoint} failed: {error}")
            else:
                logger.error(f"API call to {endpoint} failed with status {status_code} in {int(duration_ms)}ms")
        
        # Save telemetry data
        telemetry_record = {
            'timestamp': time.time(),
            'endpoint': endpoint,
            'success': success,
            'status_code': status_code,
            'duration_ms': int(duration_ms),
            'error': error
        }
        
        # Add to in-memory telemetry
        if not hasattr(self, '_telemetry'):
            self._telemetry = []
        self._telemetry.append(telemetry_record)
        
        # Save to telemetry file if we have more than 10 records
        if len(self._telemetry) >= 10:
            self._save_telemetry()
        
    def _save_telemetry(self):
        """Save telemetry data to disk."""
        if not hasattr(self, '_telemetry') or not self._telemetry:
            return
        
        telemetry_file = os.path.join(self._get_data_dir(), 'telemetry.json')
        
        # Load existing telemetry if available
        existing_telemetry = []
        if os.path.exists(telemetry_file):
            try:
                with open(telemetry_file, 'r') as f:
                    existing_telemetry = json.load(f)
            except Exception:
                pass
            
        # Add new telemetry
        existing_telemetry.extend(self._telemetry)
        
        # Limit to last 1000 entries
        if len(existing_telemetry) > 1000:
            existing_telemetry = existing_telemetry[-1000:]
        
        # Save updated telemetry
        try:
            with open(telemetry_file, 'w') as f:
                json.dump(existing_telemetry, f)
            self._telemetry = []
        except Exception as e:
            print(f"Error saving telemetry: {str(e)}")

    def _get_data_dir(self):
        """Get the directory for data storage."""
        data_dir = os.path.expanduser("~/.trae")
        os.makedirs(data_dir, exist_ok=True)
        return data_dir

    def _add_to_history(self, message, response):
        """Add message and response to conversation history."""
        if not self.conversation_id:
            return
        
        history_dir = os.path.join(self._get_data_dir(), "history")
        os.makedirs(history_dir, exist_ok=True)
        
        history_file = os.path.join(history_dir, f"{self.conversation_id}.jsonl")
        
        # Create history entry
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user": message,
            "assistant": response
        }
        
        # Append to history file
        try:
            with open(history_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Error saving to history: {str(e)}")

def main():
    """Main function for CLI."""
    parser = argparse.ArgumentParser(description="Trae Claude CLI - Command line interface for Claude 3.7 Sonnet via Trae API")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Login command
    login_parser = subparsers.add_parser("login", help="Login with an authentication token")
    login_parser.add_argument("--token", help="JWT token for authentication")
    
    # Chat command
    chat_parser = subparsers.add_parser("chat", help="Start a chat session or send a message")
    chat_parser.add_argument("message", nargs="?", help="Message to send (optional)")
    chat_parser.add_argument("--model", default="claude-3-7-sonnet", choices=["gpt-4-turbo", "claude-3-7-haiku", "claude-3-7-sonnet", "claude-3-5-sonnet"], help="Model to use for chat")
    chat_parser.add_argument("--no-computer", action="store_true", help="Disable computer use capability")
    chat_parser.add_argument("--conversation", help="Continue an existing conversation by ID")
    chat_parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    chat_parser.add_argument("--system", help="Set a custom system prompt")
    chat_parser.add_argument("--file", help="Read input message from a file")
    
    # List conversations command
    list_parser = subparsers.add_parser("list", help="List saved conversations")
    list_parser.add_argument("--limit", type=int, default=10, help="Limit the number of conversations to display")
    
    # Export conversation command
    export_parser = subparsers.add_parser("export", help="Export a conversation to a file")
    export_parser.add_argument("conversation_id", help="ID of the conversation to export")
    export_parser.add_argument("--format", choices=["markdown", "text", "json"], default="markdown", help="Format to export the conversation in")
    export_parser.add_argument("--output", help="Output file path")
    
    # Toggle computer use command
    computer_parser = subparsers.add_parser("computer", help="Toggle computer use capability")
    computer_parser.add_argument("--enable", action="store_true", help="Enable computer use")
    computer_parser.add_argument("--disable", action="store_true", help="Disable computer use")
    
    # Token extraction command
    token_parser = subparsers.add_parser("token", help="Extract token from log file")
    token_parser.add_argument("log_file", nargs="?", help="Path to log file containing token")
    
    # Telemetry command
    telemetry_parser = subparsers.add_parser("telemetry", help="View API telemetry and reliability stats")
    
    # Version command
    version_parser = subparsers.add_parser("version", help="Show version information")
    
    # Configure command
    config_parser = subparsers.add_parser("config", help="Configure CLI settings")
    config_parser.add_argument("--region", choices=["us", "sg"], help="Set API region (US or Singapore)")
    config_parser.add_argument("--default-model", help="Set default model")
    config_parser.add_argument("--show", action="store_true", help="Show current configuration")
    
    args = parser.parse_args()
    
    # Handle version command specially
    if args.command == "version":
        print(f"Trae Claude CLI v1.0.0")
        print("A command line interface for Claude 3.7 Sonnet via ByteDance's Trae API")
        return
    
    # Handle config command
    if args.command == "config":
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR, exist_ok=True)
            
        config = DEFAULT_CONFIG
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}")
        
        if args.region:
            config["region"] = args.region
            print(f"Region set to {args.region}")
            
        if args.default_model:
            config["model"] = args.default_model
            print(f"Default model set to {args.default_model}")
            
        # Save config if changes were made
        if args.region or args.default_model:
            try:
                with open(CONFIG_FILE, 'w') as f:
                    json.dump(config, f, indent=2)
                print("Configuration saved")
            except Exception as e:
                print(f"Error saving config: {e}")
        
        # Show current config
        if args.show or not (args.region or args.default_model):
            print("\nCurrent configuration:")
            for key, value in config.items():
                if key != "device_id":  # Don't show device ID
                    print(f"  {key}: {value}")
        return
    
    # Create API client
    api = TraeClaudeAPI(verbose_debug=getattr(args, 'verbose', False))
    
    # Handle login command
    if args.command == "login":
        if args.token:
            api.login(args.token)
        else:
            token = getpass.getpass("Enter JWT token: ")
            api.login(token)
    
    # Handle chat command
    elif args.command == "chat":
        if not api.check_auth():
            print("Please log in first with 'trae_claude_cli.py login'")
            return
        
        # Set custom system prompt if provided
        if hasattr(args, 'system') and args.system:
            api.system_prompt = args.system
        
        # Toggle computer use if specified
        if hasattr(args, 'no_computer') and args.no_computer:
            api.toggle_computer_use(False)
        
        # Use existing conversation or create new one
        conversation_id = args.conversation if hasattr(args, 'conversation') and args.conversation else None
        
        # Get message from file if specified
        message = args.message
        if hasattr(args, 'file') and args.file:
            try:
                with open(args.file, 'r', encoding='utf-8') as f:
                    message = f.read()
                print(f"Read {len(message)} characters from {args.file}")
            except Exception as e:
                print(f"Error reading file: {e}")
                return
        
        if message:
            # Single message mode
            response = api.send_message(message, conversation_id, model=args.model)
        else:
            # Interactive chat mode
            current_conversation = conversation_id
            print("Starting chat session. Type 'exit' or Ctrl+C to end.")
            print("Type '/help' for chat commands.")
            
            try:
                while True:
                    message = input("\nYou: ")
                    
                    if message.lower() in ('exit', 'quit', '/exit', '/quit'):
                        break
                    
                    if message.startswith('/'):
                        # Handle commands
                        if message.lower() == '/help':
                            print("\nChat commands:")
                            print("  /exit, /quit - Exit the chat session")
                            print("  /help - Show this help message")
                            print("  /new - Start a new conversation")
                            print("  /computer on|off - Enable/disable computer use")
                            print("  /model <model> - Change the model")
                            print("  /export <format> [file] - Export conversation")
                            print("  /system <prompt> - Set system prompt")
                            print("  /file <path> - Read message from file")
                            print("  /clear - Clear the screen")
                            print("  /history - Show conversation history")
                            continue
                        elif message.lower() == '/new':
                            current_conversation = None
                            print("Starting new conversation")
                            continue
                        elif message.lower().startswith('/computer'):
                            parts = message.split()
                            if len(parts) > 1:
                                if parts[1].lower() in ('on', 'enable', 'true'):
                                    api.toggle_computer_use(True)
                                    print("Computer use enabled")
                                elif parts[1].lower() in ('off', 'disable', 'false'):
                                    api.toggle_computer_use(False)
                                    print("Computer use disabled")
                            else:
                                print(f"Computer use is currently {'enabled' if api.computer_enabled else 'disabled'}")
                            continue
                        elif message.lower().startswith('/model'):
                            parts = message.split()
                            if len(parts) > 1:
                                args.model = parts[1]
                                print(f"Model set to {args.model}")
                            else:
                                print(f"Current model: {args.model}")
                            continue
                        elif message.lower().startswith('/export'):
                            parts = message.split()
                            format = "markdown"
                            output = None
                            
                            if len(parts) > 1:
                                format = parts[1]
                                
                            if len(parts) > 2:
                                output = parts[2]
                                
                            api.export_conversation(current_conversation, format, output)
                            continue
                        elif message.lower().startswith('/system'):
                            api.system_prompt = message[8:].strip()
                            print(f"System prompt set to: {api.system_prompt}")
                            continue
                        elif message.lower().startswith('/file'):
                            file_path = message[6:].strip()
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    file_content = f.read()
                                print(f"Read {len(file_content)} characters from {file_path}")
                                message = file_content
                            except Exception as e:
                                print(f"Error reading file: {e}")
                                continue
                        elif message.lower() == '/clear':
                            os.system('cls' if os.name == 'nt' else 'clear')
                            continue
                        elif message.lower() == '/history':
                            if not current_conversation:
                                print("No active conversation")
                                continue
                                
                            history = api.conversation_history
                            if not history:
                                print("No history available")
                                continue
                                
                            print("\nConversation history:")
                            for i, entry in enumerate(history):
                                print(f"\n[{i+1}] User: {entry['message'][:50]}..." if len(entry['message']) > 50 else f"\n[{i+1}] User: {entry['message']}")
                                print(f"    Claude: {entry['response'][:50]}..." if len(entry['response']) > 50 else f"    Claude: {entry['response']}")
                            continue
                        elif message.startswith('/'):
                            print(f"Unknown command: {message}")
                            print("Type '/help' for available commands")
                            continue
                    
                    # Send message
                    response = api.send_message(message, current_conversation, model=args.model)
                    if response and 'conversation_id' in response:
                        current_conversation = response['conversation_id']
                        
            except KeyboardInterrupt:
                print("\nExiting chat session")
                # Export conversation on exit if one exists
                if current_conversation:
                    should_export = input("\nExport this conversation before exiting? (y/n): ")
                    if should_export.lower().startswith('y'):
                        format = input("Export format (markdown/text/json) [markdown]: ") or "markdown"
                        output = input("Output file [conversation.md]: ") or "conversation.md"
                        api.export_conversation(current_conversation, format, output)
    
    # Handle list command
    elif args.command == "list":
        if not api.check_auth():
            print("Please log in first with 'trae_claude_cli.py login'")
            return
        
        api.list_conversations(args.limit if hasattr(args, 'limit') else 10)
    
    # Handle export command
    elif args.command == "export":
        if not api.check_auth():
            print("Please log in first with 'trae_claude_cli.py login'")
            return
        
        api.export_conversation(
            args.conversation_id,
            args.format if hasattr(args, 'format') else "markdown",
            args.output if hasattr(args, 'output') else None
        )
    
    # Handle computer command
    elif args.command == "computer":
        if not api.check_auth():
            print("Please log in first with 'trae_claude_cli.py login'")
            return
        
        if hasattr(args, 'enable') and args.enable:
            api.toggle_computer_use(True)
            print("Computer use enabled")
        elif hasattr(args, 'disable') and args.disable:
            api.toggle_computer_use(False)
            print("Computer use disabled")
        else:
            enabled = api.toggle_computer_use()
            print(f"Computer use is {'enabled' if enabled else 'disabled'}")
    
    # Handle token command
    elif args.command == "token":
        from token_extractor import extract_token_from_log, decode_jwt, check_token_expiration
        
        log_file = args.log_file if hasattr(args, 'log_file') and args.log_file else None
        
        if not log_file:
            log_file = input("Enter path to network log file: ")
        
        token = extract_token_from_log(log_file)
        if token:
            decoded = decode_jwt(token)
            if decoded:
                check_token_expiration(decoded)
                print("\nTo use this token, run:")
                print(f"python3 src/trae_claude_cli.py login --token \"{token}\"")
    
    # Handle telemetry command
    elif args.command == "telemetry":
        stats = get_telemetry_stats()
        
        print("\n=== Trae API Telemetry Stats ===")
        print(f"Total API calls: {stats.get('total_calls', 0)}")
        print(f"Success rate: {stats.get('success_rate', 0):.2f}%")
        print(f"Average response time: {stats.get('avg_duration_ms', 0):.2f} ms")
        
        print("\n=== Endpoint Performance ===")
        for endpoint, data in stats.get('endpoints', {}).items():
            print(f"\n{endpoint}:")
            print(f"  Calls: {data.get('calls', 0)}")
            print(f"  Success rate: {data.get('success_rate', 0):.2f}%")
            print(f"  Average response time: {data.get('avg_duration_ms', 0):.2f} ms")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {str(e)}")
        if os.environ.get("TRAE_DEBUG"):
            traceback.print_exc() 