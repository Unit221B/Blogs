#!/usr/bin/env python3
"""
Sonnet 3.7 API Traffic Capture Script

This script intercepts and analyzes HTTP/S traffic related to Sonnet 3.7 API calls
using mitmproxy. It logs requests and responses to files for later analysis,
extracts authentication information, and documents tool use patterns.

Usage:
    mitmdump -p 8080 --set flow_detail=3 -s src/sonnet_capture.py
"""

import json
import os
import datetime
import re
from mitmproxy import http
from mitmproxy import ctx

# Create captures directory if it doesn't exist
CAPTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)

# File to store captured API endpoints
ENDPOINTS_FILE = os.path.join(CAPTURES_DIR, "endpoints.txt")
# File to store auth tokens
AUTH_TOKENS_FILE = os.path.join(CAPTURES_DIR, "auth_tokens.txt")
# File to store tool use patterns
TOOL_USE_FILE = os.path.join(CAPTURES_DIR, "tool_use_patterns.txt")
# Folder for detailed request/response data
DETAILS_DIR = os.path.join(CAPTURES_DIR, "details")
os.makedirs(DETAILS_DIR, exist_ok=True)

# Domains and patterns likely to be associated with Sonnet 3.7 API
SONNET_API_PATTERNS = [
    "anthropic",
    "claude",
    "sonnet",
    "claude-3.7",
    "claude-3.7-sonnet",
    "claude-3-sonnet",
    "claude3.7",
    "api.claude.ai",
    "cursor.sh",
    "cursor.so",
    "trae",
    "bytedance",
    "claude/v1/messages",  # Common Anthropic API endpoint
    "claude/messages",
    "completion"
]

def is_sonnet_api_request(flow):
    """Check if a request is likely a Sonnet 3.7 API call."""
    host = flow.request.host.lower()
    url = flow.request.url.lower()
    
    # Check if the host/URL contains any of our target patterns
    if any(pattern in host or pattern in url for pattern in SONNET_API_PATTERNS):
        return True
    
    # Check the request body for Sonnet 3.7 related content
    if flow.request.content:
        try:
            body = json.loads(flow.request.content)
            body_str = json.dumps(body).lower()
            if any(pattern in body_str for pattern in SONNET_API_PATTERNS):
                return True
            
            # Check for model specification in the body
            if isinstance(body, dict) and "model" in body:
                model = body.get("model", "").lower()
                if "claude" in model or "sonnet" in model or "claude-3.7" in model:
                    return True
        except:
            pass
    
    # Check for WebSocket connections that might be used for the chat interface
    if "Upgrade" in flow.request.headers and flow.request.headers["Upgrade"].lower() == "websocket":
        ctx.log.info(f"WebSocket connection detected: {flow.request.url}")
        return True
    
    return False

def extract_auth_info(flow):
    """Extract authentication information from the request."""
    auth_info = {}
    
    # Check for Authorization header
    if "Authorization" in flow.request.headers:
        auth_info["Authorization"] = flow.request.headers["Authorization"]
        
        # Check specifically for Bearer token format used by Anthropic
        auth_header = flow.request.headers["Authorization"]
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
            auth_info["Bearer_Token"] = token
            
            # Check if it's an Anthropic API key
            if token.startswith("sk-ant-"):
                auth_info["Anthropic_API_Key"] = token
                ctx.log.info("Anthropic API key detected!")
    
    # Check for X-API-Key header (common in many APIs)
    if "X-API-Key" in flow.request.headers:
        auth_info["X-API-Key"] = flow.request.headers["X-API-Key"]
    
    # Check for specific Anthropic headers
    if "x-api-key" in flow.request.headers:
        auth_info["x-api-key"] = flow.request.headers["x-api-key"]
        
    if "anthropic-version" in flow.request.headers:
        auth_info["anthropic-version"] = flow.request.headers["anthropic-version"]
    
    # Check for common token headers
    for header in flow.request.headers:
        if "token" in header.lower() or "jwt" in header.lower() or "auth" in header.lower() or "api-key" in header.lower():
            auth_info[header] = flow.request.headers[header]
    
    # Check for cookies that might contain auth info
    for cookie_name, cookie_value in flow.request.cookies.items():
        if "token" in cookie_name.lower() or "sess" in cookie_name.lower() or "auth" in cookie_name.lower():
            auth_info[f"Cookie:{cookie_name}"] = cookie_value
    
    # Check request body for auth fields
    if flow.request.content:
        try:
            body = json.loads(flow.request.content)
            if isinstance(body, dict):
                # Check for API keys in the request body
                for key in body:
                    if "key" in key.lower() or "token" in key.lower() or "auth" in key.lower():
                        auth_info[f"Body:{key}"] = body[key]
                
                # Check for Anthropic model specification
                if "model" in body:
                    auth_info["Model"] = body["model"]
        except:
            pass
    
    # Look for JWT tokens in headers or body
    jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    
    # Check headers for JWT
    for header, value in flow.request.headers.items():
        jwt_matches = re.findall(jwt_pattern, value)
        if jwt_matches:
            auth_info[f"JWT_in_header_{header}"] = jwt_matches[0]
    
    # Check body for JWT
    if flow.request.content:
        body_str = flow.request.content.decode('utf-8', errors='ignore')
        jwt_matches = re.findall(jwt_pattern, body_str)
        if jwt_matches:
            auth_info["JWT_in_body"] = jwt_matches[0]
    
    return auth_info

def extract_tool_use_patterns(flow):
    """Extract tool use patterns from the request and response."""
    tool_patterns = {}
    
    # Check request body for tool use formatting
    if flow.request.content:
        try:
            body = json.loads(flow.request.content)
            body_str = json.dumps(body)
            
            # Look for tool definitions in system message or elsewhere
            if "tools" in body_str or "tool_use" in body_str or "function" in body_str:
                tool_patterns["request_contains_tools"] = True
                
                # Extract tool definitions if present
                if isinstance(body, dict):
                    if "tools" in body:
                        tool_patterns["tool_definitions"] = body["tools"]
                    
                    # Check for system message with tool instructions
                    if "system" in body and isinstance(body["system"], str):
                        system = body["system"]
                        if "tool" in system or "function" in system:
                            tool_patterns["system_contains_tools"] = True
        except:
            pass
    
    # Check response body for tool use patterns
    if flow.response and flow.response.content:
        try:
            body = json.loads(flow.response.content)
            body_str = json.dumps(body)
            
            # Check for tool use in response
            if "tool" in body_str or "function" in body_str or "<tool>" in body_str:
                tool_patterns["response_contains_tools"] = True
                
                # Try to extract tool use format
                if isinstance(body, dict) and "content" in body:
                    content = body["content"]
                    # Look for tool invocation patterns
                    tool_matches = re.findall(r'<tool>(.*?)</tool>', str(content), re.DOTALL)
                    if tool_matches:
                        tool_patterns["tool_invocation_format"] = tool_matches[0]
        except:
            pass
    
    return tool_patterns

def save_auth_info(auth_info, flow):
    """Save authentication information to file."""
    if not auth_info:
        return
    
    timestamp = datetime.datetime.now().isoformat()
    url = flow.request.url
    
    with open(AUTH_TOKENS_FILE, "a") as f:
        f.write(f"--- Auth Info Captured at {timestamp} from {url} ---\n")
        for key, value in auth_info.items():
            f.write(f"{key}: {value}\n")
        f.write("\n")

def save_tool_use_patterns(tool_patterns, flow):
    """Save tool use patterns to file."""
    if not tool_patterns:
        return
    
    timestamp = datetime.datetime.now().isoformat()
    url = flow.request.url
    
    with open(TOOL_USE_FILE, "a") as f:
        f.write(f"--- Tool Use Pattern Captured at {timestamp} from {url} ---\n")
        for key, value in tool_patterns.items():
            if isinstance(value, (dict, list)):
                f.write(f"{key}:\n{json.dumps(value, indent=2)}\n")
            else:
                f.write(f"{key}: {value}\n")
        f.write("\n")

def save_endpoint(flow):
    """Save endpoint information to file."""
    timestamp = datetime.datetime.now().isoformat()
    method = flow.request.method
    url = flow.request.url
    status_code = flow.response.status_code if flow.response else "N/A"
    
    with open(ENDPOINTS_FILE, "a") as f:
        f.write(f"{timestamp} | {method} | {status_code} | {url}\n")

def save_request_response_details(flow):
    """Save detailed request and response information to files."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    flow_id = f"{timestamp}_{flow.request.host}_{flow.request.path.replace('/', '_')[:50]}"
    
    # Save request details
    request_file = os.path.join(DETAILS_DIR, f"{flow_id}_request.txt")
    with open(request_file, "w") as f:
        f.write(f"URL: {flow.request.url}\n")
        f.write(f"Method: {flow.request.method}\n")
        f.write("Headers:\n")
        for key, value in flow.request.headers.items():
            f.write(f"  {key}: {value}\n")
        
        f.write("\nBody:\n")
        if flow.request.content:
            try:
                # Try to format JSON for readability
                body = json.loads(flow.request.content)
                f.write(json.dumps(body, indent=2))
            except:
                # If not JSON, write as is
                f.write(str(flow.request.content))
    
    # Save response details if available
    if flow.response:
        response_file = os.path.join(DETAILS_DIR, f"{flow_id}_response.txt")
        with open(response_file, "w") as f:
            f.write(f"Status Code: {flow.response.status_code}\n")
            f.write("Headers:\n")
            for key, value in flow.response.headers.items():
                f.write(f"  {key}: {value}\n")
            
            f.write("\nBody:\n")
            if flow.response.content:
                try:
                    # Try to format JSON for readability
                    body = json.loads(flow.response.content)
                    f.write(json.dumps(body, indent=2))
                except:
                    # If not JSON, write as is (truncate if very large)
                    content = str(flow.response.content)
                    if len(content) > 10000:
                        f.write(f"{content[:10000]}... [truncated]")
                    else:
                        f.write(content)

def request(flow):
    """Process requests before they're sent to the server."""
    ctx.log.info(f"Request: {flow.request.method} {flow.request.url}")
    
    # Only process requests that are likely Sonnet 3.7 API calls
    if not is_sonnet_api_request(flow):
        return
    
    ctx.log.info(f"Identified potential Sonnet API call: {flow.request.url}")
    
    # Extract and save authentication information
    auth_info = extract_auth_info(flow)
    if auth_info:
        ctx.log.info(f"Authentication information found in request to {flow.request.url}")
        save_auth_info(auth_info, flow)

def response(flow):
    """Process responses from the server."""
    # Only process responses that are likely Sonnet 3.7 API calls
    if not is_sonnet_api_request(flow):
        return
    
    ctx.log.info(f"Response for Sonnet API call: {flow.request.method} {flow.request.url} {flow.response.status_code}")
    
    # Save endpoint information
    save_endpoint(flow)
    
    # Extract and save tool use patterns
    tool_patterns = extract_tool_use_patterns(flow)
    if tool_patterns:
        ctx.log.info(f"Tool use pattern found in {flow.request.url}")
        save_tool_use_patterns(tool_patterns, flow)
    
    # Save detailed request and response information
    save_request_response_details(flow)

def websocket_message(flow):
    """Handle WebSocket messages."""
    # Check if the connection might be related to Sonnet 3.7
    if not is_sonnet_api_request(flow):
        return
    
    # Process the WebSocket messages
    for message in flow.websocket.messages:
        timestamp = datetime.datetime.now().isoformat()
        is_from_client = message.from_client
        direction = "Client to Server" if is_from_client else "Server to Client"
        
        # Save the WebSocket message
        websocket_dir = os.path.join(CAPTURES_DIR, "websockets")
        os.makedirs(websocket_dir, exist_ok=True)
        
        message_file = os.path.join(websocket_dir, f"{timestamp}_{flow.request.host}_{'outgoing' if is_from_client else 'incoming'}.txt")
        with open(message_file, "w") as f:
            f.write(f"URL: {flow.request.url}\n")
            f.write(f"Direction: {direction}\n")
            f.write(f"Timestamp: {timestamp}\n\n")
            
            # Try to parse as JSON for readability
            try:
                content = json.loads(message.content)
                f.write(json.dumps(content, indent=2))
                
                # Check for Sonnet-related content
                content_str = json.dumps(content).lower()
                if any(pattern in content_str for pattern in SONNET_API_PATTERNS):
                    ctx.log.info(f"Sonnet-related WebSocket message found: {flow.request.url}")
                
                # Check for tool use patterns
                if "tools" in content_str or "tool_use" in content_str or "function" in content_str:
                    tool_patterns = {"websocket_contains_tools": True}
                    save_tool_use_patterns(tool_patterns, flow)
            except:
                # If not JSON, write as is
                f.write(str(message.content))
        
        ctx.log.info(f"WebSocket message captured: {direction} for {flow.request.url}")

def load(loader):
    """Script loading event."""
    ctx.log.info("Sonnet 3.7 API traffic capture script loaded")
    ctx.log.info(f"Saving captures to {CAPTURES_DIR}")
    
    # Initialize or clear the endpoints file
    with open(ENDPOINTS_FILE, "w") as f:
        f.write("Timestamp | Method | Status | URL\n")
        f.write("-" * 100 + "\n")
    
    # Initialize tool use patterns file
    with open(TOOL_USE_FILE, "w") as f:
        f.write("# Sonnet 3.7 Tool Use Patterns\n\n")
    
    # Create WebSocket directory
    websocket_dir = os.path.join(CAPTURES_DIR, "websockets")
    os.makedirs(websocket_dir, exist_ok=True)

def done():
    """Script unload event."""
    ctx.log.info("Sonnet 3.7 API traffic capture script unloaded")
    ctx.log.info(f"Captured data saved to {CAPTURES_DIR}") 