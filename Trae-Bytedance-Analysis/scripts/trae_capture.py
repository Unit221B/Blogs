#!/usr/bin/env python3
import os
import json
import base64
import gzip
from datetime import datetime
from mitmproxy import ctx
from mitmproxy.script import concurrent

class TraeTrafficCapture:
    def __init__(self):
        self.traffic_dir = "trae_traffic"
        self.ensure_traffic_dir()
        
    def ensure_traffic_dir(self):
        if not os.path.exists(self.traffic_dir):
            os.makedirs(self.traffic_dir)
            
    def decode_content(self, content, content_type, content_encoding=None):
        if not content:
            return None
            
        try:
            # Handle binary content
            if isinstance(content, bytes):
                # First handle compression if present
                if content_encoding == "gzip":
                    try:
                        content = gzip.decompress(content)
                    except Exception as e:
                        ctx.log.error(f"Error decompressing gzip content: {str(e)}")
                        return None
                
                # Try to decode based on content type
                if "application/proto" in content_type or "application/json" in content_type:
                    # For Protocol Buffers or JSON, try to decode as UTF-8 first
                    try:
                        return content.decode('utf-8')
                    except UnicodeDecodeError:
                        # If UTF-8 fails, return base64 encoded version
                        return base64.b64encode(content).decode('utf-8')
                else:
                    # For other content types, try UTF-8 first
                    try:
                        return content.decode('utf-8')
                    except UnicodeDecodeError:
                        # If UTF-8 fails, return base64 encoded version
                        return base64.b64encode(content).decode('utf-8')
            return content
        except Exception as e:
            ctx.log.error(f"Error decoding content: {str(e)}")
            return None
            
    def save_request(self, flow):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        content_type = flow.request.headers.get("content-type", "")
        content_encoding = flow.request.headers.get("content-encoding", "")
        
        request_data = {
            "timestamp": timestamp,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "content": self.decode_content(flow.request.content, content_type, content_encoding),
            "host": flow.request.host,
            "scheme": flow.request.scheme,
            "port": flow.request.port,
            "content_type": content_type,
            "content_encoding": content_encoding
        }
        
        # Log request details
        ctx.log.info(f"Capturing request to: {flow.request.pretty_url}")
        ctx.log.info(f"Content-Type: {content_type}")
        ctx.log.info(f"Content-Encoding: {content_encoding}")
        if request_data["content"]:
            ctx.log.info(f"Content length: {len(str(request_data['content']))}")
        
        filename = f"{self.traffic_dir}/request_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(request_data, f, indent=2)
            
    def save_response(self, flow):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        content_type = flow.response.headers.get("content-type", "")
        content_encoding = flow.response.headers.get("content-encoding", "")
        
        response_data = {
            "timestamp": timestamp,
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "content": self.decode_content(flow.response.content, content_type, content_encoding),
            "content_type": content_type,
            "content_encoding": content_encoding
        }
        
        # Log response details
        ctx.log.info(f"Capturing response from: {flow.request.pretty_url}")
        ctx.log.info(f"Status code: {flow.response.status_code}")
        ctx.log.info(f"Content-Type: {content_type}")
        ctx.log.info(f"Content-Encoding: {content_encoding}")
        if response_data["content"]:
            ctx.log.info(f"Content length: {len(str(response_data['content']))}")
        
        filename = f"{self.traffic_dir}/response_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(response_data, f, indent=2)

capture = TraeTrafficCapture()

@concurrent
def request(flow):
    # Capture all traffic - we'll filter manually if needed
    ctx.log.info(f"Capturing request to: {flow.request.pretty_url}")
    capture.save_request(flow)

@concurrent
def response(flow):
    # Capture all traffic - we'll filter manually if needed
    ctx.log.info(f"Capturing response from: {flow.request.pretty_url}")
    capture.save_response(flow) 