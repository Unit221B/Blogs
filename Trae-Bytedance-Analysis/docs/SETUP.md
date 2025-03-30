# Sonnet 3.7 API Capture Setup

This document outlines the setup process for capturing and analyzing Sonnet 3.7 API traffic.

## Prerequisites

- Python 3.8 or higher
- mitmproxy 9.0.0 or higher
- A device with access to Sonnet 3.7 API (web browser or application)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/bytedance-re.git
   cd bytedance-re
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Setting Up MITM Proxy

### Step 1: Install mitmproxy certificates

1. Start the proxy server:
   ```bash
   mitmdump -p 8080
   ```

2. Configure your browser to use the proxy:
   - Set HTTP/HTTPS proxy to: `127.0.0.1:8080`

3. Visit [mitm.it](http://mitm.it) in your browser and follow the instructions to install the certificate:
   - For macOS: Download the certificate and double-click it. Open Keychain Access and set it to "Always Trust" in the "System" keychain.
   - For Windows: Download the certificate and install it into the "Trusted Root Certificate Authorities" store.
   - For iOS/Android: Follow the device-specific instructions on the mitm.it page.

### Step 2: Running the Sonnet API capture script

Start the proxy with our custom script:

```bash
mitmdump -p 8080 --set flow_detail=3 -s src/sonnet_capture.py
```

## Capturing Sonnet 3.7 API Traffic

1. With the proxy running, open a web browser or application that uses Sonnet 3.7.

2. Perform typical interactions:
   - Start a conversation
   - Send messages
   - Try to use tools or functions
   - Test system message modifications

3. The script will automatically save captured traffic to the `captures/` directory:
   - `endpoints.txt`: List of all captured API endpoints
   - `auth_tokens.txt`: Extracted authentication information
   - `tool_use_patterns.txt`: Identified tool use patterns
   - `details/`: Detailed request and response data

## Analyzing the Captured Data

After capturing traffic, analyze the data:

1. Review `endpoints.txt` to identify the API structure
2. Check `auth_tokens.txt` for authentication methods
3. Examine `tool_use_patterns.txt` for tool use implementation details
4. Look through the detailed request/response files in `details/` directory

## Troubleshooting

### Certificate Issues

If you encounter certificate warnings or connection issues:

- Ensure the mitmproxy certificate is properly installed and trusted
- Some applications might use certificate pinning, requiring additional steps
- Try using a different browser or device if persistent issues occur

### Proxy Connection Issues

If the proxy connection fails:

- Verify that the proxy is running (`mitmdump -p 8080`)
- Check that your device is properly configured to use the proxy
- Ensure no firewall is blocking the connection

### Not Capturing Expected Traffic

If you're not seeing the expected API calls:

- Verify that you're using an application or website that actually uses Sonnet 3.7
- Try different interactions to trigger API calls
- Check the console output of mitmdump for any errors 