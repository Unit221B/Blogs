# Trae App Reverse Engineering Project

## Project Overview

This project aims to reverse engineer the Trae desktop application to understand how it communicates with Claude 3.7 Sonnet and implements various features like tool use. The recent discovery of AWS SDK integration represents a significant shift in our understanding of the app's architecture.

## Latest Findings

### AWS SDK Integration Confirmed

Telemetry data has confirmed that Trae uses the AWS SDK to access Claude 3.7 Sonnet:

```json
"chat_model":"aws_sdk_claude37_sonnet"
```

This discovery indicates that Trae is likely using AWS Bedrock or another AWS service as an intermediary for Claude 3.7 Sonnet access rather than calling Anthropic's API directly.

### Authentication System

The application uses a multi-layered authentication approach:

1. **JWT-Based Authentication** with Trae/ByteDance services:
   - Tokens passed in `x-cloudide-token` or `authorization` headers
   - Authorization format: `Cloud-IDE-JWT eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`
   - Uses RS256 algorithm for signature verification
   - Login status checked through `https://api-us-east.trae.ai/cloudide/api/v3/trae/CheckLogin`

2. **AWS Authentication** (presumed):
   - Likely uses AWS credentials to access Bedrock/Claude services
   - Credentials might be obtained from Trae backend after authentication
   - May use AWS Signature V4 for request signing

3. **WebSocket Authentication** (potential):
   - Possible additional layer for real-time communication
   - Not yet captured in our traffic analysis

### Application Architecture

- **Type**: Desktop application based on Electron/VSCode
- **Extension**: Using `saoudrizwan.claude-dev-3.8.4.vsix` Claude extension
- **Version**: 1.2.4 with build 1.0.10282
- **System**: macOS Sequoia (arm64)
- **Multi-Region**: Distributed across US and Singapore regions

### API Endpoints

Several key API endpoints have been identified:

1. **Trae-Specific Endpoints**:
   - `https://api.trae.ai/icube/api/v1/native/config/query` - Configuration
   - `https://api-sg-central.trae.ai/icube/api/v1/device/log/check` - Logging
   - `https://api-us-east.trae.ai/cloudide/api/v3/trae/CheckLogin` - Login verification
   - `https://trae-api-us.mchost.guru/api/ide/v1/llm_raw_chat` - Possible LLM interactions

2. **Analytics Endpoints**:
   - `https://maliva-mcs.byteoversea.com/list` - Main analytics endpoint capturing Claude interactions
   - `https://mon-va.byteoversea.com/monitor_browser/collect/batch/` - Metrics collection

3. **AWS Endpoints**:
   - Not yet captured - likely endpoints for AWS Bedrock or related services

## Implementation Plan

### Phase 1: Discovery (Current Phase)

- [x] Set up traffic interception with mitmdump
- [x] Identify basic API endpoints and parameters
- [x] Document authentication mechanism
- [ ] Capture AWS API calls and authentication
- [ ] Analyze WebSocket traffic (if applicable)

### Phase 2: Authentication Implementation

- [ ] Implement JWT token acquisition/refresh
- [ ] Implement AWS credential management
- [ ] Create a complete authentication flow

### Phase 3: Conversation Implementation

- [ ] Implement basic conversation functionality
- [ ] Match message formats exactly
- [ ] Support streaming responses

### Phase 4: Tool Use Implementation

- [ ] Extract tool definition formats
- [ ] Implement tool invocation mechanism
- [ ] Create tool response handlers
- [ ] Test with various tool types

## Technical Challenges

1. **WebSocket Traffic Capture**: Current proxy setup is not capturing WebSocket traffic, which may be crucial for Claude interactions

2. **AWS Authentication**: Understanding how AWS credentials are obtained and used is a key challenge

3. **Tool Use Analysis**: Extracting the complete tool use flow from request to response requires capturing all communication channels

## Next Steps

1. **Modify Capture Approach**:
   - Update proxy configuration to capture WebSocket traffic
   - Use network-level capture tools like Wireshark if needed
   - Consider MitM approaches for AWS traffic

2. **App Binary Analysis**:
   - Extract and analyze the Claude extension
   - Look for AWS SDK implementation in app binaries
   - Search for credential storage locations

3. **Documentation Updates**:
   - Integrate findings across all documentation
   - Create comprehensive authentication flow diagram
   - Update API endpoint documentation with AWS endpoints when discovered

## Reference Documentation

- [API Endpoints](/Volumes/SeXternal/Dev/Reversing/bytedance-re/docs/API_ENDPOINTS.md)
- [Authentication Analysis](/Volumes/SeXternal/Dev/Reversing/bytedance-re/docs/AUTH_ANALYSIS.md)
- [Tool Use Analysis](/Volumes/SeXternal/Dev/Reversing/bytedance-re/docs/TOOL_USE.md)
- [Trae API Analysis](/Volumes/SeXternal/Dev/Reversing/bytedance-re/docs/trae_api_analysis.md) (Initial analysis)
- [Trae Auth Flow](/Volumes/SeXternal/Dev/Reversing/bytedance-re/docs/trae_auth_flow.md) (Initial auth documentation)

## Decision Log

### 2023-11-23
- Set up initial proxy capture with mitmdump
- Focused on HTTP traffic capture before tackling WebSockets

### 2023-11-24
- Documented initial API endpoints and authentication flow
- Created documentation structure for findings

### 2023-11-25
- Discovered AWS SDK integration for Claude 3.7 Sonnet
- Shifted focus to AWS authentication mechanisms
- Began documentation of authentication flow

### 2023-11-26
- Attempted to capture WebSocket traffic (unsuccessful)
- Determined need for additional tools for WebSocket analysis
- Integrated findings from previous documentation into current analysis

## Team Members

- Lead Investigator: [Your Name]
- Documentation Lead: [Your Name]
- Implementation Lead: [Your Name] 