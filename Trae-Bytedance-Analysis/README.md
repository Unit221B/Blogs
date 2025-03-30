# Trae & Bytedance AI Tool Analysis

This repository contains research and analysis of Bytedance's Trae AI tool, focusing on how it integrates with Claude 3.7 Sonnet and its authentication mechanisms.

## Key Findings

- **AWS SDK Integration**: Trae uses AWS SDK to access Claude 3.7 Sonnet, confirmed through telemetry data:
  ```json
  "chat_model":"aws_sdk_claude37_sonnet"
  ```
- **Multi-Layer Authentication**: Combines JWT-based authentication for Trae services with AWS authentication for Claude access
- **VSCode Architecture**: Built on Electron/VSCode with extension `saoudrizwan.claude-dev-3.8.4.vsix`
- **Multi-Region Deployment**: Services distributed across US and Singapore regions

## Contents

- `docs/` - Detailed documentation and analysis
  - `PROJECT_Master.md` - Comprehensive overview of all findings
  - `API_ENDPOINTS.md` - Complete API endpoint documentation
  - `AUTH_ANALYSIS.md` - Authentication flow analysis
  - `TOOL_USE.md` - Tool use implementation details
- `captures/` - Network traffic captures and analysis
- `src/` - Source code and implementation attempts
- `scripts/` - Analysis and testing scripts

## Research Approach

Our reverse engineering approach includes:
1. **Traffic Interception**: Using mitmdump to capture HTTP traffic
2. **Authentication Analysis**: Documenting JWT structure and AWS credential usage
3. **Binary Analysis**: Extracting and examining app components
4. **Implementation**: Creating proof-of-concept clients to interact with the service

## Current Challenges

1. **WebSocket Capture**: Current proxy setup doesn't capture WebSocket traffic
2. **AWS Authentication**: Understanding how AWS credentials are obtained and used
3. **Tool Use Flow**: Difficult to capture complete tool use interactions

## Implementation Goals

1. Create a compatible client that can authenticate with both Trae services and AWS Bedrock
2. Implement conversation functionality matching the official client
3. Support tool use capabilities through a compatible interface

## Documentation

See the `docs/` directory for comprehensive documentation on all aspects of the analysis.

## Project Status

This is an ongoing research project. See `tasks.md` for current task status and next steps.