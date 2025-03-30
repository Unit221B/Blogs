# Trae App API Endpoints Documentation

This document tracks all identified API endpoints used by the Trae app for interacting with the Sonnet 3.7 model.

## Target Application

- **Trae App**
  - Location: `/Applications/Trae.app` 
  - Desktop application providing access to Claude Sonnet 3.7
  - Version: 1.97.2

## Key Findings

### Claude 3.7 Sonnet Integration

Our analysis has revealed that Trae uses AWS SDK integration to access Claude 3.7 Sonnet. This is evidenced by telemetry data containing the parameter:

```
"chat_model":"aws_sdk_claude37_sonnet"
```

This suggests that Trae is using AWS Bedrock or another AWS service as the interface to Claude 3.7 Sonnet, rather than directly calling Anthropic's API.

### User/Device Identification

The app uses the following identifiers:
- Machine ID: `01cf49a95ad927ea934d0ddb6eac0511d4c5ace138dee1a6eda9e0184a51bd8d`
- Device ID: `7484270930408703504`
- User ID: `7484083577249612805`
- Session IDs appear to be UUIDs (e.g., `9bcc247f-5c49-47fa-89a5-b3776fdb4ad9`)

### System Metadata

Trae collects and transmits detailed system information:
- Architecture: `arm64`
- OS: `darwin` (macOS Sequoia 15.3.2)
- Build version: `1.0.10282`
- VSCode version: `1.97.2`
- Tenant: `marscode`
- AI Region: `US`

## Authentication System

Based on previous analyses, Trae uses a JWT-based authentication system:

1. **JWT Token Structure**
   - Tokens are passed in the `x-cloudide-token` or `authorization` headers
   - Authorization format: `Cloud-IDE-JWT eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`
   - Uses RS256 algorithm (RSA + SHA-256) for signature verification

2. **JWT Payload**
   ```json
   {
     "data": {
       "id": "7484083577249612805",
       "source": "refresh_token",
       "source_id": "6QdwN3GMUdkNmF6TR5MmD-ZpeFuPStY5K_ovv2DA1_g=.182fba6d4cb4d5ab",
       "tenant_id": "7o2d894p7dr0o4",
       "type": "user"
     },
     "exp": 1743075759,
     "iat": 1742816559
   }
   ```

3. **Login Status Check**
   - Endpoint: `https://api-us-east.trae.ai/cloudide/api/v3/trae/CheckLogin`
   - Uses the `x-cloudide-token` header
   - Validates if the current token is valid

## API Endpoints Overview

So far, we have identified the following endpoints:

### Trae-Specific API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `https://api.trae.ai/icube/api/v1/native/config/query` | GET | Configuration query with machine/device/user IDs |
| `https://api-sg-central.trae.ai/icube/api/v1/device/log/check` | POST | Device log checking |
| `https://api-us-east.trae.ai/cloudide/api/v3/trae/CheckLogin` | GET | Validates login status |
| `https://trae-api-us.mchost.guru/api/ide/v1/llm_raw_chat` | POST | Direct LLM interactions (possibly Claude API access) |
| `https://trae-api-sg.mchost.guru/api/ide/v1/ckg_ab_params` | GET | A/B testing parameters |
| `https://trae-api-us.mchost.guru/api/ide/v1/intents_config` | GET | Configures AI intentions/suggestions |

### Package & Update Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `https://lf-cdn.trae.ai/obj/trae-ai-us/pkg/app/releases/stable/1.0.10282/darwin/latest_arm64_va` | GET | Version check |
| `https://lf-cdn.trae.ai/obj/trae-ai-us/pkg/app/releases/stable/1.0.10282/darwin/Trae-darwin-arm64.zip` | GET | Application update package |

### Analytics & Telemetry Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `https://maliva-mcs.byteoversea.com/list` | POST | Analytics/tracking endpoint for app events including Claude interactions |
| `https://mon-va.byteoversea.com/monitor_browser/collect/batch/?biz_id=marscode_nativeide_us` | POST | Metrics collection |
| `https://starling-oversea.byteoversea.com/check_and_get_text` | GET | Retrieves and validates textual content |

### Extension Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `https://open-vsx.org/vscode/asset/saoudrizwan/claude-dev/3.8.4/Microsoft.VisualStudio.Code.Manifest` | GET | Claude extension manifest |
| `https://openvsxorg.blob.core.windows.net/resources/saoudrizwan/claude-dev/3.8.4/package.json` | GET | Claude extension package details |
| `https://openvsxorg.blob.core.windows.net/resources/saoudrizwan/claude-dev/3.8.4/saoudrizwan.claude-dev-3.8.4.vsix` | GET | Claude extension package |

### Sonnet 3.7 API Endpoints

*The app appears to be using AWS SDK to access Claude 3.7 Sonnet, but we have not yet identified the specific endpoint(s) used for this communication. Previous analysis suggests that `https://trae-api-us.mchost.guru/api/ide/v1/llm_raw_chat` might be involved in LLM interactions, but the current traffic doesn't show this endpoint being used for Claude 3.7 Sonnet specifically.*

## Request/Response Formats

### Configuration Request Format (api.trae.ai)

```
GET /icube/api/v1/native/config/query?machineId=01cf49a95ad927ea934d0ddb6eac0511d4c5ace138dee1a6eda9e0184a51bd8d&deviceId=7484270930408703504&userId=7484083577249612805&packageType=stable_i18n&platform=Mac&arch=arm64&scope=marscode&appVersion=1.2.1&buildVersion=1.0.9698&traeVersionCode=20250318
```

Parameters:
- `machineId` - Machine identifier: `01cf49a95ad927ea934d0ddb6eac0511d4c5ace138dee1a6eda9e0184a51bd8d`
- `deviceId` - Device identifier: `7484270930408703504`
- `userId` - User identifier: `7484083577249612805`
- `packageType` - Package type: `stable_i18n`
- `platform` - Platform: `Mac`
- `arch` - Architecture: `arm64`
- `scope` - Scope: `marscode`
- `appVersion` - App version: `1.2.1`
- `buildVersion` - Build version: `1.0.9698`
- `traeVersionCode` - Trae version code: `20250318`

### Configuration Response Format (api.trae.ai)

```json
{
  "success": false,
  "message": "\u8bf7\u6c42\u8fc7\u4e8e\u9891\u7e41\uff0c\u8bf7\u7a0d\u540e\u518d\u8bd5"
}
```

Note: The response message is in Chinese and translates to "Request too frequent, please try again later."

### LLM Request Format (from previous analysis)

```json
{
  "env_metadata": {
    "channel": "native_ide",
    "ide_version": "1.0.9698",
    "extension_version": "",
    "version_code": 2,
    "region": "sg",
    "app_id": "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8",
    "user_id": "7484083577249612805"
  },
  "events": [{
    "event": "ckg_recall_req",
    "time": 1742931605,
    "payload": "..."
  }]
}
```

### Analytics Request Format (maliva-mcs.byteoversea.com) with Claude 3.7 Sonnet Data

```json
{
  "events": [
    {
      "event": "code_comp_request",
      "params": "{\"chat_model\":\"aws_sdk_claude37_sonnet\",\"chat_type\":\"side_chat\",\"session_id\":\"ada3ae80-7ecb-49d7-912e-3fb13d1e2897\",\"message_id\":\"f936f5a0-0688-463a-afbb-80d9570634d6\",\"has_context\":0,\"has_workspace\":0,\"code_count\":0,\"file_count\":0,\"folder_count\":0,\"code_selection_count\":0,\"terminal_selection_count\":0,\"image_count\":0,\"intent_type\":\"generate_qa\",\"context\":\"pred_no_context\",\"ai_chat_type\":\"chat\"}",
      "local_time_ms": 1743358540373,
      "is_bav": 0,
      "session_id": "9bcc247f-5c49-47fa-89a5-b3776fdb4ad9"
    }
  ],
  "user": {
    "user_unique_id": "7484270930408703504",
    "user_id": "7484083577249612805",
    "user_is_login": true,
    "device_id": "7484270930408703504"
  },
  "header": {
    "app_id": 677332,
    "app_version": "1.2.4",
    "os_name": "mac",
    "os_version": "macOS Sequoia",
    "device_model": "MacBook Air (13-inch, M2, 2022)",
    "region": "US",
    "aiRegion": "US",
    "custom": "{\"icube_uid\":\"7484083577249612805\",\"machine_id\":\"01cf49a95ad927ea934d0ddb6eac0511d4c5ace138dee1a6eda9e0184a51bd8d\",\"arch\":\"arm64\",\"system\":\"darwin\"}"
  }
}
```

### Analytics Response Format (maliva-mcs.byteoversea.com)

```json
{
  "e": -1,
  "sc": 0
}
```

### Standard Sonnet Request Format

*To be determined - not yet captured*

### Standard Sonnet Response Format

*To be determined - not yet captured*

## Parameter Documentation

### Common Parameters in API Requests

| Parameter | Description |
|-----------|-------------|
| `userId` | User identifier: `7484083577249612805` |
| `deviceId` | Device identifier: `7484270930408703504` |
| `machineId` | Machine identifier: `01cf49a95ad927ea934d0ddb6eac0511d4c5ace138dee1a6eda9e0184a51bd8d` |
| `region` | Geographic region (US) |
| `platform` | Platform (Mac) |
| `arch` | Architecture (arm64) |

## Multi-Region Architecture

Based on previous analyses, Trae appears to use a multi-region deployment:

1. **US-East Region**
   - `https://api-us-east.trae.ai/cloudide/api/v3/trae/CheckLogin`
   - `https://trae-api-us.mchost.guru/api/ide/v1/llm_raw_chat`

2. **Singapore Region**
   - `https://api-sg-central.trae.ai/icube/api/v1/device/log/check`
   - `https://trae-api-sg.mchost.guru/api/ide/v1/ckg_ab_params`

The app may route to different regions based on user location or load balancing.

## Next Steps

1. The telemetry data confirms that Trae is using Claude 3.7 Sonnet via an AWS SDK
2. We need to modify our interception approach to locate:
   - The actual AWS API endpoints being used (possibly via WebSockets)
   - Authentication mechanism for AWS Bedrock or other AWS services
   - The message format for conversations with Claude 3.7 Sonnet
3. Given the previous analysis showing JWT authentication, we should:
   - Look for JWT tokens in the current traffic
   - Determine if AWS credentials are embedded in these tokens
   - Examine if `https://trae-api-us.mchost.guru/api/ide/v1/llm_raw_chat` is still being used
4. Potential approaches:
   - Use a different proxy configuration to capture WebSocket traffic
   - Attempt to capture network traffic at a lower level
   - Reverse engineer the app itself to find API call implementations

## Authorization Endpoints

*Endpoints related to authentication and authorization*

## Conversation Endpoints

*Endpoints for creating and managing conversations*

## Message Endpoints

*Endpoints for sending/receiving messages*

## Model Configuration Endpoints

*Endpoints for configuring model parameters*

## Tool Use Endpoints

*Endpoints related to tool use functionality*

## Error Responses

*Standard error response formats*

## Rate Limiting

*Information about rate limits if discovered*

## Known Limitations

*Any identified limitations of the API* 