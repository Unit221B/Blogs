# Trae API Architecture Analysis

## Overview
Trae is an AI code editor that appears to be related to ByteDance (TikTok's parent company) based on the API traffic analysis. It employs a distributed microservice architecture with endpoints across multiple domains, using JWT authentication and a mix of JSON and Protocol Buffer for data exchange.

## Authentication System

### Authentication Flow
1. The application uses a JWT-based authentication system
2. Tokens are passed in the `x-cloudide-token` or `authorization` headers
3. Format: `Cloud-IDE-JWT eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`
4. Uses RS256 algorithm (RSA + SHA-256) for signature verification
5. Token includes user ID, tenant ID, and source information

### Token Structure
```
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

## API Endpoints

### Core Endpoints
1. **Authentication & Session Management**
   - `https://api-us-east.trae.ai/cloudide/api/v3/trae/CheckLogin` - Validates login status

2. **Cloud IDE Configuration**
   - `https://trae-api-sg.mchost.guru/api/ide/v1/ckg_ab_params` - A/B testing parameters
   - `https://trae-api-us.mchost.guru/api/ide/v1/intents_config` - Configures AI intentions/suggestions

3. **AI Functionality**
   - `https://trae-api-us.mchost.guru/api/ide/v1/llm_raw_chat` - Direct LLM interactions
   - `https://trae-api-sg.mchost.guru/api/ide/v1/report/clients` - Reports client usage/analytics

### ByteDance Backend Services
1. **Monitoring & Telemetry**
   - `https://mon-va.byteoversea.com/monitor_browser/collect/batch/` - Aggregated telemetry
   
2. **Content Services**
   - `https://starling-oversea.byteoversea.com/check_and_get_text` - Retrieves and validates textual content
   - `https://maliva-mcs.byteoversea.com/list` - Content management service

### Integration Services
1. **Microsoft Services**
   - `https://dc.services.visualstudio.com/` - Visual Studio/AppInsights telemetry
   - `https://mobile.events.data.microsoft.com/OneCollector/` - Microsoft usage data collection

2. **Developer Tools**
   - `https://api.bitbucket.org/` - Bitbucket integration
   - `https://as.atlassian.com/api/v1/batch` - Atlassian services integration

## Data Formats

1. **Primary Content Types**
   - `application/json` - Standard JSON for most API calls
   - `multipart/form-data` - Used for complex data structures and file uploads
   
2. **Headers & Identification**
   - `x-app-id`: Application identifier (e.g., "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8")
   - `x-tt-logid`: ByteDance request tracking ID (e.g., "02174293160417200000000000000000000ffffac1104c0cfca04")
   - `user-agent`: Varies by endpoint (e.g., "go-resty/2.6.0", "axios/1.7.9")

## Request Examples

### LLM Request Structure
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

The payload for AI requests contains:
- Project IDs (file paths)
- User message
- Editor information including selected code
- Entity numbers and session IDs

## Telemetry & Monitoring

Trae extensively tracks user interactions through multiple channels:

1. ByteDance Monitoring
   - Collects user actions and application state
   - Usage patterns and feature adoption
   
2. Microsoft Telemetry 
   - AppInsights tracking of errors and performance
   - User behavior analytics

3. Custom Analytics
   - Internal event tracking for feature usage
   - A/B test performance monitoring

## Architecture Insights

1. **Multi-Region Deployment**
   - Endpoints in different regions (us-east, sg)
   - Regional routing for performance optimization

2. **Security Measures**
   - JWT with RSA signatures (RS256)
   - Short-lived tokens with refresh mechanisms
   - HTTPS with Strict Transport Security

3. **Microservice Architecture**
   - Distinct services for different functionality
   - Cross-service communication via standardized APIs

## Comparison to Cursor

While both are AI code editors, Trae appears to:

1. Have deeper integration with ByteDance infrastructure
2. Use a more distributed service architecture 
3. Implement more extensive telemetry
4. Have similar authentication mechanisms but with different token structures

This analysis is based on limited traffic capture and may not represent the complete API architecture. 