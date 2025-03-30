# Trae Authentication Flow Analysis

## Overview

This document analyzes the authentication flow of Trae, an AI-assisted code editor, based on traffic capture analysis. The authentication mechanism relies on JWT tokens with specific headers and structure.

## JWT Token Structure

### 1. Authorization Header Format

```
Authorization: Cloud-IDE-JWT eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoiNzQ4NDA4MzU3NzI0OTYxMjgwNSIsInNvdXJjZSI6InJlZnJlc2hfdG9rZW4iLCJzb3VyY2VfaWQiOiI2UWR3TjNHTVVka05tRjZUUjVNbUQtWnBlRnVQU3RZNUtfb3Z2MkRBMV9nPS4xODJmYmE2ZDRjYjRkNWFiIiwidGVuYW50X2lkIjoiN28yZDg5NHA3ZHIwbzQiLCJ0eXBlIjoidXNlciJ9LCJleHAiOjE3NDMwNzU3NTksImlhdCI6MTc0MjgxNjU1OX0.mXQn1IWkG7AHjB22J8136278SVaAAALXTFPICQOoRoORDzw...
```

### 2. x-cloudide-token Header Format

When using the `x-cloudide-token` header, the token format is identical to the JWT portion of the Authorization header but without the `Cloud-IDE-JWT` prefix:

```
x-cloudide-token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoiNzQ4NDA4MzU3NzI0OTYxMjgwNSIsInNvdXJjZSI6InJlZnJlc2hfdG9rZW4iLCJzb3VyY2VfaWQiOiI2UWR3TjNHTVVka05tRjZUUjVNbUQtWnBlRnVQU3RZNUtfb3Z2MkRBMV9nPS4xODJmYmE2ZDRjYjRkNWFiIiwidGVuYW50X2lkIjoiN28yZDg5NHA3ZHIwbzQiLCJ0eXBlIjoidXNlciJ9LCJleHAiOjE3NDMwNzU3NTksImlhdCI6MTc0MjgxNjU1OX0.mXQn1IWkG7AHjB22J8136278SVaAAALXTFPICQOoRoORDzw...
```

### 3. JWT Payload Structure

The decoded JWT token reveals the following structure:

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

Key components:
- `id`: User identifier (numerical string)
- `source`: Token source, typically "refresh_token"
- `source_id`: Unique identifier for the refresh token
- `tenant_id`: Organizational ID
- `type`: Account type ("user")
- `exp`: Expiration timestamp
- `iat`: Issued-at timestamp

## Authentication Endpoints

### 1. Login Status Check

```
GET https://api-us-east.trae.ai/cloudide/api/v3/trae/CheckLogin
```

- Uses the `x-cloudide-token` header
- Validates if the current token is valid
- Used by the application to verify login state on startup

### 2. Other Auth-Related Endpoints

Several ByteDance endpoints are involved in the authentication process:

```
POST https://mon-va.byteoversea.com/monitor_browser/collect/batch/?biz_id=marscode_nativeide_us
```

- Monitors login events and collects analytics
- Contains detailed application metadata

## Token Refresh Mechanism

The authentication flow includes a token refresh mechanism:

1. Token contains a `source_id` which references the refresh token
2. `exp` and `iat` fields indicate the token has a lifespan of approximately 72 hours
3. The refresh process is likely handled through background requests

## User Identification

The authentication flow includes multiple forms of identification:

1. `user_id`: Primary identifier (7484083577249612805)
2. `device_id`: Hardware identifier (01cf49a95ad927ea934d0ddb6eac0511d4c5ace138dee1a6eda9e0184a51bd8d)
3. Machine-specific details (OS version, architecture, etc.)

## Security Features

1. JWT uses RS256 algorithm (RSA + SHA-256)
2. Tokens have a finite lifespan
3. Multiple layers of verification (user ID, device ID, tenant)

## Integration with AI Services

Authentication tokens are used for all LLM-related requests:

```
POST https://trae-api-us.mchost.guru/api/ide/v1/llm_raw_chat
```

The token is required for accessing the AI completions and contains permission information about which models the user can access.

## Application Startup Flow

1. Application launches and loads cached credentials
2. Performs CheckLogin request to validate token
3. If valid, proceeds to load user-specific settings and preferences
4. If invalid, initiates re-authentication flow

## Implementation Notes

1. Token architecture suggests a centralized ByteDance SSO system
2. Multi-regional deployment (US-East and Singapore endpoints)
3. Integration with multiple ByteDance services indicates a shared authentication framework 