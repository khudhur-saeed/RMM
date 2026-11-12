# Pydantic Domain Schemas

## Overview
Pydantic v2 data models defining serialization, inbound validation, and cryptographic contract schemas.

## Interface
- agent.py:AgentBase, AgentCreate, AgentRead, AgentUpdate, AgentHeartbeat, AgentEnroll, AgentEnrollResponse
- audit_log.py:AuditLogRead
- crypto.py:PublicKeyRead, SignPayloadRequest, SignPayloadResponse, VerifySignatureRequest, VerifySignatureResponse
- organization.py:OrganizationBase, OrganizationCreate, OrganizationRead
- script.py:ShellType, ScriptParameter, ScriptBase, ScriptCreate, ScriptUpdate, ScriptRead, ScriptRenderRequest, ScriptRenderResponse
- site.py:SiteBase, SiteCreate, SiteRead
- software.py:SoftwareBase, SoftwareRead, SoftwareSyncPayload
- task.py:TaskDispatchFrame, TaskStreamFrame, TaskExitFrame
- telemetry.py:AlertSeverity, AlertCategory, AlertEvent, HardwareMetricsPayload, ServiceStatusPayload, AuthEventPayload
- token.py:EnrollmentTokenBase, EnrollmentTokenCreate, EnrollmentTokenRead, EnrollmentTokenPublic
- user.py:UserCreate, UserUpdate, UserRead, UserCreateResponse, PrincipalRead, RoleMetadataRead

## Invariants
- Script template parameters require alphanumeric identifiers and reject dangerous shell escape characters [script.py:ScriptParameter]
- Token lifespan is constrained between 1 hour and 720 hours (30 days) [token.py:EnrollmentTokenCreate]

## Side Effects
- None

## Verification
- Run: `cd server && pytest`
