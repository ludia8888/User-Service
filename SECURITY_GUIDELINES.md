# Security Guidelines - Information Exposure Prevention

## 🔒 Critical Security Principle: Minimal Information Disclosure

### **Problem: Information Overexposure**
APIs must follow the principle of **least privilege** for information disclosure. Never expose sensitive system information unless explicitly required and authorized.

### **Fixed Vulnerabilities**

#### 1. **Registration Response Information Leakage** ✅ FIXED
**Previous Risk:**
```json
{
  "user": {
    "user_id": "123",
    "username": "john",
    "email": "john@example.com",
    "roles": ["user"],                    // ❌ EXPOSED SYSTEM ROLES
    "permissions": ["schema:read", "branch:view"],  // ❌ EXPOSED PERMISSIONS
    "teams": ["default-team"],            // ❌ EXPOSED TEAM STRUCTURE
    "mfa_enabled": false
  }
}
```

**Security Fixed Response:**
```json
{
  "user": {
    "user_id": "123",
    "username": "john", 
    "email": "john@example.com",
    "status": "pending_verification"      // ✅ MINIMAL INFO ONLY
  },
  "message": "User registered successfully. Please check your email for verification instructions.",
  "next_steps": [
    "Check your email for verification link",
    "Verify your email address", 
    "Login with your credentials"
  ]
}
```

#### 2. **Account Info Endpoint Secured** ✅ FIXED
- `/auth/account/userinfo` now returns `UserProfileResponse` (minimal profile info)
- Detailed permissions moved to separate `/auth/profile/permissions` endpoint
- Requires explicit authentication and authorization

### **Security Architecture**

#### **Endpoint Security Levels:**

1. **Public Endpoints** (No Auth Required)
   - `/auth/register` - Returns minimal user info only
   - `/auth/login` - Returns tokens only, no user details

2. **Authenticated Endpoints** (Token Required)
   - `/auth/profile/profile` - Basic profile info (no permissions)
   - `/auth/account/userinfo` - Basic profile info (no permissions)

3. **Privilege-Sensitive Endpoints** (Special Permissions)
   - `/auth/profile/permissions` - Current user's detailed permissions
   - `/auth/profile/permissions/{user_id}` - Requires `user:permissions:read`

#### **Information Classification:**

| Information Type | Security Level | Access Requirements |
|------------------|----------------|-------------------|
| Username, Email, Name | **Basic** | User must be authenticated |
| User Status, MFA Status | **Profile** | User must be authenticated |
| Roles, Permissions, Teams | **Privileged** | Separate endpoint + explicit request |
| Other Users' Permissions | **Admin** | `user:permissions:read` permission |

### **Implementation Guidelines**

#### **DO ✅**
```python
# Registration - Minimal response
return UserCreateResponse(
    user=UserBasicInfo(
        user_id=str(user.id),
        username=user.username,
        email=user.email,
        status=user.status
    )
)

# Profile - Separate permissions endpoint
@router.get("/permissions")
async def get_permissions(current_user: User = Depends(get_current_user)):
    return UserPermissionsResponse(...)
```

#### **DON'T ❌**
```python
# Don't expose permissions in general responses
return UserResponse(
    user_id=user.id,
    roles=user.roles,           # ❌ System structure exposure
    permissions=user.permissions,  # ❌ Privilege escalation info
    teams=user.teams            # ❌ Organization structure
)
```

### **Attack Vectors Prevented**

1. **System Reconnaissance**: Attackers can't discover:
   - Available permissions in the system
   - Role hierarchy and structure
   - Team organization
   - Default privilege assignments

2. **Privilege Escalation Intelligence**: Attackers can't:
   - Map permission relationships
   - Identify high-value targets (users with admin roles)
   - Understand access control patterns

3. **Social Engineering**: Reduced information for:
   - Impersonation attacks
   - Targeted phishing based on user roles
   - Internal structure reconnaissance

### **Monitoring and Alerts**

#### **Implement Monitoring For:**
- Excessive calls to `/auth/profile/permissions` endpoint
- Failed authorization attempts on privilege-sensitive endpoints
- Unusual patterns in user profile access

#### **Alert Triggers:**
- Multiple users accessing permissions endpoint in short time
- Failed attempts to access other users' permissions
- Registration followed immediately by permission enumeration

### **Code Review Checklist**

When reviewing API responses, ensure:

- [ ] Registration endpoints return minimal user information
- [ ] Login endpoints return only tokens and session info
- [ ] Profile endpoints separate basic info from permissions
- [ ] Admin endpoints require explicit permission checks
- [ ] Error messages don't leak system information
- [ ] Response schemas follow principle of least privilege

### **Future Considerations**

1. **Dynamic Permission Loading**: Consider lazy-loading permissions only when explicitly requested
2. **Context-Aware Responses**: Adjust response detail based on user's own privilege level
3. **Audit Logging**: Log all access to privilege-sensitive information
4. **Response Filtering**: Implement response filtering based on requester's clearance level

---

**Security Contact**: For security concerns, contact the security team immediately.
**Last Updated**: 2025-07-06
**Next Review**: 2025-08-06