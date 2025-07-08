"""
Auth Service Improvements
JWT에 scope 클레임 추가 및 기타 개선사항
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set
import jwt
import uuid

from models.user import User
from core.config import settings


class ImprovedAuthService:
    """개선된 인증 서비스 - scope 클레임 포함"""
    
    def create_access_token(self, user: User, include_scopes: bool = True) -> str:
        """
        Create JWT access token with scope claim
        
        Args:
            user: User object with roles and permissions loaded
            include_scopes: Whether to include scope claim (default: True)
        """
        payload = {
            "sub": user.id,  # Subject - user identifier
            "type": "access",  # Token type
            "exp": datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            ),
            "iat": datetime.now(timezone.utc),  # Issued at
            "iss": getattr(settings, 'JWT_ISSUER', 'user-service'),  # Issuer
            "aud": getattr(settings, 'JWT_AUDIENCE', 'oms'),  # Audience
            "sid": str(uuid.uuid4()),  # Session ID for revocation
            "username": user.username,  # Username for logging
            "email": user.email,  # Email for identification
        }
        
        # Add scope claim if enabled
        if include_scopes:
            scopes = self._get_user_scopes(user)
            if scopes:
                payload["scope"] = " ".join(sorted(scopes))  # Space-separated scopes
        
        # Add roles claim for backward compatibility
        role_names = [role.name for role in user.roles]
        if role_names:
            payload["roles"] = role_names
        
        # Add custom claims for frequently used permissions
        if self._user_is_admin(user):
            payload["is_admin"] = True
        
        return jwt.encode(
            payload,
            settings.JWT_SECRET,
            algorithm=settings.JWT_ALGORITHM
        )
    
    def _get_user_scopes(self, user: User) -> Set[str]:
        """
        Convert user permissions to IAM scopes
        
        Returns:
            Set of scope strings (e.g., "api:ontologies:read")
        """
        scopes = set()
        
        # Map permissions to scopes
        permission_to_scope_map = {
            # Ontology permissions
            "ontology:*:read": "api:ontologies:read",
            "ontology:*:write": "api:ontologies:write",
            "ontology:*:admin": "api:ontologies:admin",
            "object_type:*:read": "api:ontologies:read",
            "object_type:*:write": "api:ontologies:write",
            "link_type:*:read": "api:ontologies:read",
            "link_type:*:write": "api:ontologies:write",
            "action_type:*:read": "api:ontologies:read",
            "action_type:*:write": "api:ontologies:write",
            "function_type:*:read": "api:ontologies:read",
            "function_type:*:write": "api:ontologies:write",
            
            # Schema permissions
            "schema:*:read": "api:schemas:read",
            "schema:*:write": "api:schemas:write",
            "schema:*:admin": "api:schemas:admin",
            
            # Branch permissions
            "branch:*:read": "api:branches:read",
            "branch:*:write": "api:branches:write",
            "branch:*:merge": "api:branches:write",
            
            # Proposal permissions
            "proposal:*:read": "api:proposals:read",
            "proposal:*:write": "api:proposals:write",
            "proposal:*:approve": "api:proposals:approve",
            "proposal:*:reject": "api:proposals:approve",
            
            # Audit permissions
            "audit:*:read": "api:audit:read",
            "audit:*:export": "api:audit:export",
            
            # System permissions
            "system:*:admin": "api:system:admin",
            "service:*:account": "api:service:account",
            "webhook:*:execute": "api:webhook:execute",
        }
        
        # Collect permissions from roles
        all_permissions = set()
        for role in user.roles:
            for permission in role.permissions:
                all_permissions.add(permission.name)
        
            # Handle special role mappings
            if role.name == "admin":
                scopes.add("api:system:admin")
            elif role.name == "developer":
                scopes.update([
                    "api:ontologies:write",
                    "api:schemas:read",
                    "api:branches:write",
                    "api:proposals:write"
                ])
            elif role.name == "reviewer":
                scopes.update([
                    "api:ontologies:read",
                    "api:schemas:read",
                    "api:branches:read",
                    "api:proposals:approve"
                ])
            elif role.name == "viewer":
                scopes.update([
                    "api:ontologies:read",
                    "api:schemas:read",
                    "api:branches:read",
                    "api:proposals:read"
                ])
        
        # Add direct permissions
        for permission in user.direct_permissions:
            all_permissions.add(permission.name)
        
        # Convert permissions to scopes
        for perm in all_permissions:
            if perm in permission_to_scope_map:
                scopes.add(permission_to_scope_map[perm])
        
        # Add team-based scopes
        for team in user.teams:
            # Team permissions could add specific scopes
            if team.name == "security-team":
                scopes.add("api:audit:read")
            elif team.name == "admin-team":
                scopes.add("api:system:admin")
        
        return scopes
    
    def _user_is_admin(self, user: User) -> bool:
        """Check if user has admin role"""
        return any(role.name == "admin" for role in user.roles)
    
    def decode_token_with_scopes(self, token: str) -> dict:
        """
        Decode JWT token and parse scopes
        
        Returns:
            Decoded payload with parsed scopes
        """
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=[settings.JWT_ALGORITHM],
                audience=getattr(settings, 'JWT_AUDIENCE', 'oms'),
                issuer=getattr(settings, 'JWT_ISSUER', 'user-service')
            )
            
            # Parse scope claim if present
            if "scope" in payload:
                payload["scopes"] = payload["scope"].split()
            else:
                payload["scopes"] = []
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidAudienceError:
            raise ValueError("Invalid audience")
        except jwt.InvalidIssuerError:
            raise ValueError("Invalid issuer")
        except (jwt.InvalidTokenError, jwt.DecodeError, jwt.InvalidSignatureError):
            raise ValueError("Invalid token")
    
    def validate_token_scopes(self, token: str, required_scopes: List[str]) -> bool:
        """
        Validate that token has required scopes
        
        Args:
            token: JWT token
            required_scopes: List of required scope strings
            
        Returns:
            True if token has all required scopes
        """
        payload = self.decode_token_with_scopes(token)
        token_scopes = set(payload.get("scopes", []))
        
        # Check if user is admin (has all scopes)
        if payload.get("is_admin") or "api:system:admin" in token_scopes:
            return True
        
        # Check if token has all required scopes
        return all(scope in token_scopes for scope in required_scopes)


# Additional improvements

class TokenMetrics:
    """토큰 사용 메트릭 수집"""
    
    @staticmethod
    async def track_token_usage(user_id: str, token_type: str, action: str):
        """토큰 사용 추적"""
        from core.redis import get_redis_client
        import json
        
        redis_client = get_redis_client()
        
        # Create metrics key
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        metrics_key = f"token_metrics:{today}:{user_id}"
        
        # Increment counters
        await redis_client.hincrby(metrics_key, f"{token_type}:{action}", 1)
        
        # Set expiry (keep metrics for 30 days)
        await redis_client.expire(metrics_key, 30 * 24 * 60 * 60)


class SecurityEnhancements:
    """보안 개선사항"""
    
    @staticmethod
    def add_jti_claim(payload: dict) -> dict:
        """JWT ID (jti) 클레임 추가 - 토큰 추적용"""
        payload["jti"] = str(uuid.uuid4())
        return payload
    
    @staticmethod
    def add_nbf_claim(payload: dict, delay_seconds: int = 0) -> dict:
        """Not Before (nbf) 클레임 추가 - 즉시 사용 방지"""
        payload["nbf"] = datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
        return payload
    
    @staticmethod
    def add_fingerprint_claim(payload: dict, request_fingerprint: str) -> dict:
        """디바이스 핑거프린트 추가 - 토큰 도용 방지"""
        import hashlib
        payload["jti_fp"] = hashlib.sha256(
            f"{payload.get('jti', '')}:{request_fingerprint}".encode()
        ).hexdigest()[:16]
        return payload


class PerformanceOptimizations:
    """성능 최적화"""
    
    @staticmethod
    async def batch_validate_tokens(tokens: List[str]) -> List[dict]:
        """여러 토큰 일괄 검증"""
        results = []
        for token in tokens:
            try:
                payload = jwt.decode(
                    token,
                    settings.JWT_SECRET,
                    algorithms=[settings.JWT_ALGORITHM],
                    options={"verify_exp": True}
                )
                results.append({"valid": True, "payload": payload})
            except Exception as e:
                results.append({"valid": False, "error": str(e)})
        return results
    
    @staticmethod
    def create_short_lived_token(user_id: str, duration_seconds: int = 300) -> str:
        """단기 토큰 생성 (특정 작업용)"""
        payload = {
            "sub": user_id,
            "type": "short_lived",
            "exp": datetime.now(timezone.utc) + timedelta(seconds=duration_seconds),
            "iat": datetime.now(timezone.utc),
            "single_use": True
        }
        
        return jwt.encode(
            payload,
            settings.JWT_SECRET,
            algorithm=settings.JWT_ALGORITHM
        )