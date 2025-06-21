"""
SOR Framework - Subject Analyzer
Analyzes request context to determine Subject characteristics
"""

import logging
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SubjectAnalyzer:
    """
    Analyzes request context to classify the Subject (who is performing the operation)
    
    Subject Types:
    - user: Regular authenticated user
    - anonymous: Unauthenticated user  
    - api: API client with key authentication
    - service: Service account or system
    - admin: Privileged administrative user
    """
    
    def __init__(self):
        self.api_patterns = [
            'api-key', 'apikey', 'x-api-key', 'authorization',
            'bearer', 'token', 'client-id'
        ]
        
        self.service_user_agents = [
            'curl', 'wget', 'python-requests', 'ruby', 'go-http-client',
            'java', 'postman', 'insomnia', 'httpie'
        ]
        
        self.admin_indicators = [
            '/admin', '/dashboard', '/management', '/control',
            'admin_user', 'superuser', 'root'
        ]
    
    def analyze(self, request_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request context to determine Subject characteristics
        
        Args:
            request_context: Dictionary containing env, session, headers, etc.
            
        Returns:
            Dictionary with Subject analysis results
        """
        try:
            env = request_context.get('env', {})
            session = request_context.get('session', {})
            headers = request_context.get('headers', {})
            remote_ip = request_context.get('remote_ip', '')
            user_agent = request_context.get('user_agent', '')
            
            subject_type = self._determine_subject_type(env, headers, user_agent)
            auth_status = self._determine_auth_status(session, headers)
            privilege_level = self._determine_privilege_level(session, env)
            trust_boundary = self._determine_trust_boundary(env, remote_ip)
            session_context = self._extract_session_context(session)
            
            return {
                'type': subject_type,
                'authentication_status': auth_status,
                'privilege_level': privilege_level,
                'trust_boundary': trust_boundary,
                'session_context': session_context,
                'remote_ip': remote_ip,
                'user_agent_classification': self._classify_user_agent(user_agent),
                'risk_indicators': self._identify_risk_indicators(env, headers, session)
            }
            
        except Exception as e:
            logger.error(f"Error in Subject analysis: {e}")
            return {
                'type': 'unknown',
                'authentication_status': 'unknown',
                'privilege_level': 'unknown',
                'trust_boundary': 'unknown',
                'session_context': {},
                'error': str(e)
            }
    
    def _determine_subject_type(self, env: Dict, headers: Dict, user_agent: str) -> str:
        """Determine the type of subject making the request"""
        
        # Check for API authentication
        if self._has_api_authentication(headers):
            return 'api'
        
        # Check for service account indicators
        if self._is_service_account(user_agent, env):
            return 'service'
        
        # Check for administrative access
        if self._is_admin_request(env, headers):
            return 'admin'
        
        # Check for authenticated user
        if self._has_user_authentication(headers):
            return 'user'
        
        # Default to anonymous
        return 'anonymous'
    
    def _determine_auth_status(self, session: Dict, headers: Dict) -> str:
        """Determine authentication status"""
        
        # Check session for authentication indicators
        auth_keys = ['user_id', 'current_user', 'logged_in', 'authenticated']
        if any(key in session for key in auth_keys):
            return 'authenticated'
        
        # Check headers for authentication
        auth_headers = ['authorization', 'x-api-key', 'cookie']
        if any(header.lower() in [h.lower() for h in headers.keys()] for header in auth_headers):
            return 'authenticated'
        
        return 'unauthenticated'
    
    def _determine_privilege_level(self, session: Dict, env: Dict) -> str:
        """Determine privilege level of the subject"""
        
        # Check for admin indicators in session
        admin_keys = ['admin', 'superuser', 'root', 'is_admin']
        if any(key in session and session[key] for key in admin_keys):
            return 'admin'
        
        # Check URL path for admin areas
        path = env.get('PATH_INFO', '').lower()
        if any(indicator in path for indicator in self.admin_indicators):
            return 'elevated'
        
        # Check for role-based indicators
        role_keys = ['role', 'roles', 'permissions']
        for key in role_keys:
            if key in session:
                role_value = str(session[key]).lower()
                if any(admin_term in role_value for admin_term in ['admin', 'super', 'root']):
                    return 'admin'
                elif any(elevated_term in role_value for elevated_term in ['manager', 'moderator', 'editor']):
                    return 'elevated'
        
        return 'standard'
    
    def _determine_trust_boundary(self, env: Dict, remote_ip: str) -> str:
        """Determine trust boundary classification"""
        
        # Check for internal/private IP ranges
        if self._is_internal_ip(remote_ip):
            return 'internal'
        
        # Check for localhost/loopback
        if remote_ip in ['127.0.0.1', '::1', 'localhost']:
            return 'localhost'
        
        # Check for known proxy headers indicating internal routing
        forwarded_headers = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_HOST']
        if any(header in env for header in forwarded_headers):
            return 'proxied'
        
        # Default to external
        return 'external'
    
    def _extract_session_context(self, session: Dict) -> Dict[str, Any]:
        """Extract relevant session context for security analysis"""
        
        relevant_keys = [
            'user_id', 'current_user', 'role', 'permissions', 
            'last_login', 'login_time', 'csrf_token'
        ]
        
        context = {}
        for key in relevant_keys:
            if key in session:
                # Avoid exposing sensitive data, just indicate presence
                if key in ['csrf_token', 'session_id']:
                    context[key] = '[PRESENT]' if session[key] else '[ABSENT]'
                else:
                    context[key] = session[key]
        
        return context
    
    def _has_api_authentication(self, headers: Dict) -> bool:
        """Check if request has API-style authentication"""
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if any(pattern in header_lower for pattern in self.api_patterns):
                return True
        
        return False
    
    def _is_service_account(self, user_agent: str, env: Dict) -> bool:
        """Check if request appears to be from a service account"""
        
        user_agent_lower = user_agent.lower()
        
        # Check for programmatic user agents
        if any(pattern in user_agent_lower for pattern in self.service_user_agents):
            return True
        
        # Check for missing or minimal user agent (typical of scripts)
        if not user_agent or len(user_agent) < 10:
            return True
        
        # Check for direct server-to-server indicators
        if env.get('HTTP_HOST') and env.get('SERVER_NAME'):
            if env['HTTP_HOST'] == env['SERVER_NAME']:
                return True
        
        return False
    
    def _is_admin_request(self, env: Dict, headers: Dict) -> bool:
        """Check if request is for administrative functionality"""
        
        path = env.get('PATH_INFO', '').lower()
        return any(indicator in path for indicator in self.admin_indicators)
    
    def _has_user_authentication(self, headers: Dict) -> bool:
        """Check for user-style authentication (session cookies, etc.)"""
        
        # Look for session cookies or user authentication headers
        for header_name, header_value in headers.items():
            if header_name.lower() == 'cookie':
                cookie_lower = header_value.lower()
                if any(session_indicator in cookie_lower for session_indicator in 
                      ['session', '_session', 'sessionid', 'jsessionid']):
                    return True
        
        return False
    
    def _classify_user_agent(self, user_agent: str) -> str:
        """Classify the user agent type"""
        
        if not user_agent:
            return 'missing'
        
        user_agent_lower = user_agent.lower()
        
        # Browser patterns
        browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera']
        if any(browser in user_agent_lower for browser in browsers):
            return 'browser'
        
        # Mobile patterns
        mobile_patterns = ['mobile', 'android', 'iphone', 'ipad']
        if any(pattern in user_agent_lower for pattern in mobile_patterns):
            return 'mobile'
        
        # Programmatic patterns
        if any(pattern in user_agent_lower for pattern in self.service_user_agents):
            return 'programmatic'
        
        # Bot patterns
        bot_patterns = ['bot', 'crawler', 'spider', 'scraper']
        if any(pattern in user_agent_lower for pattern in bot_patterns):
            return 'bot'
        
        return 'unknown'
    
    def _identify_risk_indicators(self, env: Dict, headers: Dict, session: Dict) -> list:
        """Identify potential risk indicators in the request"""
        
        risks = []
        
        # Missing or suspicious user agent
        user_agent = env.get('HTTP_USER_AGENT', '')
        if not user_agent:
            risks.append('missing_user_agent')
        elif len(user_agent) < 10:
            risks.append('suspicious_user_agent')
        
        # Multiple forwarding headers (potential proxy chaining)
        forwarding_headers = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_HOST']
        forwarding_count = sum(1 for header in forwarding_headers if header in env)
        if forwarding_count > 1:
            risks.append('multiple_proxy_headers')
        
        # Mismatched host headers
        http_host = env.get('HTTP_HOST', '')
        server_name = env.get('SERVER_NAME', '')
        if http_host and server_name and http_host != server_name:
            risks.append('host_header_mismatch')
        
        # Session without CSRF protection
        if session and 'csrf_token' not in session:
            risks.append('missing_csrf_token')
        
        return risks
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is in internal/private ranges"""
        
        if not ip or ip == '[FILTERED]':
            return False
        
        # Remove subnet mask if present
        ip = ip.split('/')[0]
        
        try:
            # Check for private IP ranges (RFC 1918)
            private_ranges = [
                r'^10\.',
                r'^192\.168\.',
                r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
            ]
            
            for pattern in private_ranges:
                if re.match(pattern, ip):
                    return True
            
        except Exception:
            pass
        
        return False