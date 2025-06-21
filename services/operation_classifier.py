"""
SOR Framework - Operation Classifier
Classifies operations based on method info, source code, and execution context
"""

import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class OperationClassifier:
    """
    Classifies operations into security-relevant categories
    
    Operation Categories:
    - data_access: Database operations (CRUD)
    - authentication: Authentication and authorization operations
    - system_operations: File I/O, network, system commands
    - cryptographic: Encryption, hashing, signing operations
    - validation: Input validation and sanitization
    - business_logic: Application-specific operations
    """
    
    def __init__(self):
        self.security_operations = {
            'data_access': {
                'read': {
                    'patterns': [
                        'find', 'where', 'select', 'first', 'last', 'all', 'get',
                        'fetch', 'query', 'search', 'index', 'show'
                    ],
                    'sql_keywords': ['SELECT', 'FROM', 'WHERE', 'JOIN'],
                    'risk_level': 'low'
                },
                'write': {
                    'patterns': [
                        'create', 'update', 'save', 'insert', 'new', 'build',
                        'modify', 'edit', 'change', 'set'
                    ],
                    'sql_keywords': ['INSERT', 'UPDATE', 'CREATE'],
                    'risk_level': 'medium'
                },
                'delete': {
                    'patterns': [
                        'delete', 'destroy', 'remove', 'drop', 'clear', 'purge'
                    ],
                    'sql_keywords': ['DELETE', 'DROP', 'TRUNCATE'],
                    'risk_level': 'high'
                },
                'raw_sql': {
                    'patterns': [
                        'find_by_sql', 'execute', 'exec_query', 'exec_insert',
                        'exec_update', 'exec_delete', 'connection.execute'
                    ],
                    'sql_keywords': ['EXEC', 'EXECUTE'],
                    'risk_level': 'high'
                }
            },
            'authentication': {
                'login': {
                    'patterns': [
                        'authenticate', 'sign_in', 'login', 'log_in', 'signin'
                    ],
                    'risk_level': 'medium'
                },
                'logout': {
                    'patterns': [
                        'sign_out', 'logout', 'log_out', 'signout', 'destroy_session'
                    ],
                    'risk_level': 'low'
                },
                'authorization': {
                    'patterns': [
                        'authorize', 'can?', 'cannot?', 'ability', 'permitted?',
                        'allowed?', 'check_permission', 'access_control'
                    ],
                    'risk_level': 'high'
                },
                'session_management': {
                    'patterns': [
                        'current_user', 'session', 'reset_session', 'session_id'
                    ],
                    'risk_level': 'medium'
                }
            },
            'system_operations': {
                'file_io': {
                    'patterns': [
                        'open', 'read', 'write', 'File.', 'IO.', 'file',
                        'upload', 'download', 'copy', 'move'
                    ],
                    'risk_level': 'medium'
                },
                'execution': {
                    'patterns': [
                        'system', 'exec', 'spawn', '`', 'popen', 'shell'
                    ],
                    'risk_level': 'critical'
                },
                'network': {
                    'patterns': [
                        'http', 'request', 'fetch', 'curl', 'wget', 'tcp', 'udp',
                        'socket', 'connect', 'Net::', 'URI'
                    ],
                    'risk_level': 'medium'
                }
            },
            'cryptographic': {
                'encryption': {
                    'patterns': [
                        'encrypt', 'decrypt', 'cipher', 'AES', 'RSA', 'OpenSSL'
                    ],
                    'risk_level': 'high'
                },
                'hashing': {
                    'patterns': [
                        'hash', 'digest', 'MD5', 'SHA', 'bcrypt', 'Digest'
                    ],
                    'risk_level': 'medium'
                },
                'signing': {
                    'patterns': [
                        'sign', 'verify', 'signature', 'JWT', 'token'
                    ],
                    'risk_level': 'high'
                }
            },
            'validation': {
                'input_validation': {
                    'patterns': [
                        'validate', 'sanitize', 'escape', 'filter', 'clean',
                        'strip_tags', 'html_escape', 'sql_escape'
                    ],
                    'risk_level': 'low'
                },
                'parameter_handling': {
                    'patterns': [
                        'permit', 'require', 'params', 'strong_parameters'
                    ],
                    'risk_level': 'medium'
                }
            },
            'code_evaluation': {
                'dynamic_evaluation': {
                    'patterns': [
                        'eval', 'instance_eval', 'class_eval', 'module_eval',
                        'define_method', 'send', '__send__'
                    ],
                    'risk_level': 'critical'
                }
            }
        }
    
    def analyze(self, method_info: Dict[str, Any], source_code: str, 
                execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze method execution to classify the operation
        
        Args:
            method_info: Dictionary containing method name, class, file, line
            source_code: Source code of the method
            execution_context: Execution context from trace
            
        Returns:
            Dictionary with operation classification results
        """
        try:
            method_name = method_info.get('name', '')
            class_name = execution_context.get('class_name', '')
            
            classifications = self._classify_operations(method_name, source_code, class_name)
            vulnerability_patterns = self._detect_vulnerability_patterns(source_code)
            primary_classification = self._select_primary_classification(classifications)
            security_implications = self._derive_security_implications(classifications)
            code_patterns = self._analyze_code_patterns(source_code)
            
            return {
                'classifications': classifications,
                'vulnerability_patterns': vulnerability_patterns,
                'primary_classification': primary_classification,
                'security_implications': security_implications,
                'code_patterns': code_patterns,
                'method_signature': self._extract_method_signature(method_info, execution_context)
            }
            
        except Exception as e:
            logger.error(f"Error in Operation classification: {e}")
            return {
                'classifications': [],
                'vulnerability_patterns': [],
                'primary_classification': {
                    'category': 'unknown',
                    'operation': 'unknown',
                    'risk_level': 'unknown',
                    'confidence': 0.0
                },
                'error': str(e)
            }
    
    def _classify_operations(self, method_name: str, source_code: str, class_name: str) -> List[Dict[str, Any]]:
        """Classify the operation into security categories"""
        
        classifications = []
        method_lower = method_name.lower()
        source_lower = source_code.lower()
        class_lower = class_name.lower()
        
        for category, operations in self.security_operations.items():
            for operation, config in operations.items():
                confidence = self._calculate_confidence(
                    method_lower, source_lower, class_lower, config
                )
                
                if confidence > 0.1:  # Only include if there's reasonable confidence
                    classifications.append({
                        'category': category,
                        'operation': operation,
                        'risk_level': config['risk_level'],
                        'confidence': confidence,
                        'evidence': self._collect_evidence(
                            method_lower, source_lower, config
                        )
                    })
        
        # Sort by confidence descending
        return sorted(classifications, key=lambda x: x['confidence'], reverse=True)
    
    def _calculate_confidence(self, method_name: str, source_code: str, 
                            class_name: str, config: Dict) -> float:
        """Calculate confidence score for operation classification"""
        
        confidence = 0.0
        
        # Method name pattern matching
        patterns = config.get('patterns', [])
        for pattern in patterns:
            if pattern in method_name:
                confidence += 0.4
            if pattern in class_name:
                confidence += 0.2
        
        # SQL keyword matching
        sql_keywords = config.get('sql_keywords', [])
        for keyword in sql_keywords:
            if keyword.lower() in source_code:
                confidence += 0.3
        
        # Source code pattern matching
        for pattern in patterns:
            if pattern in source_code:
                confidence += 0.3
        
        # Cap at 1.0
        return min(confidence, 1.0)
    
    def _collect_evidence(self, method_name: str, source_code: str, config: Dict) -> List[str]:
        """Collect evidence for the classification"""
        
        evidence = []
        
        patterns = config.get('patterns', [])
        for pattern in patterns:
            if pattern in method_name:
                evidence.append(f"method_name: {pattern}")
            if pattern in source_code:
                evidence.append(f"source_code: {pattern}")
        
        sql_keywords = config.get('sql_keywords', [])
        for keyword in sql_keywords:
            if keyword.lower() in source_code:
                evidence.append(f"sql_keyword: {keyword}")
        
        return evidence
    
    def _detect_vulnerability_patterns(self, source_code: str) -> List[str]:
        """Detect vulnerability patterns in source code"""
        
        patterns = []
        
        # SQL Injection patterns
        if re.search(r'#\{.*\}', source_code) and re.search(r'(SELECT|INSERT|UPDATE|DELETE)', source_code, re.I):
            patterns.append('sql_injection_risk')
        
        # Command Injection patterns
        if re.search(r'#\{.*\}', source_code) and re.search(r'(system|exec|spawn|`)', source_code, re.I):
            patterns.append('command_injection_risk')
        
        # Code Injection patterns
        if re.search(r'(eval|instance_eval|class_eval)', source_code, re.I):
            patterns.append('code_injection_risk')
        
        # Path Traversal patterns
        if re.search(r'File\.(open|read|write).*\.\./i', source_code, re.I):
            patterns.append('path_traversal_risk')
        
        # Insecure Deserialization
        if re.search(r'(Marshal\.load|YAML\.load|JSON\.parse)', source_code, re.I):
            patterns.append('deserialization_risk')
        
        # Weak Cryptography
        if re.search(r'(MD5|SHA1)', source_code, re.I):
            patterns.append('weak_cryptography')
        
        # Missing Authorization
        if 'params[' in source_code and not re.search(r'(authorize|can\?|permitted\?)', source_code, re.I):
            patterns.append('missing_authorization_check')
        
        return patterns
    
    def _select_primary_classification(self, classifications: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Select the primary classification based on confidence and risk"""
        
        if not classifications:
            return {
                'category': 'unknown',
                'operation': 'unknown', 
                'risk_level': 'none',
                'confidence': 0.0
            }
        
        # Prioritize by risk level, then confidence
        risk_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
        
        primary = max(classifications, key=lambda x: (
            risk_priority.get(x['risk_level'], 0),
            x['confidence']
        ))
        
        return primary
    
    def _derive_security_implications(self, classifications: List[Dict[str, Any]]) -> List[str]:
        """Derive security implications from classifications"""
        
        implications = []
        
        # Collect unique categories and risk levels
        categories = set(c['category'] for c in classifications)
        risk_levels = set(c['risk_level'] for c in classifications)
        
        # Data access implications
        if 'data_access' in categories:
            implications.append('Handles sensitive data access')
            if 'high' in risk_levels:
                implications.append('Performs high-risk data operations')
        
        # Authentication implications
        if 'authentication' in categories:
            implications.append('Affects authentication/authorization')
        
        # System operations implications
        if 'system_operations' in categories:
            implications.append('Performs system-level operations')
            if 'critical' in risk_levels:
                implications.append('Executes system commands - high security risk')
        
        # Cryptographic implications
        if 'cryptographic' in categories:
            implications.append('Handles cryptographic operations')
        
        # Code evaluation implications
        if 'code_evaluation' in categories:
            implications.append('Performs dynamic code evaluation - critical risk')
        
        return implications
    
    def _analyze_code_patterns(self, source_code: str) -> Dict[str, Any]:
        """Analyze source code for security-relevant patterns"""
        
        patterns = {
            'string_interpolation': bool(re.search(r'#\{.*\}', source_code)),
            'direct_sql': bool(re.search(r'(SELECT|INSERT|UPDATE|DELETE)', source_code, re.I)),
            'system_calls': bool(re.search(r'(system|exec|spawn|`)', source_code, re.I)),
            'file_operations': bool(re.search(r'File\.(open|read|write)', source_code, re.I)),
            'eval_usage': bool(re.search(r'(eval|instance_eval|class_eval)', source_code, re.I)),
            'parameter_access': bool(re.search(r'params\[', source_code)),
            'session_access': bool(re.search(r'session\[', source_code)),
            'authorization_check': bool(re.search(r'(authorize|can\?|permitted\?)', source_code, re.I)),
            'validation_present': bool(re.search(r'(validate|sanitize|escape)', source_code, re.I))
        }
        
        # Calculate risk score based on patterns
        risk_score = 0
        if patterns['string_interpolation'] and patterns['direct_sql']:
            risk_score += 8
        if patterns['system_calls']:
            risk_score += 6
        if patterns['eval_usage']:
            risk_score += 7
        if patterns['parameter_access'] and not patterns['authorization_check']:
            risk_score += 4
        if patterns['file_operations']:
            risk_score += 3
        
        patterns['risk_score'] = min(risk_score, 10)  # Cap at 10
        
        return patterns
    
    def _extract_method_signature(self, method_info: Dict[str, Any], 
                                 execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract method signature information"""
        
        return {
            'method_name': method_info.get('name', ''),
            'class_name': execution_context.get('class_name', ''),
            'file_path': method_info.get('file', ''),
            'line_number': method_info.get('line', 0),
            'local_variables': execution_context.get('local_variables', []),
            'instance_variables': execution_context.get('instance_variables', [])
        }