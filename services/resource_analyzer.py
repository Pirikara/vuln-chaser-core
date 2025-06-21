"""
SOR Framework - Resource Analyzer
Analyzes resources to determine sensitivity, access patterns, and protection mechanisms
"""

import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ResourceAnalyzer:
    """
    Analyzes resources (data, files, network endpoints) to determine:
    - Resource type and sensitivity level
    - Access patterns (direct, indirect, filtered)
    - Protection mechanisms in place
    - Data classification
    """
    
    def __init__(self):
        self.sensitive_data_patterns = {
            'personal_info': [
                'email', 'name', 'address', 'phone', 'ssn', 'social_security',
                'birth_date', 'birthday', 'age', 'gender', 'personal'
            ],
            'financial': [
                'credit_card', 'card_number', 'account_number', 'routing_number',
                'bank', 'payment', 'billing', 'salary', 'income', 'financial'
            ],
            'authentication': [
                'password', 'passwd', 'pwd', 'token', 'key', 'secret',
                'credential', 'auth', 'session', 'csrf', 'api_key'
            ],
            'medical': [
                'medical', 'health', 'diagnosis', 'treatment', 'patient',
                'medication', 'prescription', 'hipaa'
            ],
            'business_critical': [
                'confidential', 'proprietary', 'trade_secret', 'internal',
                'private', 'restricted', 'classified'
            ]
        }
        
        self.database_models = [
            'User', 'Account', 'Payment', 'Order', 'Transaction', 'Customer',
            'Employee', 'Patient', 'Member', 'Profile', 'Credential'
        ]
        
        self.file_sensitivity_patterns = {
            'high': ['.key', '.pem', '.cert', '.p12', '.jks', 'private_key',
                    'config', 'secret', 'credential', '.env'],
            'medium': ['.log', '.txt', '.csv', '.json', '.xml', '.yaml',
                      'backup', 'dump', 'export'],
            'low': ['.jpg', '.png', '.gif', '.css', '.js', '.html']
        }
    
    def analyze(self, parameters: Dict[str, Any], source_code: str, 
                resource_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze resource context to determine resource characteristics
        
        Args:
            parameters: Method parameters/arguments
            source_code: Source code of the method
            resource_context: Resource context from execution trace
            
        Returns:
            Dictionary with resource analysis results
        """
        try:
            resource_type = self._determine_resource_type(resource_context)
            sensitivity = self._analyze_sensitivity(parameters, source_code, resource_context)
            access_pattern = self._analyze_access_pattern(source_code)
            data_classification = self._classify_data(parameters, source_code)
            affected_resources = self._identify_affected_resources(resource_context)
            protection_mechanisms = self._detect_protection_mechanisms(source_code)
            
            return {
                'type': resource_type,
                'sensitivity': sensitivity,
                'access_pattern': access_pattern,
                'data_classification': data_classification,
                'affected_resources': affected_resources,
                'protection_mechanisms': protection_mechanisms,
                'risk_assessment': self._assess_resource_risk(
                    resource_type, sensitivity, access_pattern, protection_mechanisms
                )
            }
            
        except Exception as e:
            logger.error(f"Error in Resource analysis: {e}")
            return {
                'type': 'unknown',
                'sensitivity': 'unknown',
                'access_pattern': 'unknown',
                'data_classification': {},
                'affected_resources': [],
                'protection_mechanisms': [],
                'error': str(e)
            }
    
    def _determine_resource_type(self, resource_context: Dict[str, Any]) -> str:
        """Determine the primary type of resource being accessed"""
        
        database_ops = resource_context.get('database_operations', [])
        file_ops = resource_context.get('file_operations', [])
        network_ops = resource_context.get('network_operations', [])
        env_access = resource_context.get('environment_access', [])
        
        if database_ops:
            return 'database'
        elif file_ops:
            return 'file_system'
        elif network_ops:
            return 'network'
        elif env_access:
            return 'environment'
        else:
            return 'memory'
    
    def _analyze_sensitivity(self, parameters: Dict[str, Any], source_code: str, 
                           resource_context: Dict[str, Any]) -> str:
        """Analyze sensitivity level of the resource"""
        
        sensitivity_score = 0
        sensitivity_indicators = []
        
        # Check accessed constants for sensitive models
        constants = resource_context.get('accessed_constants', [])
        for constant in constants:
            if any(model in constant for model in self.database_models):
                sensitivity_score += 2
                sensitivity_indicators.append(f"sensitive_model: {constant}")
        
        # Check parameters for sensitive data patterns
        param_text = ' '.join(str(v) for v in parameters.values() if v != '[FILTERED]')
        for category, patterns in self.sensitive_data_patterns.items():
            for pattern in patterns:
                if pattern.lower() in param_text.lower():
                    sensitivity_score += 3
                    sensitivity_indicators.append(f"sensitive_param: {pattern}")
        
        # Check source code for sensitive operations
        source_lower = source_code.lower()
        for category, patterns in self.sensitive_data_patterns.items():
            for pattern in patterns:
                if pattern in source_lower:
                    sensitivity_score += 1
                    sensitivity_indicators.append(f"sensitive_code: {pattern}")
        
        # Check database operations for sensitivity
        db_ops = resource_context.get('database_operations', [])
        sensitive_db_ops = ['delete', 'drop', 'truncate', 'update']
        for op in db_ops:
            if op.lower() in sensitive_db_ops:
                sensitivity_score += 2
                sensitivity_indicators.append(f"sensitive_db_op: {op}")
        
        # Check file operations for sensitive files
        file_ops = resource_context.get('file_operations', [])
        for op in file_ops:
            for level, patterns in self.file_sensitivity_patterns.items():
                if any(pattern in source_lower for pattern in patterns):
                    if level == 'high':
                        sensitivity_score += 4
                    elif level == 'medium':
                        sensitivity_score += 2
                    sensitivity_indicators.append(f"sensitive_file: {op}")
        
        # Determine sensitivity level
        if sensitivity_score >= 8:
            return 'critical'
        elif sensitivity_score >= 5:
            return 'high'
        elif sensitivity_score >= 2:
            return 'medium'
        elif sensitivity_score > 0:
            return 'low'
        else:
            return 'public'
    
    def _analyze_access_pattern(self, source_code: str) -> str:
        """Analyze how the resource is being accessed"""
        
        source_lower = source_code.lower()
        
        # Direct SQL execution
        if re.search(r'(find_by_sql|execute|exec_query)', source_lower):
            return 'direct_sql'
        
        # Raw file access
        if re.search(r'file\.(open|read|write)', source_lower):
            return 'direct_file'
        
        # ORM with conditions
        if re.search(r'where.*=|find.*:conditions', source_lower):
            return 'filtered_access'
        
        # Parameterized access
        if re.search(r'find\(.*\)|find_by.*\(', source_lower):
            return 'parameterized'
        
        # Bulk operations
        if re.search(r'(all|find_each|in_batches)', source_lower):
            return 'bulk_access'
        
        # System command execution
        if re.search(r'(system|exec|spawn)', source_lower):
            return 'system_command'
        
        return 'standard'
    
    def _classify_data(self, parameters: Dict[str, Any], source_code: str) -> Dict[str, Any]:
        """Classify the type of data being handled"""
        
        data_types = {}
        
        # Analyze parameters
        for key, value in parameters.items():
            if value == '[FILTERED]':
                data_types[key] = 'sensitive_filtered'
                continue
                
            key_lower = key.lower()
            for category, patterns in self.sensitive_data_patterns.items():
                if any(pattern in key_lower for pattern in patterns):
                    data_types[key] = category
                    break
            else:
                data_types[key] = 'general'
        
        # Analyze source code for data type indicators
        source_lower = source_code.lower()
        detected_types = set()
        
        for category, patterns in self.sensitive_data_patterns.items():
            for pattern in patterns:
                if pattern in source_lower:
                    detected_types.add(category)
        
        return {
            'parameter_classification': data_types,
            'detected_data_types': list(detected_types),
            'contains_sensitive_data': bool(detected_types),
            'filtered_parameters': sum(1 for v in parameters.values() if v == '[FILTERED]')
        }
    
    def _identify_affected_resources(self, resource_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify specific resources that are affected"""
        
        resources = []
        
        # Database resources
        db_ops = resource_context.get('database_operations', [])
        if db_ops:
            resources.append({
                'type': 'database',
                'operations': db_ops,
                'tables': self._extract_table_names(resource_context)
            })
        
        # File system resources
        file_ops = resource_context.get('file_operations', [])
        if file_ops:
            resources.append({
                'type': 'file_system',
                'operations': file_ops,
                'paths': self._extract_file_paths(resource_context)
            })
        
        # Network resources
        network_ops = resource_context.get('network_operations', [])
        if network_ops:
            resources.append({
                'type': 'network',
                'operations': network_ops,
                'endpoints': self._extract_network_endpoints(resource_context)
            })
        
        # Environment resources
        env_access = resource_context.get('environment_access', [])
        if env_access:
            resources.append({
                'type': 'environment',
                'accessed_variables': env_access
            })
        
        return resources
    
    def _detect_protection_mechanisms(self, source_code: str) -> List[str]:
        """Detect security protection mechanisms in the code"""
        
        protections = []
        source_lower = source_code.lower()
        
        # Input validation
        validation_patterns = [
            'validate', 'validates', 'validation', 'valid?',
            'sanitize', 'escape', 'strip_tags', 'html_escape'
        ]
        if any(pattern in source_lower for pattern in validation_patterns):
            protections.append('input_validation')
        
        # Authorization checks
        auth_patterns = [
            'authorize', 'can?', 'cannot?', 'ability', 'permitted?',
            'before_action', 'before_filter', 'check_permission'
        ]
        if any(pattern in source_lower for pattern in auth_patterns):
            protections.append('authorization_check')
        
        # Parameter filtering
        param_patterns = [
            'permit', 'require', 'strong_parameters', 'params.permit'
        ]
        if any(pattern in source_lower for pattern in param_patterns):
            protections.append('parameter_filtering')
        
        # SQL injection protection
        if re.search(r'(prepare|bind|placeholder|\?)', source_lower):
            protections.append('parameterized_query')
        
        # CSRF protection
        if re.search(r'(csrf|authenticity_token)', source_lower):
            protections.append('csrf_protection')
        
        # Encryption/encoding
        crypto_patterns = ['encrypt', 'encode', 'hash', 'digest', 'bcrypt']
        if any(pattern in source_lower for pattern in crypto_patterns):
            protections.append('encryption')
        
        # Rate limiting
        if re.search(r'(rate_limit|throttle)', source_lower):
            protections.append('rate_limiting')
        
        return protections
    
    def _assess_resource_risk(self, resource_type: str, sensitivity: str, 
                            access_pattern: str, protections: List[str]) -> Dict[str, Any]:
        """Assess overall risk level for the resource access"""
        
        risk_score = 0
        risk_factors = []
        
        # Base risk by resource type
        type_risk = {
            'database': 3,
            'file_system': 4,
            'network': 2,
            'environment': 3,
            'memory': 1
        }
        risk_score += type_risk.get(resource_type, 1)
        
        # Sensitivity risk
        sensitivity_risk = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'public': 0
        }
        risk_score += sensitivity_risk.get(sensitivity, 0)
        if sensitivity in ['critical', 'high']:
            risk_factors.append(f"high_sensitivity: {sensitivity}")
        
        # Access pattern risk
        pattern_risk = {
            'direct_sql': 4,
            'direct_file': 3,
            'system_command': 5,
            'bulk_access': 2,
            'filtered_access': 1,
            'parameterized': 1,
            'standard': 0
        }
        risk_score += pattern_risk.get(access_pattern, 0)
        if pattern_risk.get(access_pattern, 0) >= 3:
            risk_factors.append(f"risky_access_pattern: {access_pattern}")
        
        # Protection mitigation
        protection_mitigation = len(protections)
        risk_score = max(0, risk_score - protection_mitigation)
        
        if not protections:
            risk_factors.append("no_protection_mechanisms")
        
        # Final risk level
        if risk_score >= 10:
            risk_level = 'critical'
        elif risk_score >= 7:
            risk_level = 'high'
        elif risk_score >= 4:
            risk_level = 'medium'
        elif risk_score >= 2:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'protection_count': len(protections),
            'recommendations': self._generate_risk_recommendations(
                risk_level, risk_factors, protections
            )
        }
    
    def _extract_table_names(self, resource_context: Dict[str, Any]) -> List[str]:
        """Extract database table names from context"""
        
        tables = []
        constants = resource_context.get('accessed_constants', [])
        
        for constant in constants:
            if any(model in constant for model in self.database_models):
                tables.append(constant)
        
        return tables
    
    def _extract_file_paths(self, resource_context: Dict[str, Any]) -> List[str]:
        """Extract file paths from context"""
        
        # This would be enhanced to extract actual file paths from execution context
        # For now, return operation types
        return resource_context.get('file_operations', [])
    
    def _extract_network_endpoints(self, resource_context: Dict[str, Any]) -> List[str]:
        """Extract network endpoints from context"""
        
        # This would be enhanced to extract actual URLs/endpoints
        # For now, return operation types
        return resource_context.get('network_operations', [])
    
    def _generate_risk_recommendations(self, risk_level: str, risk_factors: List[str], 
                                     protections: List[str]) -> List[str]:
        """Generate risk mitigation recommendations"""
        
        recommendations = []
        
        if risk_level in ['critical', 'high']:
            if 'authorization_check' not in protections:
                recommendations.append("Implement authorization checks")
            if 'input_validation' not in protections:
                recommendations.append("Add input validation")
            if 'parameterized_query' not in protections and 'direct_sql' in str(risk_factors):
                recommendations.append("Use parameterized queries")
        
        if 'no_protection_mechanisms' in risk_factors:
            recommendations.append("Implement security controls")
        
        if 'risky_access_pattern' in str(risk_factors):
            recommendations.append("Review access pattern for security")
        
        if 'high_sensitivity' in str(risk_factors):
            recommendations.append("Implement data encryption")
            recommendations.append("Add audit logging")
        
        return recommendations