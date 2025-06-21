"""
SOR Framework - Relationship Tracker
Analyzes relationships between Subject, Operation, and Resource to identify security violations
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class SORRelationshipTracker:
    """
    Analyzes relationships between Subject, Operation, and Resource to identify:
    - Trust boundary violations
    - Privilege escalation attempts
    - Data flow risks
    - Authorization gaps
    - Attack patterns
    """
    
    def __init__(self):
        self.trust_violation_rules = [
            {
                'name': 'external_to_sensitive_data',
                'condition': lambda s, o, r: (
                    s.get('trust_boundary') == 'external' and
                    r.get('sensitivity') in ['critical', 'high']
                ),
                'severity': 'high',
                'description': 'External subject accessing sensitive data'
            },
            {
                'name': 'unauthenticated_data_access',
                'condition': lambda s, o, r: (
                    s.get('authentication_status') == 'unauthenticated' and
                    o.get('primary_classification', {}).get('category') == 'data_access'
                ),
                'severity': 'high',
                'description': 'Unauthenticated access to data resources'
            },
            {
                'name': 'anonymous_write_operations',
                'condition': lambda s, o, r: (
                    s.get('type') == 'anonymous' and
                    o.get('primary_classification', {}).get('operation') in ['write', 'delete']
                ),
                'severity': 'critical',
                'description': 'Anonymous user performing write/delete operations'
            }
        ]
        
        self.privilege_escalation_rules = [
            {
                'name': 'standard_user_admin_operation',
                'condition': lambda s, o, r: (
                    s.get('privilege_level') == 'standard' and
                    'admin' in str(o.get('method_signature', {}).get('file_path', '')).lower()
                ),
                'severity': 'critical',
                'description': 'Standard user accessing admin functionality'
            },
            {
                'name': 'api_client_privileged_resource',
                'condition': lambda s, o, r: (
                    s.get('type') == 'api' and
                    r.get('sensitivity') == 'critical' and
                    'authorization_check' not in r.get('protection_mechanisms', [])
                ),
                'severity': 'high',
                'description': 'API client accessing privileged resource without authorization'
            },
            {
                'name': 'service_account_user_data',
                'condition': lambda s, o, r: (
                    s.get('type') == 'service' and
                    'personal_info' in r.get('data_classification', {}).get('detected_data_types', [])
                ),
                'severity': 'medium',
                'description': 'Service account accessing personal data'
            }
        ]
        
        self.data_flow_risk_rules = [
            {
                'name': 'external_to_internal_data_flow',
                'condition': lambda s, o, r: (
                    s.get('trust_boundary') == 'external' and
                    'sql_injection_risk' in o.get('vulnerability_patterns', [])
                ),
                'severity': 'critical',
                'description': 'External input flowing to SQL execution without protection'
            },
            {
                'name': 'unvalidated_input_to_system',
                'condition': lambda s, o, r: (
                    'command_injection_risk' in o.get('vulnerability_patterns', []) and
                    'input_validation' not in r.get('protection_mechanisms', [])
                ),
                'severity': 'critical',
                'description': 'Unvalidated input flowing to system command execution'
            },
            {
                'name': 'sensitive_data_in_logs',
                'condition': lambda s, o, r: (
                    r.get('data_classification', {}).get('contains_sensitive_data') and
                    'log' in str(o.get('method_signature', {}).get('method_name', '')).lower()
                ),
                'severity': 'medium',
                'description': 'Sensitive data potentially logged'
            }
        ]
    
    def analyze_relationships(self, subject: Dict[str, Any], operation: Dict[str, Any], 
                            resource: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze relationships between Subject, Operation, and Resource
        
        Args:
            subject: Subject analysis results
            operation: Operation classification results
            resource: Resource analysis results
            
        Returns:
            Dictionary with relationship analysis results
        """
        try:
            violations = []
            
            # Check trust boundary violations
            trust_violations = self._check_trust_violations(subject, operation, resource)
            violations.extend(trust_violations)
            
            # Check privilege escalation
            privilege_violations = self._check_privilege_escalation(subject, operation, resource)
            violations.extend(privilege_violations)
            
            # Check data flow risks
            data_flow_risks = self._check_data_flow_risks(subject, operation, resource)
            violations.extend(data_flow_risks)
            
            # Calculate overall risk score
            risk_score = self._calculate_relationship_risk(subject, operation, resource, violations)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(violations, subject, operation, resource)
            
            # Determine relationship patterns
            patterns = self._identify_relationship_patterns(subject, operation, resource)
            
            return {
                'violations': violations,
                'risk_score': risk_score,
                'recommendations': recommendations,
                'relationship_patterns': patterns,
                'trust_assessment': self._assess_trust_relationship(subject, operation, resource),
                'attack_vectors': self._identify_attack_vectors(violations, subject, operation, resource)
            }
            
        except Exception as e:
            logger.error(f"Error in SOR relationship analysis: {e}")
            return {
                'violations': [],
                'risk_score': 0.0,
                'recommendations': [],
                'error': str(e)
            }
    
    def _check_trust_violations(self, subject: Dict[str, Any], operation: Dict[str, Any], 
                              resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for trust boundary violations"""
        
        violations = []
        
        for rule in self.trust_violation_rules:
            if rule['condition'](subject, operation, resource):
                violations.append({
                    'type': 'trust_boundary_violation',
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'evidence': self._collect_violation_evidence(rule['name'], subject, operation, resource)
                })
        
        return violations
    
    def _check_privilege_escalation(self, subject: Dict[str, Any], operation: Dict[str, Any], 
                                  resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for privilege escalation attempts"""
        
        violations = []
        
        for rule in self.privilege_escalation_rules:
            if rule['condition'](subject, operation, resource):
                violations.append({
                    'type': 'privilege_escalation',
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'evidence': self._collect_violation_evidence(rule['name'], subject, operation, resource)
                })
        
        return violations
    
    def _check_data_flow_risks(self, subject: Dict[str, Any], operation: Dict[str, Any], 
                             resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for data flow security risks"""
        
        violations = []
        
        for rule in self.data_flow_risk_rules:
            if rule['condition'](subject, operation, resource):
                violations.append({
                    'type': 'data_flow_risk',
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'evidence': self._collect_violation_evidence(rule['name'], subject, operation, resource)
                })
        
        return violations
    
    def _collect_violation_evidence(self, rule_name: str, subject: Dict[str, Any], 
                                  operation: Dict[str, Any], resource: Dict[str, Any]) -> Dict[str, Any]:
        """Collect evidence for a specific violation"""
        
        evidence = {
            'subject_indicators': [],
            'operation_indicators': [],
            'resource_indicators': []
        }
        
        # Subject evidence
        if subject.get('type') == 'anonymous':
            evidence['subject_indicators'].append('anonymous_user')
        if subject.get('trust_boundary') == 'external':
            evidence['subject_indicators'].append('external_source')
        if subject.get('authentication_status') == 'unauthenticated':
            evidence['subject_indicators'].append('unauthenticated')
        
        # Operation evidence
        vuln_patterns = operation.get('vulnerability_patterns', [])
        for pattern in vuln_patterns:
            evidence['operation_indicators'].append(f'vulnerability_pattern: {pattern}')
        
        if operation.get('primary_classification', {}).get('risk_level') in ['high', 'critical']:
            evidence['operation_indicators'].append('high_risk_operation')
        
        # Resource evidence
        if resource.get('sensitivity') in ['high', 'critical']:
            evidence['resource_indicators'].append('sensitive_resource')
        if not resource.get('protection_mechanisms'):
            evidence['resource_indicators'].append('no_protection')
        
        return evidence
    
    def _calculate_relationship_risk(self, subject: Dict[str, Any], operation: Dict[str, Any], 
                                   resource: Dict[str, Any], violations: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score for the SOR relationship"""
        
        base_risk = 0.0
        
        # Subject risk factors
        subject_risk = {
            'anonymous': 3.0,
            'external': 2.0,
            'api': 1.5,
            'service': 1.0,
            'user': 0.5
        }
        base_risk += subject_risk.get(subject.get('type', 'user'), 0.5)
        
        if subject.get('trust_boundary') == 'external':
            base_risk += 2.0
        if subject.get('authentication_status') == 'unauthenticated':
            base_risk += 2.5
        
        # Operation risk factors
        op_risk = operation.get('primary_classification', {}).get('risk_level', 'low')
        risk_multipliers = {
            'critical': 3.0,
            'high': 2.5,
            'medium': 1.5,
            'low': 1.0
        }
        base_risk *= risk_multipliers.get(op_risk, 1.0)
        
        # Resource risk factors
        resource_risk_score = resource.get('risk_assessment', {}).get('risk_score', 0)
        base_risk += resource_risk_score * 0.5
        
        # Violation penalties
        violation_penalties = {
            'critical': 4.0,
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0
        }
        
        for violation in violations:
            penalty = violation_penalties.get(violation.get('severity', 'low'), 1.0)
            base_risk += penalty
        
        # Protection mitigation
        protections = resource.get('protection_mechanisms', [])
        mitigation = len(protections) * 0.5
        base_risk = max(0.0, base_risk - mitigation)
        
        # Cap at 10.0
        return min(base_risk, 10.0)
    
    def _generate_recommendations(self, violations: List[Dict[str, Any]], subject: Dict[str, Any], 
                                operation: Dict[str, Any], resource: Dict[str, Any]) -> List[str]:
        """Generate specific recommendations based on violations and analysis"""
        
        recommendations = []
        
        # Violation-specific recommendations
        for violation in violations:
            if violation['type'] == 'trust_boundary_violation':
                recommendations.append("Implement authentication for external access")
                recommendations.append("Add input validation for external requests")
            elif violation['type'] == 'privilege_escalation':
                recommendations.append("Implement proper authorization checks")
                recommendations.append("Review access control policies")
            elif violation['type'] == 'data_flow_risk':
                recommendations.append("Use parameterized queries")
                recommendations.append("Implement input sanitization")
        
        # Subject-based recommendations
        if subject.get('type') == 'anonymous' and subject.get('trust_boundary') == 'external':
            recommendations.append("Require authentication for sensitive operations")
        
        # Operation-based recommendations
        vuln_patterns = operation.get('vulnerability_patterns', [])
        if 'sql_injection_risk' in vuln_patterns:
            recommendations.append("Replace string interpolation with prepared statements")
        if 'command_injection_risk' in vuln_patterns:
            recommendations.append("Validate and sanitize system command inputs")
        
        # Resource-based recommendations
        if resource.get('sensitivity') in ['high', 'critical']:
            if 'encryption' not in resource.get('protection_mechanisms', []):
                recommendations.append("Implement data encryption for sensitive resources")
            if 'authorization_check' not in resource.get('protection_mechanisms', []):
                recommendations.append("Add authorization checks for sensitive data")
        
        # Remove duplicates while preserving order
        seen = set()
        return [rec for rec in recommendations if not (rec in seen or seen.add(rec))]
    
    def _identify_relationship_patterns(self, subject: Dict[str, Any], operation: Dict[str, Any], 
                                      resource: Dict[str, Any]) -> List[str]:
        """Identify common security relationship patterns"""
        
        patterns = []
        
        # Authentication patterns
        if subject.get('authentication_status') == 'authenticated':
            if operation.get('primary_classification', {}).get('category') == 'authentication':
                patterns.append('authenticated_auth_operation')
            else:
                patterns.append('authenticated_data_access')
        else:
            patterns.append('unauthenticated_access')
        
        # Trust boundary patterns
        if subject.get('trust_boundary') == 'external':
            if resource.get('type') == 'database':
                patterns.append('external_to_database')
            elif resource.get('type') == 'file_system':
                patterns.append('external_to_filesystem')
        
        # Privilege patterns
        if subject.get('privilege_level') == 'admin':
            patterns.append('admin_access')
        elif subject.get('privilege_level') == 'standard':
            if resource.get('sensitivity') == 'critical':
                patterns.append('standard_user_critical_resource')
        
        # Risk patterns
        if (operation.get('primary_classification', {}).get('risk_level') == 'critical' and
            resource.get('sensitivity') == 'critical'):
            patterns.append('high_risk_operation_sensitive_data')
        
        return patterns
    
    def _assess_trust_relationship(self, subject: Dict[str, Any], operation: Dict[str, Any], 
                                 resource: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the trust relationship between components"""
        
        trust_score = 5.0  # Start with neutral trust
        
        # Subject trust factors
        if subject.get('authentication_status') == 'authenticated':
            trust_score += 2.0
        else:
            trust_score -= 3.0
        
        if subject.get('trust_boundary') == 'internal':
            trust_score += 1.0
        elif subject.get('trust_boundary') == 'external':
            trust_score -= 2.0
        
        # Operation trust factors
        if 'authorization_check' in resource.get('protection_mechanisms', []):
            trust_score += 1.5
        if 'input_validation' in resource.get('protection_mechanisms', []):
            trust_score += 1.0
        
        # Vulnerability penalties
        vuln_patterns = operation.get('vulnerability_patterns', [])
        trust_score -= len(vuln_patterns) * 1.0
        
        trust_level = 'high' if trust_score >= 7 else 'medium' if trust_score >= 4 else 'low'
        
        return {
            'trust_score': max(0.0, min(trust_score, 10.0)),
            'trust_level': trust_level,
            'trust_factors': self._identify_trust_factors(subject, operation, resource)
        }
    
    def _identify_trust_factors(self, subject: Dict[str, Any], operation: Dict[str, Any], 
                              resource: Dict[str, Any]) -> Dict[str, List[str]]:
        """Identify factors affecting trust assessment"""
        
        positive_factors = []
        negative_factors = []
        
        # Positive trust factors
        if subject.get('authentication_status') == 'authenticated':
            positive_factors.append('authenticated_subject')
        if subject.get('trust_boundary') == 'internal':
            positive_factors.append('internal_source')
        if resource.get('protection_mechanisms'):
            positive_factors.append('protected_resource')
        
        # Negative trust factors
        if subject.get('type') == 'anonymous':
            negative_factors.append('anonymous_access')
        if subject.get('trust_boundary') == 'external':
            negative_factors.append('external_source')
        if operation.get('vulnerability_patterns'):
            negative_factors.append('vulnerability_patterns_detected')
        if not resource.get('protection_mechanisms'):
            negative_factors.append('unprotected_resource')
        
        return {
            'positive': positive_factors,
            'negative': negative_factors
        }
    
    def _identify_attack_vectors(self, violations: List[Dict[str, Any]], subject: Dict[str, Any], 
                               operation: Dict[str, Any], resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential attack vectors based on the SOR analysis"""
        
        attack_vectors = []
        
        # SQL Injection vector
        if ('sql_injection_risk' in operation.get('vulnerability_patterns', []) and
            subject.get('trust_boundary') == 'external'):
            attack_vectors.append({
                'type': 'sql_injection',
                'likelihood': 'high',
                'impact': 'critical',
                'description': 'External user can inject SQL through unprotected parameters'
            })
        
        # Command Injection vector
        if ('command_injection_risk' in operation.get('vulnerability_patterns', []) and
            'input_validation' not in resource.get('protection_mechanisms', [])):
            attack_vectors.append({
                'type': 'command_injection',
                'likelihood': 'medium',
                'impact': 'critical',
                'description': 'Unvalidated input can be used to execute system commands'
            })
        
        # Privilege Escalation vector
        privilege_violations = [v for v in violations if v['type'] == 'privilege_escalation']
        if privilege_violations:
            attack_vectors.append({
                'type': 'privilege_escalation',
                'likelihood': 'medium',
                'impact': 'high',
                'description': 'Subject may access resources beyond intended privileges'
            })
        
        # Data Exposure vector
        if (resource.get('sensitivity') in ['high', 'critical'] and
            'authorization_check' not in resource.get('protection_mechanisms', [])):
            attack_vectors.append({
                'type': 'data_exposure',
                'likelihood': 'medium',
                'impact': 'high',
                'description': 'Sensitive data may be exposed without proper authorization'
            })
        
        return attack_vectors