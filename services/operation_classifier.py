"""
Pattern-Free Operation Analysis
Collects raw operation data without predefined security classifications
Enables LLM to perform creative, unrestricted security analysis
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class OperationCollector:
    """
    Pattern-Free Operation Data Collection
    
    Replaces pattern-based classification with raw data collection
    Enables LLM to perform creative security analysis without constraints
    """
    
    def __init__(self):
        # No predefined patterns - collect raw data only
        self.pattern_free_collection = True
        self.llm_analysis_required = True
    
    def collect_operation_data(self, method_name: str, source_code: str, 
                              execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect raw operation data without pattern-based classification
        """
        
        return {
            'raw_operation_data': {
                'method_name': method_name,
                'source_code': source_code,
                'source_length': len(source_code),
                'execution_context': execution_context,
                'method_calls_detected': self._extract_method_calls(source_code),
                'variable_assignments': self._extract_variable_assignments(source_code),
                'string_operations': self._extract_string_operations(source_code),
                'parameter_references': self._extract_parameter_references(source_code)
            },
            # Compatibility fields for SOR Analysis Engine
            'primary_classification': {
                'category': 'pattern_free_analysis',
                'operation': 'llm_driven_analysis',
                'risk_level': 'requires_llm_assessment',
                'implementation_quality': 'pattern_free'
            },
            'collection_metadata': {
                'pattern_free_collection': True,
                'llm_analysis_required': True,
                'no_predefined_classifications': True,
                'creative_analysis_enabled': True
            }
        }
    
    def _extract_method_calls(self, source_code: str) -> List[str]:
        """Extract method calls without security classification"""
        import re
        method_calls = re.findall(r'(\w+)\s*\(', source_code)
        return method_calls
    
    def _extract_variable_assignments(self, source_code: str) -> List[str]:
        """Extract variable assignments without security assessment"""
        import re
        assignments = re.findall(r'(\w+)\s*=', source_code)
        return assignments
    
    def _extract_string_operations(self, source_code: str) -> Dict[str, bool]:
        """Extract string operations without pattern-based security analysis"""
        return {
            'contains_interpolation': '#{' in source_code,
            'contains_string_concat': '+' in source_code or '<<' in source_code,
            'contains_quotes': '"' in source_code or "'" in source_code,
            'contains_backslash': '\\' in source_code
        }
    
    def _extract_parameter_references(self, source_code: str) -> Dict[str, bool]:
        """Extract parameter references without security pre-assessment"""
        return {
            'contains_params': 'params' in source_code,
            'contains_request': 'request' in source_code,
            'contains_session': 'session' in source_code,
            'contains_current_user': 'current_user' in source_code
        }
    
    def analyze_operation_sequence(self, operation_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze sequence of operations without pattern-based security assessment
        """
        
        return {
            'sequence_analysis': {
                'total_operations': len(operation_list),
                'operation_methods': [op.get('method_name', '') for op in operation_list],
                'unique_methods': list(set(op.get('method_name', '') for op in operation_list)),
                'source_code_snippets': [op.get('source_code', '')[:200] for op in operation_list],
                'parameter_usage_sequence': [
                    op.get('raw_operation_data', {}).get('parameter_references', {})
                    for op in operation_list
                ]
            },
            'llm_analysis_context': {
                'pattern_free_sequence': True,
                'creative_analysis_required': True,
                'no_predefined_security_categories': True
            }
        }


# Backward compatibility alias
OperationClassifier = OperationCollector