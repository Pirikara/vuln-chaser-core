"""
SOR Framework - Analysis Engine
Coordinates all SOR components to provide comprehensive security analysis
"""

import asyncio
import logging
import time
from typing import Dict, Any, List

from .subject_analyzer import SubjectAnalyzer
from .operation_classifier import OperationClassifier
from .resource_analyzer import ResourceAnalyzer
from .sor_relationship_tracker import SORRelationshipTracker

logger = logging.getLogger(__name__)


class SORAnalysisEngine:
    """
    Central engine that coordinates all SOR Framework components to provide
    comprehensive security analysis of trace data.
    
    Workflow:
    1. Parse trace data for SOR contexts
    2. Analyze Subject characteristics
    3. Classify Operation patterns
    4. Evaluate Resource sensitivity
    5. Track SOR relationships and violations
    6. Generate comprehensive security assessment
    """
    
    def __init__(self):
        self.subject_analyzer = SubjectAnalyzer()
        self.operation_classifier = OperationClassifier()
        self.resource_analyzer = ResourceAnalyzer()
        self.relationship_tracker = SORRelationshipTracker()
        
        # Performance tracking
        self.analysis_times = {
            'subject': [],
            'operation': [],
            'resource': [],
            'relationship': [],
            'total': []
        }
    
    async def analyze_trace_batch(self, trace_batch: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze a batch of traces using the SOR Framework
        
        Args:
            trace_batch: Dictionary containing batch_id, timestamp, and traces
            
        Returns:
            List of SOR analysis results for each trace
        """
        start_time = time.time()
        
        try:
            traces = trace_batch.get('traces', [])
            results = []
            
            logger.info(f"Starting SOR analysis for {len(traces)} traces")
            
            if not traces:
                logger.warning("⚠️ No traces to analyze")
                return []
            
            # Process traces concurrently for better performance
            tasks = []
            for trace in traces:
                task = asyncio.create_task(self.analyze_single_trace(trace))
                tasks.append(task)
            
            # Wait for all analyses to complete
            trace_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results and handle exceptions
            for i, result in enumerate(trace_results):
                if isinstance(result, Exception):
                    logger.error(f"Error analyzing trace {i}: {result}")
                    results.append({
                        'trace_id': traces[i].get('trace_id', f'trace-{i}'),
                        'error': str(result),
                        'sor_analysis': None
                    })
                else:
                    results.append(result)
            
            total_time = time.time() - start_time
            self.analysis_times['total'].append(total_time)
            
            logger.info(f"SOR analysis completed in {total_time:.2f}s for {len(traces)} traces")
            
            return results
            
        except Exception as e:
            logger.error(f"Error in SOR trace batch analysis: {e}")
            return [{
                'error': str(e),
                'sor_analysis': None
            }]
    
    async def analyze_single_trace(self, trace: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single trace using the SOR Framework
        
        Args:
            trace: Individual trace data with request_context and execution_trace
            
        Returns:
            Dictionary with comprehensive SOR analysis results
        """
        trace_id = trace.get('trace_id', 'unknown')
        
        try:
            # Extract SOR contexts from trace data
            request_context = trace.get('request_context', {})
            execution_traces = trace.get('execution_trace', [])
            
            if not execution_traces:
                return {
                    'trace_id': trace_id,
                    'sor_analysis': {
                        'subject': {},
                        'operations': [],
                        'resources': [],
                        'relationships': {},
                        'summary': {
                            'risk_level': 'none',
                            'total_violations': 0,
                            'message': 'No execution traces found'
                        }
                    }
                }
            
            # Analyze Subject (once per trace)
            subject_start = time.time()
            subject_analysis = await self._analyze_subject(request_context)
            self.analysis_times['subject'].append(time.time() - subject_start)
            
            # Analyze Operations and Resources for each execution trace
            operation_analyses = []
            resource_analyses = []
            
            for exec_trace in execution_traces:
                # Extract method info and contexts
                method_info = {
                    'name': exec_trace.get('method', ''),
                    'file': exec_trace.get('file', ''),
                    'line': exec_trace.get('line', 0)
                }
                source_code = exec_trace.get('source', '')
                execution_context = exec_trace.get('execution_context', {})
                resource_context = exec_trace.get('resource_context', {})
                parameters = exec_trace.get('parameter_usage', {})
                
                # Analyze Operation
                op_start = time.time()
                operation_analysis = await self._analyze_operation(
                    method_info, source_code, execution_context
                )
                operation_analysis['trace_method'] = method_info.get('name')
                operation_analyses.append(operation_analysis)
                self.analysis_times['operation'].append(time.time() - op_start)
                
                # Analyze Resource
                res_start = time.time()
                resource_analysis = await self._analyze_resource(
                    parameters, source_code, resource_context
                )
                resource_analysis['trace_method'] = method_info.get('name')
                resource_analyses.append(resource_analysis)
                self.analysis_times['resource'].append(time.time() - res_start)
            
            # Analyze SOR Relationships
            rel_start = time.time()
            relationship_analysis = await self._analyze_relationships(
                subject_analysis, operation_analyses, resource_analyses
            )
            self.analysis_times['relationship'].append(time.time() - rel_start)
            
            # Generate comprehensive summary
            summary = self._generate_analysis_summary(
                subject_analysis, operation_analyses, resource_analyses, relationship_analysis
            )
            
            return {
                'trace_id': trace_id,
                'execution_trace': execution_traces,  # Include execution_trace for vulnerability analysis
                'sor_analysis': {
                    'subject': subject_analysis,
                    'operations': operation_analyses,
                    'resources': resource_analyses,
                    'relationships': relationship_analysis,
                    'summary': summary
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing trace {trace_id}: {e}")
            return {
                'trace_id': trace_id,
                'error': str(e),
                'sor_analysis': None
            }
    
    async def _analyze_subject(self, request_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Subject using SubjectAnalyzer"""
        return self.subject_analyzer.analyze(request_context)
    
    async def _analyze_operation(self, method_info: Dict[str, Any], source_code: str, 
                               execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Operation using Pattern-Free OperationCollector"""
        method_name = method_info.get('name', '')
        return self.operation_classifier.collect_operation_data(method_name, source_code, execution_context)
    
    async def _analyze_resource(self, parameters: Dict[str, Any], source_code: str, 
                              resource_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Resource using ResourceAnalyzer"""
        return self.resource_analyzer.analyze(parameters, source_code, resource_context)
    
    async def _analyze_relationships(self, subject_analysis: Dict[str, Any], 
                                   operation_analyses: List[Dict[str, Any]], 
                                   resource_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze SOR relationships across all operations in the trace"""
        
        all_violations = []
        all_recommendations = []
        relationship_patterns = []
        max_risk_score = 0.0
        trust_assessments = []
        attack_vectors = []
        
        # Analyze relationships for each operation-resource pair
        for i, (op_analysis, res_analysis) in enumerate(zip(operation_analyses, resource_analyses)):
            relationship_result = self.relationship_tracker.analyze_relationships(
                subject_analysis, op_analysis, res_analysis
            )
            
            # Collect all findings
            violations = relationship_result.get('violations', [])
            for violation in violations:
                violation['operation_index'] = i
                violation['method'] = op_analysis.get('trace_method', '')
            all_violations.extend(violations)
            
            all_recommendations.extend(relationship_result.get('recommendations', []))
            relationship_patterns.extend(relationship_result.get('relationship_patterns', []))
            
            risk_score = relationship_result.get('risk_score', 0.0)
            max_risk_score = max(max_risk_score, risk_score)
            
            trust_assessments.append(relationship_result.get('trust_assessment', {}))
            attack_vectors.extend(relationship_result.get('attack_vectors', []))
        
        # Remove duplicate recommendations
        unique_recommendations = list(dict.fromkeys(all_recommendations))
        
        # Aggregate trust assessment
        avg_trust_score = sum(ta.get('trust_score', 0) for ta in trust_assessments) / max(len(trust_assessments), 1)
        
        return {
            'violations': all_violations,
            'risk_score': max_risk_score,
            'recommendations': unique_recommendations,
            'relationship_patterns': list(set(relationship_patterns)),
            'trust_assessment': {
                'average_trust_score': avg_trust_score,
                'trust_level': 'high' if avg_trust_score >= 7 else 'medium' if avg_trust_score >= 4 else 'low',
                'individual_assessments': trust_assessments
            },
            'attack_vectors': attack_vectors
        }
    
    def _generate_analysis_summary(self, subject_analysis: Dict[str, Any], 
                                 operation_analyses: List[Dict[str, Any]], 
                                 resource_analyses: List[Dict[str, Any]], 
                                 relationship_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis summary"""
        
        violations = relationship_analysis.get('violations', [])
        risk_score = relationship_analysis.get('risk_score', 0.0)
        
        # Determine overall risk level
        if risk_score >= 8.0:
            risk_level = 'critical'
        elif risk_score >= 6.0:
            risk_level = 'high'
        elif risk_score >= 3.0:
            risk_level = 'medium'
        elif risk_score > 0.0:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        # Count violation types
        violation_counts = {}
        for violation in violations:
            v_type = violation.get('type', 'unknown')
            violation_counts[v_type] = violation_counts.get(v_type, 0) + 1
        
        # Identify highest risk operations
        high_risk_operations = []
        for i, op_analysis in enumerate(operation_analyses):
            primary_class = op_analysis.get('primary_classification', {})
            if primary_class.get('risk_level') in ['high', 'critical']:
                high_risk_operations.append({
                    'index': i,
                    'method': op_analysis.get('trace_method', ''),
                    'risk_level': primary_class.get('risk_level'),
                    'category': primary_class.get('category')
                })
        
        # Identify sensitive resources
        sensitive_resources = []
        for i, res_analysis in enumerate(resource_analyses):
            if res_analysis.get('sensitivity') in ['high', 'critical']:
                sensitive_resources.append({
                    'index': i,
                    'method': res_analysis.get('trace_method', ''),
                    'sensitivity': res_analysis.get('sensitivity'),
                    'type': res_analysis.get('type')
                })
        
        # Generate summary message
        message_parts = []
        if violations:
            message_parts.append(f"Found {len(violations)} security violations")
        if high_risk_operations:
            message_parts.append(f"{len(high_risk_operations)} high-risk operations detected")
        if sensitive_resources:
            message_parts.append(f"{len(sensitive_resources)} sensitive resources accessed")
        
        if not message_parts:
            message = "No significant security concerns detected"
        else:
            message = "; ".join(message_parts)
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'total_violations': len(violations),
            'violation_types': violation_counts,
            'high_risk_operations': high_risk_operations,
            'sensitive_resources': sensitive_resources,
            'subject_type': subject_analysis.get('type', 'unknown'),
            'trust_boundary': subject_analysis.get('trust_boundary', 'unknown'),
            'authentication_status': subject_analysis.get('authentication_status', 'unknown'),
            'total_operations': len(operation_analyses),
            'total_resources': len(resource_analyses),
            'message': message,
            'top_recommendations': relationship_analysis.get('recommendations', [])[:3]
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for SOR analysis"""
        
        metrics = {}
        
        for component, times in self.analysis_times.items():
            if times:
                metrics[component] = {
                    'avg_time_ms': sum(times) / len(times) * 1000,
                    'min_time_ms': min(times) * 1000,
                    'max_time_ms': max(times) * 1000,
                    'total_analyses': len(times)
                }
            else:
                metrics[component] = {
                    'avg_time_ms': 0,
                    'min_time_ms': 0,
                    'max_time_ms': 0,
                    'total_analyses': 0
                }
        
        return metrics
    
    def reset_performance_metrics(self):
        """Reset performance tracking metrics"""
        for component in self.analysis_times:
            self.analysis_times[component] = []