"""
ComprehensiveSecurityAnalyzer - Phase 2 Core Implementation
Agent側の生データを受け取り、LLMで包括的セキュリティ分析
パターンに依存しない柔軟で創造的な脆弱性検出
"""

import json
import logging
import asyncio
from typing import Dict, List, Any, Optional
from .openrouter_client import OpenRouterClient

logger = logging.getLogger(__name__)


class ComprehensiveSecurityAnalyzer:
    """
    Agent側の生データから包括的セキュリティ分析を実行
    パターンマッチングに依存せず、LLMの創造的分析能力を最大限活用
    """
    
    def __init__(self):
        self.llm_client = OpenRouterClient()
        self.context_builder = SecurityContextBuilder()
        
    async def analyze_security_comprehensively(self, raw_execution_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        生データから包括的セキュリティ分析
        """
        
        # LLM用の包括的コンテキスト構築
        analysis_context = self.context_builder.build_comprehensive_context(raw_execution_data)
        
        # LLMによる包括的分析
        security_analysis = await self.perform_llm_comprehensive_analysis(analysis_context)
        
        return {
            'vulnerability_findings': security_analysis['vulnerabilities'],
            'novel_patterns': security_analysis['novel_patterns_detected'],
            'attack_vectors': security_analysis['attack_vectors'],
            'business_logic_issues': security_analysis['business_logic_issues'],
            'risk_assessment': security_analysis['risk_assessment'],
            'remediation_strategy': security_analysis['remediation_strategy']
        }

    async def analyze_batch_comprehensively(self, execution_data_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        複数の実行データを並列で包括的に分析
        """
        analysis_tasks = []
        
        for execution_data in execution_data_batch:
            task = asyncio.create_task(self.analyze_security_comprehensively(execution_data))
            analysis_tasks.append(task)
        
        # 並列実行
        results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        # 結果を処理（エラーハンドリング含む）
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Analysis failed for batch item {i}: {result}")
                processed_results.append({
                    'error': str(result),
                    'vulnerability_findings': [],
                    'analysis_status': 'failed'
                })
            else:
                result['analysis_status'] = 'success'
                processed_results.append(result)
        
        return processed_results

    def build_comprehensive_context(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        生データからLLM分析用の包括的コンテキストを構築
        """
        
        return {
            'execution_overview': {
                'endpoint': raw_data.get('endpoint'),
                'method': raw_data.get('method'),
                'trace_count': len(raw_data.get('traces', []))
            },
            'code_structure': raw_data.get('code_structure', {}),
            'data_flow_analysis': self.structure_data_flow_info(raw_data.get('data_flow_info', {})),
            'external_interactions': raw_data.get('external_interactions', []),
            'semantic_structure': raw_data.get('semantic_analysis', {}),
            'execution_context': raw_data.get('execution_context', {})
        }

    def structure_data_flow_info(self, data_flow_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        データフロー情報を構造化
        """
        structured_flow = {}
        
        # データフローの各段階を分析
        if isinstance(data_flow_info, list):
            for flow in data_flow_info:
                flow_type = flow.get('flow_type', 'unknown')
                if flow_type not in structured_flow:
                    structured_flow[flow_type] = []
                structured_flow[flow_type].append(flow)
        
        return structured_flow

    async def perform_llm_comprehensive_analysis(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        LLMによる包括的セキュリティ分析
        """
        
        prompt = f"""
# COMPREHENSIVE SECURITY ANALYSIS - PATTERN-FREE APPROACH

You are an elite security researcher with expertise in application security, code analysis, and emerging threats. Analyze the following Ruby application execution trace for ALL possible security vulnerabilities.

**CRITICAL**: Do not rely on predefined vulnerability patterns. Think creatively and comprehensively about potential security issues, including novel attack vectors and business logic flaws.

## EXECUTION DATA
{json.dumps(context, indent=2)}

## ANALYSIS APPROACH

### 1. Comprehensive Vulnerability Discovery
- **Traditional Vulnerabilities**: OWASP Top 10 and beyond
- **Novel Attack Vectors**: Think outside conventional patterns  
- **Business Logic Flaws**: Analyze intended vs actual behavior
- **Data Flow Risks**: Trace all data transformations
- **Context-Specific Risks**: Consider application-specific threats
- **Framework Vulnerabilities**: Ruby/Rails specific issues
- **Dependency Risks**: Third-party library issues

### 2. Deep Code Analysis
- **Source-to-Sink Analysis**: Comprehensive data flow tracing
- **Control Flow Analysis**: Logic vulnerabilities and bypasses
- **Trust Boundary Analysis**: Privilege escalations and boundary violations
- **Input Validation Analysis**: All input sources and processing
- **Output Handling Analysis**: All output destinations and encoding
- **Error Handling Analysis**: Information disclosure and exception handling

### 3. Creative Threat Modeling
- **Multi-Step Attacks**: Complex attack chains
- **Race Conditions**: Concurrency issues
- **State Management**: Session and application state vulnerabilities
- **Configuration Issues**: Deployment and configuration vulnerabilities
- **Side-Channel Attacks**: Timing and information leakage

## OUTPUT REQUIREMENTS

Provide a comprehensive analysis in the following JSON format:

```json
{{
  "vulnerabilities": [
    {{
      "id": "unique_vulnerability_id",
      "type": "vulnerability_classification",
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0,
      "owasp_category": "A0X:2021 or Custom",
      "title": "Clear, specific vulnerability title",
      "description": "Detailed technical description",
      "attack_vector": "Specific exploitation steps",
      "business_impact": "Real-world business consequences",
      "affected_code": {{
        "method": "specific_method",
        "file": "file_path",
        "line": "line_number",
        "code_snippet": "relevant_code"
      }},
      "evidence": "Supporting evidence from trace analysis",
      "remediation": {{
        "immediate": "Immediate fix steps",
        "comprehensive": "Long-term security improvements"
      }}
    }}
  ],
  "novel_patterns_detected": [
    {{
      "pattern_type": "newly_identified_pattern",
      "description": "What makes this pattern unique",
      "security_implications": "Why this is a security concern",
      "detection_criteria": "How to identify this pattern",
      "prevalence": "How common this appears in the trace"
    }}
  ],
  "attack_vectors": [
    {{
      "vector_name": "attack_vector_name",
      "complexity": "low|medium|high",
      "prerequisites": ["required_conditions"],
      "attack_steps": ["step1", "step2", "step3"],
      "potential_impact": "impact_description",
      "detection_difficulty": "easy|medium|hard"
    }}
  ],
  "business_logic_issues": [
    {{
      "issue_type": "business_logic_vulnerability_type",
      "description": "Business logic flaw description",
      "exploitation_scenario": "How this could be abused",
      "business_impact": "Impact on business operations"
    }}
  ],
  "risk_assessment": {{
    "overall_risk_level": "critical|high|medium|low",
    "attack_surface_analysis": "Description of exposed attack surface",
    "exploitability_assessment": "How easily exploitable",
    "impact_assessment": "Potential damage evaluation",
    "threat_actor_targeting": "Who might target this"
  }},
  "remediation_strategy": {{
    "immediate_priorities": ["urgent_actions"],
    "security_architecture_improvements": ["architectural_changes"],
    "development_process_improvements": ["process_changes"],
    "monitoring_recommendations": ["detection_mechanisms"]
  }}
}}
```

## ANALYSIS GUIDELINES

1. **Be Thorough**: Examine every aspect of the execution trace
2. **Think Creatively**: Consider unconventional attack vectors
3. **Context Matters**: Understand the business context and implications
4. **Evidence-Based**: Base conclusions on actual trace evidence
5. **Actionable**: Provide specific, implementable remediation steps
6. **Future-Proof**: Consider evolving threat landscapes

Perform your analysis now, focusing on comprehensive vulnerability discovery beyond traditional patterns.
"""

        messages = [
            {"role": "system", "content": "You are a world-class security expert specializing in comprehensive application security analysis, novel vulnerability discovery, and creative threat modeling."},
            {"role": "user", "content": prompt}
        ]
        
        response = await self.llm_client.chat_completion(messages)
        
        return self.parse_comprehensive_analysis_response(response['content'])

    def parse_comprehensive_analysis_response(self, response_content: str) -> Dict[str, Any]:
        """
        LLM応答を解析して構造化データを抽出
        """
        try:
            # JSONコンテンツの抽出
            json_content = self.extract_json_from_response(response_content)
            
            if not json_content:
                logger.warning("No JSON content found in LLM response")
                return self.create_empty_analysis_result()
            
            # JSON解析
            parsed_result = json.loads(json_content)
            
            # 結果の検証と正規化
            normalized_result = self.normalize_analysis_result(parsed_result)
            
            return normalized_result
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from LLM response: {e}")
            return self.create_empty_analysis_result()
        except Exception as e:
            logger.error(f"Unexpected error parsing analysis response: {e}")
            return self.create_empty_analysis_result()

    def extract_json_from_response(self, response_content: str) -> Optional[str]:
        """
        LLM応答からJSONコンテンツを抽出
        """
        # Strategy 1: Look for ```json code blocks
        if '```json' in response_content:
            start_marker = response_content.find('```json') + 7
            end_marker = response_content.find('```', start_marker)
            if end_marker != -1:
                return response_content[start_marker:end_marker].strip()
        
        # Strategy 2: Look for JSON object boundaries
        start_idx = response_content.find('{')
        if start_idx != -1:
            # Count braces to find matching closing brace
            brace_count = 0
            end_idx = start_idx
            for i, char in enumerate(response_content[start_idx:], start_idx):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break
            
            if brace_count == 0:
                return response_content[start_idx:end_idx]
        
        return None

    def normalize_analysis_result(self, parsed_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析結果を正規化
        """
        normalized = {
            'vulnerabilities': self.normalize_vulnerabilities(parsed_result.get('vulnerabilities', [])),
            'novel_patterns_detected': parsed_result.get('novel_patterns_detected', []),
            'attack_vectors': parsed_result.get('attack_vectors', []),
            'business_logic_issues': parsed_result.get('business_logic_issues', []),
            'risk_assessment': parsed_result.get('risk_assessment', {}),
            'remediation_strategy': parsed_result.get('remediation_strategy', {})
        }
        
        return normalized

    def normalize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        脆弱性データの正規化
        """
        normalized_vulns = []
        
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            
            # 必須フィールドの検証
            if not all(field in vuln for field in ['type', 'severity', 'confidence']):
                logger.warning(f"Skipping vulnerability with missing required fields: {vuln}")
                continue
            
            # 正規化された脆弱性
            normalized_vuln = {
                'id': vuln.get('id', f"vuln_{len(normalized_vulns) + 1}"),
                'type': vuln.get('type', 'unknown_vulnerability'),
                'severity': self.normalize_severity(vuln.get('severity')),
                'confidence': self.normalize_confidence(vuln.get('confidence')),
                'owasp_category': vuln.get('owasp_category', 'Custom'),
                'title': vuln.get('title', vuln.get('type', 'Unknown Vulnerability')),
                'description': vuln.get('description', ''),
                'attack_vector': vuln.get('attack_vector', ''),
                'business_impact': vuln.get('business_impact', ''),
                'affected_code': vuln.get('affected_code', {}),
                'evidence': vuln.get('evidence', ''),
                'remediation': vuln.get('remediation', {}),
                'pattern_free_detection': True  # マーカー：パターンフリー検出による
            }
            
            normalized_vulns.append(normalized_vuln)
        
        return normalized_vulns

    def normalize_severity(self, severity: Any) -> str:
        """
        深刻度の正規化
        """
        if not isinstance(severity, str):
            return 'medium'
        
        severity_lower = severity.lower()
        valid_severities = ['critical', 'high', 'medium', 'low']
        
        if severity_lower in valid_severities:
            return severity_lower
        
        return 'medium'  # デフォルト

    def normalize_confidence(self, confidence: Any) -> float:
        """
        信頼度の正規化
        """
        try:
            conf_float = float(confidence)
            return max(0.0, min(1.0, conf_float))  # 0.0-1.0の範囲に制限
        except (ValueError, TypeError):
            return 0.5  # デフォルト

    def create_empty_analysis_result(self) -> Dict[str, Any]:
        """
        空の分析結果を作成
        """
        return {
            'vulnerabilities': [],
            'novel_patterns_detected': [],
            'attack_vectors': [],
            'business_logic_issues': [],
            'risk_assessment': {
                'overall_risk_level': 'unknown',
                'attack_surface_analysis': 'Analysis failed',
                'exploitability_assessment': 'Unable to assess',
                'impact_assessment': 'Unable to assess',
                'threat_actor_targeting': 'Unable to assess'
            },
            'remediation_strategy': {
                'immediate_priorities': ['Review code manually'],
                'security_architecture_improvements': ['Implement comprehensive security review'],
                'development_process_improvements': ['Add security testing'],
                'monitoring_recommendations': ['Implement security monitoring']
            }
        }


class SecurityContextBuilder:
    """
    セキュリティ分析用のコンテキスト構築を担当
    """
    
    def build_comprehensive_context(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        包括的なセキュリティ分析コンテキストを構築
        """
        context = {}
        
        # 実行概要
        context['execution_overview'] = self.build_execution_overview(raw_data)
        
        # コード構造分析
        context['code_analysis'] = self.build_code_analysis_context(raw_data)
        
        # データフロー分析
        context['data_flow_analysis'] = self.build_data_flow_context(raw_data)
        
        # 外部相互作用分析
        context['external_interactions'] = self.build_external_interactions_context(raw_data)
        
        # セマンティック分析
        context['semantic_analysis'] = self.build_semantic_context(raw_data)
        
        # 実行コンテキスト
        context['execution_context'] = self.build_execution_context(raw_data)
        
        return context

    def build_execution_overview(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        実行概要の構築
        """
        overview = {
            'endpoint': raw_data.get('endpoint', 'unknown'),
            'http_method': raw_data.get('method', 'unknown'),
            'total_method_calls': len(raw_data.get('traces', [])),
            'has_parameters': bool(raw_data.get('params', {})),
            'parameter_count': len(raw_data.get('params', {}))
        }
        
        # トレース情報の統計
        traces = raw_data.get('traces', [])
        if traces:
            overview['unique_files'] = len(set(trace.get('file', '') for trace in traces))
            overview['unique_methods'] = len(set(trace.get('method', '') for trace in traces))
            
            # リスクレベル分布
            risk_levels = [trace.get('risk_level', 'none') for trace in traces]
            overview['risk_distribution'] = {
                'high': risk_levels.count('high'),
                'medium': risk_levels.count('medium'),
                'low': risk_levels.count('low'),
                'none': risk_levels.count('none')
            }
        
        return overview

    def build_code_analysis_context(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        コード分析コンテキストの構築
        """
        code_structure = raw_data.get('code_structure', [])
        
        if not code_structure:
            return {'status': 'no_code_structure_available'}
        
        analysis = {
            'total_methods': len(code_structure),
            'methods_with_external_refs': 0,
            'methods_with_string_ops': 0,
            'methods_with_conditionals': 0,
            'parameter_usage_patterns': {}
        }
        
        for method_info in code_structure:
            if method_info.get('external_references'):
                analysis['methods_with_external_refs'] += 1
            
            if method_info.get('string_operations'):
                analysis['methods_with_string_ops'] += 1
            
            if method_info.get('conditional_logic'):
                analysis['methods_with_conditionals'] += 1
            
            # パラメータ使用パターンの分析
            param_usage = method_info.get('parameter_usage', {})
            if param_usage.get('uses_request_params'):
                usage_key = 'direct_interpolation' if param_usage.get('direct_interpolation') else 'safe_usage'
                analysis['parameter_usage_patterns'][usage_key] = analysis['parameter_usage_patterns'].get(usage_key, 0) + 1
        
        return analysis

    def build_data_flow_context(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        データフローコンテキストの構築
        """
        data_flow_info = raw_data.get('data_flow_info', [])
        
        if not data_flow_info:
            return {'status': 'no_data_flow_available'}
        
        flow_analysis = {
            'total_flows': len(data_flow_info),
            'input_sources': set(),
            'output_destinations': set(),
            'transformation_count': 0
        }
        
        for flow in data_flow_info:
            # 入力ソースの追跡
            if flow.get('input_sources'):
                flow_analysis['input_sources'].update(flow['input_sources'])
            
            # 出力先の追跡
            if flow.get('output_destinations'):
                flow_analysis['output_destinations'].update(flow['output_destinations'])
            
            # 変換処理の計数
            if flow.get('flow_operations'):
                flow_analysis['transformation_count'] += len(flow['flow_operations'])
        
        # setを listに変換
        flow_analysis['input_sources'] = list(flow_analysis['input_sources'])
        flow_analysis['output_destinations'] = list(flow_analysis['output_destinations'])
        
        return flow_analysis

    def build_external_interactions_context(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        外部相互作用コンテキストの構築
        """
        external_interactions = raw_data.get('external_interactions', [])
        
        if not external_interactions:
            return {'status': 'no_external_interactions'}
        
        interaction_summary = {
            'total_interactions': len(external_interactions),
            'interaction_types': {},
            'database_operations': 0,
            'file_operations': 0,
            'network_operations': 0,
            'system_operations': 0
        }
        
        for interaction in external_interactions:
            interaction_type = interaction.get('type', 'unknown')
            interaction_summary['interaction_types'][interaction_type] = interaction_summary['interaction_types'].get(interaction_type, 0) + 1
            
            # 特定のタイプのカウント
            if interaction_type == 'database_interaction':
                interaction_summary['database_operations'] += 1
            elif interaction_type == 'file_interaction':
                interaction_summary['file_operations'] += 1
            elif interaction_type == 'network_interaction':
                interaction_summary['network_operations'] += 1
            elif interaction_type == 'system_interaction':
                interaction_summary['system_operations'] += 1
        
        return interaction_summary

    def build_semantic_context(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        セマンティック分析コンテキストの構築
        """
        semantic_analysis = raw_data.get('semantic_analysis', {})
        
        if not semantic_analysis:
            return {'status': 'no_semantic_analysis'}
        
        context = {
            'control_flow_complexity': self.analyze_control_flow_complexity(semantic_analysis.get('control_flow', [])),
            'data_dependency_count': len(semantic_analysis.get('data_dependencies', [])),
            'trust_boundary_crossings': len(semantic_analysis.get('trust_boundaries', [])),
            'business_logic_patterns': self.summarize_business_logic(semantic_analysis.get('business_logic_flow', {}))
        }
        
        return context

    def build_execution_context(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        実行コンテキストの構築
        """
        execution_context = raw_data.get('execution_context', {})
        
        if not execution_context:
            return {'status': 'no_execution_context'}
        
        context = {
            'application_framework': execution_context.get('application_context', {}).get('framework', 'unknown'),
            'runtime_environment': execution_context.get('runtime_environment', {}),
            'performance_metrics': execution_context.get('performance_metrics', {}),
            'call_chain_analysis': execution_context.get('call_chain_analysis', {})
        }
        
        return context

    def analyze_control_flow_complexity(self, control_flow: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        制御フローの複雑さを分析
        """
        if not control_flow:
            return {'total_complexity': 0, 'average_complexity': 0}
        
        complexities = []
        flow_types = set()
        
        for flow in control_flow:
            complexity = flow.get('complexity', 'low')
            complexities.append(complexity)
            
            flow_type_list = flow.get('flow_type', [])
            if isinstance(flow_type_list, list):
                flow_types.update(flow_type_list)
        
        complexity_score_map = {'low': 1, 'medium': 2, 'high': 3, 'very_high': 4}
        total_score = sum(complexity_score_map.get(c, 1) for c in complexities)
        
        return {
            'total_complexity': total_score,
            'average_complexity': total_score / len(complexities) if complexities else 0,
            'unique_flow_types': list(flow_types),
            'complexity_distribution': {
                'low': complexities.count('low'),
                'medium': complexities.count('medium'),
                'high': complexities.count('high'),
                'very_high': complexities.count('very_high')
            }
        }

    def summarize_business_logic(self, business_logic: Dict[str, Any]) -> Dict[str, Any]:
        """
        ビジネスロジックフローの要約
        """
        summary = {
            'has_authentication_flow': bool(business_logic.get('authentication_flow')),
            'has_authorization_flow': bool(business_logic.get('authorization_flow')),
            'has_data_processing_flow': bool(business_logic.get('data_processing_flow')),
            'has_transaction_flow': bool(business_logic.get('transaction_flow'))
        }
        
        # 各フローの詳細カウント
        for flow_type, flow_data in business_logic.items():
            if isinstance(flow_data, list):
                summary[f'{flow_type}_count'] = len(flow_data)
        
        return summary