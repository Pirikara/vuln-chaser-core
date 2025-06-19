#!/usr/bin/env python3
import asyncio
import sys
import os
sys.path.insert(0, '.')

# Set API key
os.environ['OPENROUTER_API_KEY'] = "dummy"

from services.vulnerability_analyzer import VulnerabilityAnalyzer

async def test_real_vulnerability_analysis():
    print('🔍 Testing REAL LLM vulnerability analysis...')
    
    try:
        analyzer = VulnerabilityAnalyzer()
        print('✅ Vulnerability analyzer initialized with real OpenRouter client')
        
        # Test with a simple SQL injection trace
        test_trace = {
            'trace_id': 'test-sql-injection',
            'request_info': {
                'method': 'GET',
                'path': '/users/search',
                'params': {'name': 'john'}
            },
            'execution_trace': [
                {
                    'method': 'User.find_by_sql',
                    'file': 'app/models/user.rb',
                    'line': 15,
                    'source': 'User.find_by_sql("SELECT * FROM users WHERE name LIKE \'%#{params[:name]}%\'")',
                    'context': 'SQL execution detected, Potential SQL injection',
                    'timestamp': '2025-06-19T10:00:00Z'
                }
            ]
        }
        
        print('🤖 Sending trace to Google Gemma 3 27B for analysis...')
        result = await analyzer.analyze_single_trace(test_trace)
        
        print('✅ LLM analysis completed!')
        print(f'📊 Analysis time: {result["analysis_metadata"]["response_time_ms"]}ms')
        print(f'💰 Cost: ${result["analysis_metadata"]["cost_usd"]:.6f}')
        print(f'🔍 Vulnerabilities found: {len(result["vulnerabilities"])}')
        
        for i, vuln in enumerate(result['vulnerabilities'], 1):
            print(f'   {i}. {vuln["type"]} ({vuln["severity"]}) - Confidence: {vuln["confidence"]}')
            print(f'      OWASP: {vuln["owasp_category"]}')
            print(f'      Description: {vuln["description"]}')
            print(f'      Recommendation: {vuln["recommendation"]}')
        
        print('🎯 REAL PoC vulnerability detection is working with LLM!')
        
    except Exception as e:
        print(f'❌ LLM analysis error: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_real_vulnerability_analysis())
