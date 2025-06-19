#!/usr/bin/env python3
import asyncio
import sys
import os
sys.path.insert(0, '.')

# Set API key
os.environ['OPENROUTER_API_KEY'] = 'dummy'

from services.vulnerability_analyzer import VulnerabilityAnalyzer

async def debug_llm_response():
    print('🔍 Debugging LLM response format...')
    
    try:
        analyzer = VulnerabilityAnalyzer()
        
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
        
        print('🤖 Building prompt and sending to LLM...')
        prompt = analyzer._build_vulnerability_prompt(test_trace)
        
        messages = [{"role": "user", "content": prompt}]
        response = await analyzer.openrouter_client.chat_completion(messages)
        
        print(f'✅ LLM response received (time: {response["response_time_ms"]}ms)')
        print('📝 Raw LLM response:')
        print('-' * 80)
        print(response["content"])
        print('-' * 80)
        
        # Try to parse
        vulnerabilities = analyzer._parse_vulnerability_response(response["content"])
        print(f'🔍 Parsed vulnerabilities: {len(vulnerabilities)}')
        
        for vuln in vulnerabilities:
            print(f'   - {vuln["type"]} ({vuln["severity"]})')
        
    except Exception as e:
        print(f'❌ Error: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_llm_response())
