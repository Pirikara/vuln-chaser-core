#!/usr/bin/env python3
import json

# Actual response from LLM
response_content = '''```json
{
  "vulnerabilities": [
    {
      "owasp_category": "A03:2021",
      "type": "SQL Injection",
      "severity": "high",
      "confidence": 0.95,
      "affected_method": "User.find_by_sql",
      "line": 15,
      "description": "The `User.find_by_sql` method uses string interpolation (`#{params[:name]}`) to construct the SQL query. This is highly vulnerable to SQL injection attacks. An attacker can manipulate the `name` parameter to inject malicious SQL code, potentially allowing them to read, modify, or delete data from the database.",
      "recommendation": "Use parameterized queries (prepared statements) instead of string interpolation.  In Rails, this can be achieved using `where` or `sanitize` methods. For example: `User.where('name LIKE ?', \"%#{params[:name]}%\")` or `User.find_by_sql('SELECT * FROM users WHERE name LIKE ?', [params[:name].to_s])`.  The latter is preferred as it handles type conversion and escaping automatically."
    }
  ]
}
```'''

print('🔍 Debugging JSON parsing issue...')

# Extract JSON
if '```json' in response_content:
    start_marker = response_content.find('```json') + 7
    end_marker = response_content.find('```', start_marker)
    if end_marker != -1:
        json_content = response_content[start_marker:end_marker].strip()
    else:
        json_content = response_content[start_marker:].strip()
else:
    start_idx = response_content.find('{')
    end_idx = response_content.rfind('}') + 1
    json_content = response_content[start_idx:end_idx]

print('📝 Extracted JSON:')
print('-' * 40)
print(json_content)
print('-' * 40)

try:
    parsed = json.loads(json_content)
    print(f'✅ JSON parsed successfully!')
    print(f'🔍 Vulnerabilities: {len(parsed["vulnerabilities"])}')
    
    for vuln in parsed["vulnerabilities"]:
        print(f'   - {vuln["type"]} ({vuln["severity"]}) confidence: {vuln["confidence"]}')
        
except json.JSONDecodeError as e:
    print(f'❌ JSON parse error: {e}')
    print(f'Error position: {e.pos}')
    print(f'Context around error:')
    context_start = max(0, e.pos - 50)
    context_end = min(len(json_content), e.pos + 50)
    print(f'"{json_content[context_start:context_end]}"')
    print(' ' * (e.pos - context_start) + '^')