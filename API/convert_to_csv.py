import json
import pandas as pd
import re

# Set your file paths
input_file = r"C:\Users\LENOVO\Desktop\Personal Project\Final Year Project\data\trainDataSet.jsonl"
output_file = r"C:\Users\LENOVO\Desktop\Personal Project\Final Year Project\data\securecode_train_updated.csv"

# List to store all flattened records
records = []

print("Reading JSONL file...")

def extract_code_blocks(text):
    """Extract code blocks from markdown text."""
    # Find all ```python ... ``` or ``` ... ``` blocks
    code_blocks = re.findall(r'```(?:\w+)?\s*\n(.*?)```', text, re.DOTALL)
    if code_blocks:
        return '\n\n'.join(code_blocks)
    return None

def extract_attack_payload(text):
    """Extract attack payload from text."""
    # Look for "Attack Payload" section
    patterns = [
        r'\*\*Attack Payload\*\*[:\s]*\n```(?:text)?\s*\n(.*?)```',
        r'Attack Payload[:\s]*\n```(?:text)?\s*\n(.*?)```',
        r'attack payload[:\s]*(.*?)(?:\n\n|\*\*|```)',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()[:2000]
    return ''

def extract_section(text, section_name):
    """Extract a named section from the text."""
    patterns = [
        rf'\*\*{section_name}\*\*[:\s]*\n```(?:\w+)?\s*\n(.*?)```',
        rf'{section_name}[:\s]*\n```(?:\w+)?\s*\n(.*?)```',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()[:5000]
    return ''

# Read JSONL line by line
with open(input_file, 'r', encoding='utf-8') as f:
    for line_num, line in enumerate(f, 1):
        if line.strip():
            try:
                item = json.loads(line)
                
                # Combine all assistant responses for extraction
                conversations = item.get('conversations', [])
                all_text = ''
                vulnerable_code = ''
                secure_code = ''
                attack_payload = ''
                
                for conv in conversations:
                    # The dataset uses 'content', NOT 'value'
                    content = conv.get('content', conv.get('value', ''))
                    
                    if conv.get('role') == 'assistant':
                        all_text += content + '\n\n'
                        
                        # Extract vulnerable code
                        if not vulnerable_code:
                            vuln = extract_section(content, 'VULNERABLE CODE')
                            if vuln:
                                vulnerable_code = vuln
                        
                        # Extract secure code
                        if not secure_code:
                            sec = extract_section(content, 'SECURE VERSION')
                            if sec:
                                secure_code = sec
                        
                        # Extract attack payload
                        if not attack_payload:
                            payload = extract_attack_payload(content)
                            if payload:
                                attack_payload = payload
                
                # If still no code found, try extracting any code blocks
                if not vulnerable_code:
                    code_blocks = extract_code_blocks(all_text)
                    if code_blocks and 'vulnerable' in all_text[:500].lower():
                        vulnerable_code = code_blocks[:5000]
                
                # Build record
                record = {
                    # Basic ID
                    'id': item.get('id', ''),
                    
                    # Flatten metadata fields
                    'category': item.get('metadata', {}).get('category', ''),
                    'owasp_2021': item.get('metadata', {}).get('owasp_2021', ''),
                    'severity': item.get('metadata', {}).get('severity', ''),
                    'cwe': item.get('metadata', {}).get('cwe', ''),
                    'language': item.get('metadata', {}).get('lang', ''),
                    'epss_score': item.get('metadata', {}).get('epss_score', ''),
                    
                    # Flatten context fields
                    'cve_id': item.get('context', {}).get('cve', ''),
                    'real_incident': item.get('context', {}).get('real_world_incident', ''),
                    'incident_year': item.get('context', {}).get('year', ''),
                    
                    # Extracted content
                    'vulnerable_code': vulnerable_code[:5000],
                    'secure_code': secure_code[:5000],
                    'attack_payload': attack_payload[:2000],
                    'conversation_text': all_text[:10000],
                    
                    # Additional metadata
                    'complexity': item.get('metadata', {}).get('complexity', ''),
                    'technique': item.get('metadata', {}).get('technique', ''),
                    'subcategory': item.get('metadata', {}).get('subcategory', ''),
                    
                    # Keep full original JSON as backup
                    'full_json': json.dumps(item)[:10000],
                }
                
                records.append(record)
                
                if line_num % 100 == 0:
                    print(f"Processed {line_num} records...")
                    
            except json.JSONDecodeError as e:
                print(f"Error on line {line_num}: {e}")
                continue

print(f"Total records processed: {len(records)}")

# Convert to DataFrame and save as CSV
df = pd.DataFrame(records)

# Quick quality check
vuln_filled = (df['vulnerable_code'].fillna('').str.len() > 50).sum()
payload_filled = (df['attack_payload'].fillna('').str.len() > 10).sum()
print(f"\n=== QUALITY CHECK ===")
print(f"vulnerable_code with content: {vuln_filled}/{len(df)}")
print(f"attack_payload with content: {payload_filled}/{len(df)}")

df.to_csv(output_file, index=False, encoding='utf-8')

print(f"\n✅ CSV saved to: {output_file}")
print(f"📊 Total rows: {len(df)}")
print(f"📋 Columns: {df.columns.tolist()}")
print(f"\nSeverity distribution:")
print(df['severity'].value_counts())