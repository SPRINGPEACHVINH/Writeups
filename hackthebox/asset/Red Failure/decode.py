import re

def decode_obfuscated_string(obfuscated_code):
    pattern = r'\(\s*"([^"]+)"\s*-f\s*([^)]+)\s*\)'
    matches = re.finditer(pattern, obfuscated_code)
    
    for match in matches:
        format_str = match.group(1)
        parts = [p.strip().strip("'") for p in match.group(2).split(',')]
        
        parts = [p.replace('`', '') for p in parts]
        
        result = ""
        for part in format_str.split('}'):
            if not part:
                continue
            index = int(part.split('{')[1])
            result += parts[index]
        
        obfuscated_code = obfuscated_code.replace(match.group(0), f'"{result}"')
    
    return obfuscated_code

def process_file(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    decoded_content = decode_obfuscated_string(content)
    
    decoded_content = decoded_content.replace('`', '')
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(decoded_content)

if __name__ == "__main__":
    input_file = "shell.txt"
    output_file = "decoded_shell.txt"
    process_file(input_file, output_file)
    print(f"Result {output_file}")