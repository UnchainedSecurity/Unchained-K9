from pathlib import Path
import re

parser_path = Path("/home/hollowedtemplar/sentinel/backend/app/services/parser.py")
content = parser_path.read_text()

old_extract = """def extract_json(text: str) -> list:
    try: return json.loads(text)
    except: pass
    match = re.search(r'```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try: return json.loads(match.group(1))
        except: pass
    start, end = text.find('['), text.rfind(']')
    if start != -1 and end != -1:
        try: return json.loads(text[start:end+1])
        except: pass
    return []"""

new_extract = """def extract_json(text: str) -> list:
    try: 
        res = json.loads(text)
        return res if res is not None else []
    except: pass
    match = re.search(r'```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try: 
            res = json.loads(match.group(1))
            return res if res is not None else []
        except: pass
    start, end = text.find('['), text.rfind(']')
    if start != -1 and end != -1:
        try: 
            res = json.loads(text[start:end+1])
            return res if res is not None else []
        except: pass
    return []"""

content = content.replace(old_extract, new_extract)

old_ai = """            parsed_data = extract_json(ai_text)
            if isinstance(parsed_data, dict): parsed_data = parsed_data.get("findings", parsed_data.get("results", []))
            severity_map = { (item.get("type"), item.get("value")): item.get("severity", "Unknown") for item in parsed_data if isinstance(item, dict) }"""

new_ai = """            parsed_data = extract_json(ai_text)
            if parsed_data is None: parsed_data = []
            if isinstance(parsed_data, dict): parsed_data = parsed_data.get("findings", parsed_data.get("results", []))
            if parsed_data is None: parsed_data = []
            severity_map = { (item.get("type"), item.get("value")): item.get("severity", "Unknown") for item in parsed_data if isinstance(item, dict) }"""

content = content.replace(old_ai, new_ai)

parser_path.write_text(content)
print("Parser patched.")
