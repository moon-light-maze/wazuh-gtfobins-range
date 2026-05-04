#!/usr/bin/env python3
import json
import re
import subprocess
from datetime import datetime

def quick_gtfobins_check():
    try:
        result = subprocess.run(['tail', '-n', '100', '/wazuh_logs/alerts/alerts.log'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return {"detected": False, "error": "Could not read logs"}
        
        content = result.stdout
        detected_techniques = []
        
        # Simple GTFOBins pattern detection
        patterns = {
            'awk_system': r'awk.*system\(',
            'python_os': r'python.*os\.system',
            'vim_shell': r'vim.*:!',
            'find_exec': r'find.*-exec.*sh'
        }
        
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                detected_techniques.append({
                    'technique': pattern_name,
                    'description': f'GTFOBins {pattern_name} detected'
                })
        
        return {
            "detected": len(detected_techniques) > 0,
            "detected_techniques": detected_techniques,
            "content_length": len(content),
            "method": "simple_pattern_match"
        }
        
    except Exception as e:
        return {"detected": False, "error": str(e)}

if __name__ == "__main__":
    result = quick_gtfobins_check()
    print(json.dumps(result, indent=2))
