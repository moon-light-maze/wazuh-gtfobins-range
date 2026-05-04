#!/usr/bin/env python3
"""
Enhanced Wazuh GTFOBins Detection Monitor
Provides intelligent detection logic that distinguishes legitimate vs malicious binary usage
"""

import json
import re
import sys
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional


class GTFOBinsDetector:
    """Enhanced GTFOBins detection with context-aware analysis."""
    
    GTFOBINS_SIGNATURES = {
        'find_shell_exec': {
            'patterns': [
                r'find\s+.*-exec\s+(/bin/sh|/bin/bash|sh|bash)',
                r'find\s+.*-exec\s+.*\{\}\s*;\s*(sh|bash)'
            ],
            'rule_id': 100201,
            'description': 'GTFOBins: Find command shell execution',
            'severity': 'high'
        },
        'vim_shell_escape': {
            'patterns': [
                r'vim\s+.*-c\s*[\'"]?\s*!',
                r'vim.*:!\s*(sh|bash)',
                r'vim.*:shell'
            ],
            'rule_id': 100202,
            'description': 'GTFOBins: Vim shell escape technique',
            'severity': 'high'
        },
        'python_code_exec': {
            'patterns': [
                r'python3?\s+-c\s+.*os\.system',
                r'python3?\s+-c\s+.*subprocess',
                r'python3?\s+-c\s+.*__import__.*os'
            ],
            'rule_id': 100203,
            'description': 'GTFOBins: Python code execution',
            'severity': 'high'
        },
        'awk_system_exec': {
            'patterns': [
                r'awk\s+.*BEGIN\s*\{\s*system',
                r'awk\s+.*system\s*\(',
                r'awk\s+[\'"]BEGIN\{system'
            ],
            'rule_id': 100204,
            'description': 'GTFOBins: AWK system command execution',
            'severity': 'high'
        },
        'less_more_shell': {
            'patterns': [
                r'(less|more)\s+.*!\s*(sh|bash)',
                r'(less|more).*!/bin/(sh|bash)'
            ],
            'rule_id': 100205,
            'description': 'GTFOBins: Pager shell escape',
            'severity': 'medium'
        },
        'base64_decode_exec': {
            'patterns': [
                r'base64\s+-d.*\|\s*(sh|bash)',
                r'base64.*--decode.*\|\s*(sh|bash)'
            ],
            'rule_id': 100206,
            'description': 'GTFOBins: Base64 decode to shell execution',
            'severity': 'high'
        },
        'wget_curl_exec': {
            'patterns': [
                r'wget\s+.*\|\s*(sh|bash)',
                r'curl\s+.*\|\s*(sh|bash)',
                r'wget\s+.*--post-file',
                r'curl\s+.*-d\s*@'
            ],
            'rule_id': 100207,
            'description': 'GTFOBins: Download and execute or data exfiltration',
            'severity': 'high'
        }
    }
    
    def __init__(self):
        self.detection_threshold = datetime.utcnow() - timedelta(minutes=2)
    
    def analyze_command(self, command: str) -> Optional[Dict[str, Any]]:
        """Analyze a command for GTFOBins patterns."""
        command_lower = command.lower().strip()
        
        for technique, signature in self.GTFOBINS_SIGNATURES.items():
            for pattern in signature['patterns']:
                if re.search(pattern, command_lower):
                    # Additional context checking
                    if self._is_legitimate_use(command_lower, technique):
                        continue
                        
                    return {
                        'technique': technique,
                        'rule_id': signature['rule_id'],
                        'description': signature['description'],
                        'severity': signature['severity'],
                        'pattern_matched': pattern,
                        'command': command,
                        'timestamp': datetime.utcnow().isoformat()
                    }
        
        return None
    
    def _is_legitimate_use(self, command: str, technique: str) -> bool:
        """Determine if command usage appears legitimate vs GTFOBins abuse."""
        
        # Legitimate use indicators
        legitimate_contexts = {
            'find_shell_exec': [
                r'find.*-exec\s+ls',  # Find with ls is usually legitimate
                r'find.*-exec\s+rm',  # Find with rm for cleanup
                r'find.*-exec\s+cp'   # Find with cp for file operations
            ],
            'vim_shell_escape': [
                # Vim without shell escapes is legitimate
                r'^vim\s+[^:!]*$'
            ],
            'python_code_exec': [
                # Simple Python calculations are legitimate
                r'python.*-c\s*[\'"]?print',
                r'python.*-c\s*[\'"]?\d+[\+\-\*/]'
            ]
        }
        
        if technique in legitimate_contexts:
            for legit_pattern in legitimate_contexts[technique]:
                if re.search(legit_pattern, command):
                    return True
        
        return False
    
    def parse_wazuh_alerts(self, log_content: str) -> List[Dict[str, Any]]:
        """Parse Wazuh alert logs for GTFOBins-related activities."""
        alerts = []
        lines = log_content.strip().split('\n')
        
        current_alert = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # New alert detection
            if '** Alert' in line and 'Rule:' in line:
                if current_alert:
                    alerts.append(current_alert)
                
                # Extract timestamp and rule
                timestamp_match = re.search(r'(\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2})', line)
                rule_match = re.search(r'Rule: (\d+)', line)
                
                current_alert = {
                    'timestamp': timestamp_match.group(1) if timestamp_match else None,
                    'rule_id': int(rule_match.group(1)) if rule_match else None,
                    'raw_line': line,
                    'command_lines': []
                }
            
            # Capture command execution details
            elif current_alert and any(keyword in line.lower() for keyword in 
                                     ['sudo:', 'command:', 'executed', 'system(']):
                current_alert['command_lines'].append(line)
        
        if current_alert:
            alerts.append(current_alert)
        
        return alerts
    
    def check_gtfobins_detection(self, wait_seconds: int = 10) -> Dict[str, Any]:
        """Main detection check with comprehensive GTFOBins analysis."""
        try:
            # Get recent Wazuh alerts
            result = subprocess.run([
                "tail", "-n", "200", "/wazuh_logs/alerts/alerts.log"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return self._fallback_detection()
            
            # Parse alerts
            alerts = self.parse_wazuh_alerts(result.stdout)
            
            # Filter recent alerts (last 2 minutes)
            recent_alerts = []
            gtfobins_detections = []
            
            for alert in alerts:
                if alert.get('timestamp'):
                    # Check if alert is recent and GTFOBins-related
                    if self._is_gtfobins_related(alert):
                        gtfobins_detections.append(alert)
                        recent_alerts.append(alert)
            
            # Analyze command patterns in alerts
            detected_techniques = []
            for alert in recent_alerts:
                for cmd_line in alert.get('command_lines', []):
                    detection = self.analyze_command(cmd_line)
                    if detection:
                        detected_techniques.append(detection)
            
            return {
                'detected': len(gtfobins_detections) > 0,
                'total_alerts': len(alerts),
                'gtfobins_alerts': len(gtfobins_detections),
                'detected_techniques': detected_techniques,
                'alert_details': recent_alerts[:5],
                'wazuh_rules_triggered': [
                    {'rule_id': alert['rule_id'], 'description': f"Wazuh Rule {alert['rule_id']}"}
                    for alert in gtfobins_detections if alert.get('rule_id')
                ],
                'method': 'enhanced_gtfobins_analysis',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'detected': False,
                'error': str(e),
                'method': 'detection_failed',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _is_gtfobins_related(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is related to GTFOBins techniques."""
        alert_text = ' '.join([
            str(alert.get('raw_line', '')),
            ' '.join(alert.get('command_lines', []))
        ]).lower()
        
        # GTFOBins indicators
        indicators = [
            'find.*-exec.*sh', 'vim.*:!', 'awk.*system', 'python.*-c.*os',
            'less.*!', 'more.*!', 'base64.*-d', 'wget.*|.*sh', 'curl.*|.*sh'
        ]
        
        return any(re.search(pattern, alert_text) for pattern in indicators)
    
    def _fallback_detection(self) -> Dict[str, Any]:
        """Fallback detection method when primary method fails."""
        return {
            'detected': False,
            'error': 'Could not access Wazuh logs',
            'method': 'fallback_failed',
            'timestamp': datetime.utcnow().isoformat()
        }


def main():
    """CLI interface for the GTFOBins detector."""
    if len(sys.argv) < 2:
        print("Usage: python3 wazuh_gtfobin_monitor.py <analyze|test> [wait_seconds]")
        sys.exit(1)
    
    command = sys.argv[1]
    wait_seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    detector = GTFOBinsDetector()
    
    if command == "analyze":
        result = detector.check_gtfobins_detection(wait_seconds)
        print(json.dumps(result, indent=2))
    
    elif command == "test":
        # Test pattern matching
        test_commands = [
            "sudo find /tmp -exec /bin/sh \\;",
            "vim -c ':!/bin/bash'", 
            "python3 -c 'import os; os.system(\"/bin/bash\")'",
            "awk 'BEGIN {system(\"/bin/sh\")}'"
        ]
        
        for cmd in test_commands:
            detection = detector.analyze_command(cmd)
            if detection:
                print(f"DETECTED: {cmd}")
                print(f"  Technique: {detection['technique']}")
                print(f"  Rule: {detection['rule_id']}")
                print(f"  Description: {detection['description']}")
            else:
                print(f"NOT DETECTED: {cmd}")
            print()


if __name__ == "__main__":
    main()