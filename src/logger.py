"""Logging and log parsing utilities."""

import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class LogManager:
    """Manages session logs for test execution."""
    
    def __init__(self, logs_dir: str):
        self.logs_dir = Path(logs_dir)
    
    def initialize(self):
        """Create logs directory if it doesn't exist."""
        self.logs_dir.mkdir(parents=True, exist_ok=True)
    
    def create_session_log(self, session_id: str, metadata: Dict[str, Any]) -> Path:
        """Create a new session log file with header."""
        log_path = self.logs_dir / f"session_{session_id}.log"
        header = '\n'.join([
            '=' * 80,
            f"Session ID: {session_id}",
            f"Skill: {metadata.get('skillName', 'unknown')}",
            f"Task Type: {metadata.get('taskType', 'unknown')}",
            f"Prompt: {metadata.get('prompt', '')}",
            f"Started: {datetime.now().isoformat()}",
            '=' * 80,
            ''
        ])
        log_path.write_text(header, encoding='utf-8')
        return log_path
    
    def append_log(self, session_id: str, content: str):
        """Append timestamped content to session log."""
        log_path = self.logs_dir / f"session_{session_id}.log"
        timestamp = datetime.now().isoformat()
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {content}\n")
    
    def append_raw_output(self, session_id: str, output: str):
        """Append raw output without timestamp."""
        log_path = self.logs_dir / f"session_{session_id}.log"
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(output)
    
    def finalize_log(self, session_id: str, result: Dict[str, Any]):
        """Add footer with results to session log."""
        log_path = self.logs_dir / f"session_{session_id}.log"
        
        checkpoints = result.get('checkpoints', [])
        errors = result.get('extractedErrors', [])
        
        footer_lines = [
            '',
            '=' * 80,
            f"Completed: {datetime.now().isoformat()}",
            f"Success: {result.get('success', False)}",
            f"Outcome: {result.get('outcome', '')}",
            f"Duration: {result.get('duration', 0)}ms",
            f"Retries: {result.get('retryCount', 0)}",
            '',
            'Failed Checkpoints:'
        ]
        footer_lines.extend([f"  - {cp.get('event')}: {cp.get('reason', 'unknown')}" for cp in checkpoints])
        footer_lines.append('')
        footer_lines.append('Extracted Errors:')
        footer_lines.extend([f"  - [{err.get('type')}] {err.get('message')}" for err in errors])
        footer_lines.append('=' * 80)
        
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write('\n'.join(footer_lines))
    
    def read_log(self, session_id: str) -> str:
        """Read session log content."""
        log_path = self.logs_dir / f"session_{session_id}.log"
        return log_path.read_text(encoding='utf-8')


class LogParser:
    """Parses logs to extract errors, warnings, and success indicators."""
    
    def __init__(self):
        # Error patterns with blocking flag - made more specific to avoid false positives
        self.error_patterns = [
            # Azure CLI errors - require ERROR prefix or specific context
            {'type': 'az_auth', 'pattern': r"ERROR:\s*(Please run 'az login'|No subscription found|AADSTS\d+)", 'blocking': True},
            {'type': 'az_auth', 'pattern': r"(?:^|\n)\s*(?:ERROR|FATAL|FAILED).*?(az login|not logged in)", 'blocking': True},
            {'type': 'az_auth', 'pattern': r"(?:authentication|auth)\s+(?:failed|error|required)(?:\s|$|\.)", 'blocking': True},
            {'type': 'az_subscription', 'pattern': r'ERROR:\s*(.*subscription.*not found|no active subscription)', 'blocking': True},
            {'type': 'az_resource', 'pattern': r'ERROR:\s*(.*resource.*not found|ResourceNotFound)', 'blocking': False},
            {'type': 'az_permission', 'pattern': r'ERROR:\s*(.*AuthorizationFailed|.*does not have authorization|.*permission.*denied)', 'blocking': True},
            {'type': 'az_validation', 'pattern': r'ERROR:\s*(.*validation failed|.*invalid.*parameter)', 'blocking': False},
            
            # Azure Developer CLI errors - require specific context
            {'type': 'azd_auth', 'pattern': r'(?:ERROR|FAILED).*?(azd auth login|not authenticated with azd)', 'blocking': True},
            {'type': 'azd_auth', 'pattern': r'azd:\s*ERROR.*?auth', 'blocking': True},
            {'type': 'azd_init', 'pattern': r'(?:ERROR|FAILED).*?(project not initialized|azure\.yaml not found)', 'blocking': False},
            {'type': 'azd_env', 'pattern': r'(?:ERROR|FAILED).*?(no environment selected|environment.*not found)', 'blocking': False},
            
            # Copilot CLI specific errors - look for actual error indicators
            {'type': 'copilot_tool_error', 'pattern': r'\[ERROR\].*?tool.*?(?:failed|error)', 'blocking': False},
            {'type': 'copilot_tool_error', 'pattern': r'tool\s+execution\s+failed', 'blocking': False},
            {'type': 'copilot_mcp_error', 'pattern': r'\[ERROR\].*?(?:MCP|mcp).*?(?:error|failed)', 'blocking': False},
            {'type': 'copilot_mcp_error', 'pattern': r'(?:MCP|mcp)\s+server.*?(?:error|failed|unavailable)', 'blocking': False},
            {'type': 'copilot_model_error', 'pattern': r'\[ERROR\].*?(?:model|API).*?error', 'blocking': True},
            {'type': 'copilot_model_error', 'pattern': r'(?:rate\s*limit|quota)\s*exceeded', 'blocking': True},
            {'type': 'copilot_permission', 'pattern': r'\[ERROR\].*?(?:permission|access)\s*denied', 'blocking': True},
            {'type': 'copilot_timeout', 'pattern': r'\[ERROR\].*?(?:request|operation)\s*(?:timeout|timed\s*out)', 'blocking': False},
            {'type': 'copilot_skill_error', 'pattern': r'\[ERROR\].*?skill.*?(?:failed|error)', 'blocking': False},
            
            # OAuth errors - specific to actual OAuth failures
            {'type': 'oauth_error', 'pattern': r'\[ERROR\].*?OAuth.*?(?:failed|error|required)', 'blocking': True},
            {'type': 'oauth_error', 'pattern': r'OAuth\s+authentication\s+(?:failed|required|error)', 'blocking': True},
            {'type': 'oauth_error', 'pattern': r'Failed to register OAuth client', 'blocking': True},
            
            # General errors - require error context
            {'type': 'timeout', 'pattern': r'(?:ERROR|FAILED|exceeded).*?(?:timeout|timed\s*out)', 'blocking': False},
            {'type': 'timeout', 'pattern': r'Timeout\s+after\s+\d+', 'blocking': False},
            {'type': 'network', 'pattern': r'(?:ERROR|FAILED).*?(connection refused|ECONNREFUSED|network.*error|DNS.*failed)', 'blocking': False},
            {'type': 'file_not_found', 'pattern': r'(?:ERROR|FAILED).*?(file not found|ENOENT|no such file)', 'blocking': False},
            {'type': 'permission', 'pattern': r'(?:ERROR|FAILED).*?(permission denied|EACCES)', 'blocking': True},
            {'type': 'syntax', 'pattern': r'(?:ERROR|FAILED).*?(syntax error|unexpected token|parse error)', 'blocking': False},
            {'type': 'dependency', 'pattern': r'(?:ERROR|FAILED).*?(module not found|package.*not found|dependency.*missing)', 'blocking': False},
            
            # Bicep/ARM errors - specific patterns
            {'type': 'bicep', 'pattern': r'(?:ERROR|FAILED).*?(BCP\d+|bicep.*error)', 'blocking': False},
            {'type': 'bicep', 'pattern': r'Bicep\s+(?:compilation|validation)\s+failed', 'blocking': False},
            {'type': 'arm', 'pattern': r'(?:ERROR|FAILED).*?(deployment failed|InvalidTemplate|DeploymentFailed)', 'blocking': False},
            
            # Deployment failures
            {'type': 'deployment_failed', 'pattern': r'(?:Provisioning|Deployment)\s+(?:State|state):\s*Failed', 'blocking': True},
            {'type': 'deployment_failed', 'pattern': r'azd\s+(?:provision|deploy).*?failed', 'blocking': True},
            
            # Interactive prompts that shouldn't happen in non-interactive mode
            {'type': 'interactive_prompt', 'pattern': r'(?:^|\n)\s*\?\s*(?:Press|Select|Enter|Choose)', 'blocking': True},
            {'type': 'login_prompt', 'pattern': r'(?:^|\n)\s*(?:Username|Password|Enter.*password):', 'blocking': True}
        ]
        
        # Success patterns
        self.success_patterns = [
            r'successfully (created|deployed|completed|updated|deleted)',
            r'deployment.*succeeded',
            r'operation completed',
            r'done\.',
            r'finished successfully',
            r'\[done\]',
            r'task completed',
            r'changes.*applied',
            r'file.*created',
            r'generated.*successfully'
        ]
        
        # Copilot-specific success patterns
        self.copilot_success_patterns = [
            r'tool.*completed',
            r'skill.*invoked.*successfully',
            r'mcp.*response.*received',
            r'azure.*resource.*created',
            r'bicep.*generated',
            r'terraform.*generated'
        ]
        
        # Warning patterns
        self.warning_patterns = [
            {'type': 'deprecation', 'pattern': r'(deprecated|will be removed|no longer supported)'},
            {'type': 'quota', 'pattern': r'(quota|limit.*reached|throttl)'},
            {'type': 'retry', 'pattern': r'(retrying|retry.*attempt|will retry)'}
        ]
    
    def parse_log(self, log_content: str) -> Dict[str, Any]:
        """Parse log content to extract errors, warnings, and success indicators."""
        errors = []
        warnings = []
        success_indicators = []
        
        # Extract errors
        for pattern_info in self.error_patterns:
            matches = re.findall(pattern_info['pattern'], log_content, re.IGNORECASE)
            for match in matches:
                match_str = match if isinstance(match, str) else match[0] if match else ''
                errors.append({
                    'type': pattern_info['type'],
                    'message': match_str.strip(),
                    'blocking': pattern_info.get('blocking', False),
                    'context': self._extract_context(log_content, match_str)
                })
        
        # Extract warnings
        for pattern_info in self.warning_patterns:
            matches = re.findall(pattern_info['pattern'], log_content, re.IGNORECASE)
            for match in matches:
                match_str = match if isinstance(match, str) else match[0] if match else ''
                warnings.append({
                    'type': pattern_info['type'],
                    'message': match_str.strip()
                })
        
        # Check success patterns
        for pattern in self.success_patterns + self.copilot_success_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            success_indicators.extend([m.strip() if isinstance(m, str) else m[0].strip() for m in matches])
        
        has_blocking_errors = any(e.get('blocking', False) for e in errors)
        
        return {
            'errors': errors,
            'warnings': warnings,
            'successIndicators': success_indicators,
            'hasBlockingErrors': has_blocking_errors,
            'summary': self._generate_summary(errors, warnings, success_indicators)
        }
    
    def _extract_context(self, content: str, match: str) -> str:
        """Extract surrounding context for a match."""
        if not match:
            return ''
        try:
            index = content.find(match)
            if index == -1:
                return ''
            start = max(0, index - 100)
            end = min(len(content), index + len(match) + 100)
            return content[start:end].replace('\n', ' ').strip()
        except:
            return ''
    
    def _generate_summary(self, errors: List, warnings: List, success_indicators: List) -> str:
        """Generate a summary string."""
        parts = []
        if errors:
            error_types = list(set(e['type'] for e in errors))
            parts.append(f"Errors: {len(errors)} ({', '.join(error_types)})")
        if warnings:
            parts.append(f"Warnings: {len(warnings)}")
        if success_indicators:
            parts.append(f"Success indicators: {len(success_indicators)}")
        return ' | '.join(parts) or 'No issues detected'
    
    def detect_interactive_wait(self, output: str) -> bool:
        """Detect if output is waiting for interactive input."""
        interactive_patterns = [
            r'\?\s*$',
            r':\s*$',
            r'\[y/n\]',
            r'press.*key',
            r'enter.*continue',
            r'select.*option',
            r'choose.*from',
            r'waiting for.*input'
        ]
        return any(re.search(p, output, re.IGNORECASE) for p in interactive_patterns)
