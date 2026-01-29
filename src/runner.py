"""Copilot CLI execution runner."""

import os
import re
import sys
import json
import uuid
import asyncio
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

from .logger import LogManager, LogParser


class CopilotCliRunner:
    """Runs Copilot CLI commands and analyzes results."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logs_dir = Path(config.get('logsDir') or Path(config.get('resultsDir', 'results')) / 'logs')
        self.log_manager = LogManager(str(self.logs_dir))
        self.log_parser = LogParser()
        self.active_sessions: Dict[str, Any] = {}
        
        # Event callbacks
        self.on_started: Optional[Callable] = None
        self.on_output: Optional[Callable] = None
    
    def initialize(self):
        """Initialize the runner."""
        self.log_manager.initialize()
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Pre-run auth check
        auth_config = self.config.get('authInheritance', {})
        if auth_config.get('preRunCheck', False):
            self._verify_azure_auth(auth_config)
    
    def _verify_azure_auth(self, auth_config: Dict[str, Any]):
        """Verify Azure authentication before running."""
        if auth_config.get('requireAzLogin', False):
            try:
                result = subprocess.run(
                    ['az', 'account', 'show'],
                    capture_output=True, text=True, timeout=10,
                    shell=True  # Required on Windows for .cmd files
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        "Azure CLI not authenticated. Run 'az login' before starting evaluation."
                    )
            except FileNotFoundError:
                raise RuntimeError("Azure CLI not installed. Install from https://aka.ms/installazurecli")
        
        if auth_config.get('requireAzdLogin', False):
            try:
                result = subprocess.run(
                    ['azd', 'auth', 'login', '--check-status'],
                    capture_output=True, text=True, timeout=10,
                    shell=True  # Required on Windows for .cmd files
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        "Azure Developer CLI not authenticated. Run 'azd auth login' before starting."
                    )
            except FileNotFoundError:
                pass  # AZD is optional
    
    def build_environment(self) -> Dict[str, str]:
        """Build environment variables for non-interactive mode."""
        env = os.environ.copy()
        
        non_interactive = self.config.get('nonInteractive', {})
        if non_interactive.get('enabled', True):
            # Azure CLI defaults
            if non_interactive.get('azDefaults'):
                env.update(non_interactive['azDefaults'])
            
            # Azure Developer CLI defaults
            if non_interactive.get('azdDefaults'):
                env.update(non_interactive['azdDefaults'])
            
            # Common non-interactive settings
            env['CI'] = 'true'
            env['NONINTERACTIVE'] = '1'
        
        # Ensure Azure auth env vars are inherited
        auth_config = self.config.get('authInheritance', {})
        for var in auth_config.get('envVarsToInherit', []):
            if var in os.environ:
                env[var] = os.environ[var]
        
        return env
    
    def build_copilot_command(self, prompt: str, session_id: str) -> Dict[str, Any]:
        """Build Copilot CLI command with debug options."""
        session_log_dir = self.logs_dir / f"copilot_{session_id}"
        
        copilot_path = self.config.get('copilotCliPath', 'copilot')
        opts = self.config.get('copilotOptions', {})
        
        args = [copilot_path, '-p', prompt]
        
        # Model selection
        model = opts.get('model')
        if model:
            args.extend(['--model', model])
        
        # Debug logging
        if opts.get('logLevel'):
            args.extend(['--log-level', opts['logLevel']])
        args.extend(['--log-dir', str(session_log_dir)])
        
        # Non-interactive options
        if opts.get('allowAllTools', True):
            args.append('--allow-all-tools')
        if opts.get('noAskUser', True):
            args.append('--no-ask-user')
        if opts.get('noColor', True):
            args.append('--no-color')
        if opts.get('silent', False):
            args.append('--silent')
        
        # Share session output
        share_path = self.logs_dir / f"session_{session_id}_output.md"
        args.extend(['--share', str(share_path)])
        
        return {
            'args': args,
            'command': ' '.join(f'"{a}"' if ' ' in a else a for a in args),
            'sessionLogDir': session_log_dir,
            'model': model or 'default'
        }
    
    def run_prompt(
        self,
        skill_name: str,
        task_type: str,
        prompt: str,
        work_dir: str,
        retry_count: int = 0
    ) -> Dict[str, Any]:
        """Run a prompt and return the result."""
        session_id = str(uuid.uuid4())
        start_time = datetime.now()
        checkpoints = []
        output = ''
        success = False
        outcome = ''
        extracted_errors = []
        copilot_logs = None
        
        # Initialize logging
        self.log_manager.create_session_log(session_id, {
            'skillName': skill_name,
            'taskType': task_type,
            'prompt': prompt
        })
        
        try:
            checkpoints.append({'time': datetime.now().isoformat(), 'event': 'started', 'status': 'ok'})
            
            if self.on_started:
                self.on_started({'sessionId': session_id, 'skillName': skill_name, 'prompt': prompt})
            
            self.log_manager.append_log(session_id, 'EVENT: Started execution')
            
            # Build command
            cmd_info = self.build_copilot_command(prompt, session_id)
            self.log_manager.append_log(session_id, f"COMMAND: {cmd_info['command']}")
            
            # Create copilot log directory
            cmd_info['sessionLogDir'].mkdir(parents=True, exist_ok=True)
            
            # Execute command
            env = self.build_environment()
            timeout = self.config.get('timeoutSeconds', 300)
            
            try:
                # Use Popen for real-time output streaming
                process = subprocess.Popen(
                    cmd_info['args'],
                    cwd=work_dir,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    shell=(sys.platform == 'win32')
                )
                
                output_lines = []
                start = datetime.now()
                
                while True:
                    # Check timeout
                    elapsed = (datetime.now() - start).total_seconds()
                    if elapsed > timeout:
                        process.kill()
                        checkpoints.append({
                            'time': datetime.now().isoformat(),
                            'event': 'timeout',
                            'status': 'failed',
                            'reason': f'Timeout after {timeout}s'
                        })
                        break
                    
                    line = process.stdout.readline()
                    if line:
                        output_lines.append(line)
                        # Stream to callback for real-time display
                        if self.on_output:
                            self.on_output({'data': line})
                    elif process.poll() is not None:
                        # Process finished
                        break
                
                # Get any remaining output
                remaining = process.stdout.read()
                if remaining:
                    output_lines.append(remaining)
                    if self.on_output:
                        self.on_output({'data': remaining})
                
                output = ''.join(output_lines)
                exit_code = process.returncode or 0
                
            except Exception as e:
                output = str(e)
                exit_code = -1
                checkpoints.append({
                    'time': datetime.now().isoformat(),
                    'event': 'execution_error',
                    'status': 'failed',
                    'reason': str(e)
                })
            
            # Log output
            self.log_manager.append_log(session_id, '\n--- RAW OUTPUT START ---')
            self.log_manager.append_raw_output(session_id, output)
            self.log_manager.append_log(session_id, '--- RAW OUTPUT END ---\n')
            
            checkpoints.append({
                'time': datetime.now().isoformat(),
                'event': 'execution_complete',
                'status': 'ok',
                'exitCode': exit_code
            })
            
            if self.on_output:
                self.on_output({'data': output})
            
            # Parse stdout for errors
            stdout_analysis = self.log_parser.parse_log(output)
            
            # Collect Copilot debug logs
            copilot_logs = self.collect_copilot_logs(cmd_info['sessionLogDir'])
            
            self.log_manager.append_log(
                session_id,
                f"EVENT: Collected {len(copilot_logs['files'])} Copilot debug log files"
            )
            
            # Comprehensive analysis with smart success detection
            analysis = self.comprehensive_analysis(stdout_analysis, copilot_logs, output)
            success = analysis['success']
            outcome = analysis['outcome']
            extracted_errors = analysis['allErrors']
            alerts = analysis.get('alerts', [])
            
            # Only add checkpoint for truly blocking errors (not reclassified alerts)
            critical_blocking = [e for e in extracted_errors if e.get('blocking') and not e.get('reclassified')]
            if critical_blocking:
                checkpoints.append({
                    'time': datetime.now().isoformat(),
                    'event': 'blocking_error_detected',
                    'status': 'failed',
                    'reason': analysis['reason']
                })
            
            if not success:
                checkpoints.append({
                    'time': datetime.now().isoformat(),
                    'event': 'analysis_failed',
                    'status': 'failed',
                    'reason': analysis['reason']
                })
            
            self.log_manager.append_log(
                session_id,
                f"EVENT: Analysis complete - Success: {success}, Outcome: {outcome}"
            )
            
        except Exception as e:
            checkpoints.append({
                'time': datetime.now().isoformat(),
                'event': 'error',
                'status': 'failed',
                'reason': str(e)
            })
            outcome = f"Error: {str(e)}"
            success = False
            self.log_manager.append_log(session_id, f"ERROR: {str(e)}")
            
            # Check for retry
            max_retries = self.config.get('maxRetries', 2)
            if retry_count < max_retries and not self._is_non_retryable_error(str(e)):
                checkpoints.append({
                    'time': datetime.now().isoformat(),
                    'event': 'retry_scheduled',
                    'status': 'pending',
                    'attempt': retry_count + 1
                })
                self.log_manager.append_log(
                    session_id,
                    f"EVENT: Scheduling retry {retry_count + 1}/{max_retries}"
                )
                return self.run_prompt(skill_name, task_type, prompt, work_dir, retry_count + 1)
        
        end_time = datetime.now()
        duration = int((end_time - start_time).total_seconds() * 1000)
        
        # Ensure we have copilot logs
        if copilot_logs is None:
            cmd_info = self.build_copilot_command(prompt, session_id)
            copilot_logs = self.collect_copilot_logs(cmd_info['sessionLogDir'])
        
        result = {
            'sessionId': session_id,
            'skillName': skill_name,
            'taskType': task_type,
            'prompt': prompt,
            'model': copilot_logs.get('model') or cmd_info.get('model', 'unknown'),
            'outcome': outcome,
            'success': success,
            'checkpoints': [cp for cp in checkpoints if cp['status'] == 'failed'],
            'extractedErrors': extracted_errors,
            'alerts': alerts,  # Non-blocking issues that didn't prevent success
            'toolCalls': copilot_logs.get('toolCalls', []),
            'skillInvocations': copilot_logs.get('skillInvocations', []),
            'tokenUsage': copilot_logs.get('tokenUsage', {}),
            'retryCount': retry_count,
            'duration': duration,
            'output': output[:10000],
            'logFile': str(self.logs_dir / f"session_{session_id}.log"),
            'copilotLogDir': str(cmd_info['sessionLogDir']),
            'copilotLogs': {
                'fileCount': len(copilot_logs.get('files', [])),
                'errorCount': len(copilot_logs.get('errors', [])),
                'warningCount': len(copilot_logs.get('warnings', [])),
                'successIndicatorCount': len(copilot_logs.get('successIndicators', []))
            },
            'artifacts': self._extract_artifacts(output, copilot_logs),
            'timestamp': datetime.now().isoformat()
        }
        
        # Finalize log
        self.log_manager.append_log(session_id, '\n--- COPILOT DEBUG LOGS ---')
        self.log_manager.append_log(session_id, f"Model: {result['model']}")
        token_usage = copilot_logs.get('tokenUsage', {})
        self.log_manager.append_log(
            session_id,
            f"Token Usage: input={token_usage.get('inputTokens', 0)}, "
            f"output={token_usage.get('outputTokens', 0)}, "
            f"total={token_usage.get('totalTokens', 0)}"
        )
        self.log_manager.append_log(session_id, '--- END COPILOT DEBUG LOGS ---\n')
        self.log_manager.finalize_log(session_id, result)
        
        return result
    
    def collect_copilot_logs(self, log_dir: Path) -> Dict[str, Any]:
        """Collect and parse Copilot debug logs."""
        result = {
            'files': [],
            'errors': [],
            'warnings': [],
            'successIndicators': [],
            'hasBlockingErrors': False,
            'toolCalls': [],
            'skillInvocations': [],
            'tokenUsage': {
                'inputTokens': 0,
                'outputTokens': 0,
                'totalTokens': 0,
                'cacheReadTokens': 0,
                'cacheWriteTokens': 0
            },
            'model': None
        }
        
        if not log_dir.exists():
            return result
        
        try:
            for file_path in log_dir.iterdir():
                if file_path.suffix in ['.log', '.json', '.txt', '.md']:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        result['files'].append({
                            'name': file_path.name,
                            'path': str(file_path),
                            'content': content,
                            'size': len(content)
                        })
                        
                        # Parse for errors
                        analysis = self.log_parser.parse_log(content)
                        
                        if analysis['errors']:
                            for err in analysis['errors']:
                                err['source'] = file_path.name
                            result['errors'].extend(analysis['errors'])
                        
                        if analysis['warnings']:
                            for warn in analysis['warnings']:
                                warn['source'] = file_path.name
                            result['warnings'].extend(analysis['warnings'])
                        
                        if analysis['successIndicators']:
                            result['successIndicators'].extend(analysis['successIndicators'])
                        
                        if analysis['hasBlockingErrors']:
                            result['hasBlockingErrors'] = True
                        
                        # Extract tool calls from JSON
                        if file_path.suffix == '.json':
                            tool_calls = self._extract_tool_calls(content)
                            result['toolCalls'].extend(tool_calls)
                        
                        # Extract skill invocations
                        skills = self._extract_skill_invocations(content)
                        result['skillInvocations'].extend(skills)
                        
                        # Extract token usage
                        tokens = self._extract_token_usage(content)
                        result['tokenUsage']['inputTokens'] += tokens['inputTokens']
                        result['tokenUsage']['outputTokens'] += tokens['outputTokens']
                        result['tokenUsage']['totalTokens'] += tokens['totalTokens']
                        result['tokenUsage']['cacheReadTokens'] += tokens['cacheReadTokens']
                        result['tokenUsage']['cacheWriteTokens'] += tokens['cacheWriteTokens']
                        
                        # Extract model info
                        if not result['model']:
                            result['model'] = self._extract_model_info(content)
                        
                    except Exception:
                        pass
        except Exception:
            pass
        
        return result
    
    def _extract_tool_calls(self, content: str) -> List[Dict]:
        """Extract tool calls from JSON content."""
        tool_calls = []
        try:
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if any(k in obj for k in ['tool', 'toolName', 'function']):
                        tool_calls.append({
                            'name': obj.get('tool') or obj.get('toolName') or obj.get('function', {}).get('name'),
                            'status': obj.get('status') or obj.get('result', {}).get('status', 'unknown'),
                            'error': obj.get('error') or obj.get('result', {}).get('error'),
                            'duration': obj.get('duration') or obj.get('elapsed')
                        })
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        return tool_calls
    
    def _extract_skill_invocations(self, content: str) -> List[Dict]:
        """Extract skill invocations from content."""
        skills = []
        pattern = r'skill[:\s]+["\']?([a-z\-]+)["\']?'
        for match in re.finditer(pattern, content, re.IGNORECASE):
            skills.append({
                'name': match.group(1),
                'context': content[max(0, match.start() - 50):match.end() + 50]
            })
        return skills
    
    def _extract_token_usage(self, content: str) -> Dict[str, int]:
        """Extract token usage from content."""
        usage = {
            'inputTokens': 0,
            'outputTokens': 0,
            'totalTokens': 0,
            'cacheReadTokens': 0,
            'cacheWriteTokens': 0
        }
        
        # Direct field matching for JSON format (handles multiline)
        # prompt_tokens / input_tokens
        for match in re.finditer(r'"(?:prompt_tokens|input_tokens)"\s*:\s*(\d+)', content, re.IGNORECASE):
            usage['inputTokens'] += int(match.group(1))
        
        # completion_tokens / output_tokens  
        for match in re.finditer(r'"(?:completion_tokens|output_tokens)"\s*:\s*(\d+)', content, re.IGNORECASE):
            usage['outputTokens'] += int(match.group(1))
        
        # total_tokens
        for match in re.finditer(r'"total_tokens"\s*:\s*(\d+)', content, re.IGNORECASE):
            usage['totalTokens'] += int(match.group(1))
        
        # cached_tokens
        for match in re.finditer(r'"cached_tokens"\s*:\s*(\d+)', content, re.IGNORECASE):
            usage['cacheReadTokens'] += int(match.group(1))
        
        # Log format: "Tokens: input=123, output=456"
        pattern2 = r'tokens?[:\s]+(?:input|prompt)\s*[=:]\s*(\d+)[,\s]+(?:output|completion)\s*[=:]\s*(\d+)'
        for match in re.finditer(pattern2, content, re.IGNORECASE):
            usage['inputTokens'] += int(match.group(1))
            usage['outputTokens'] += int(match.group(2))
        
        # Stats format: "Input: 1,234 tokens | Output: 567 tokens"
        pattern6 = r'input[:\s]+([0-9,]+)\s*tokens?[^|]*\|\s*output[:\s]+([0-9,]+)\s*tokens?'
        for match in re.finditer(pattern6, content, re.IGNORECASE):
            usage['inputTokens'] += int(match.group(1).replace(',', ''))
            usage['outputTokens'] += int(match.group(2).replace(',', ''))
        
        # Calculate total if not found from total_tokens field
        if usage['totalTokens'] == 0 and (usage['inputTokens'] > 0 or usage['outputTokens'] > 0):
            usage['totalTokens'] = usage['inputTokens'] + usage['outputTokens']
        
        return usage
    
    def _extract_model_info(self, content: str) -> Optional[str]:
        """Extract model name from content."""
        # JSON format
        match = re.search(r'"model"\s*:\s*"([^"]+)"', content, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Log format
        match = re.search(r'(?:model|using model)[:\s]+([a-z0-9\-\.]+)', content, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Known model names
        model_names = [
            'claude-sonnet-4.5', 'claude-haiku-4.5', 'claude-opus-4.5', 'claude-sonnet-4',
            'gemini-3-pro-preview',
            'gpt-5.2-codex', 'gpt-5.2', 'gpt-5.1-codex-max', 'gpt-5.1-codex', 'gpt-5.1',
            'gpt-5', 'gpt-5.1-codex-mini', 'gpt-5-mini', 'gpt-4.1'
        ]
        for model in model_names:
            if model.lower() in content.lower():
                return model
        
        return None
    
    def comprehensive_analysis(
        self,
        stdout_analysis: Dict[str, Any],
        copilot_logs: Dict[str, Any],
        output: str = ''
    ) -> Dict[str, Any]:
        """Combine stdout and Copilot log analysis with smart success detection."""
        result = {
            'success': False,
            'outcome': '',
            'reason': '',
            'allErrors': [],
            'allWarnings': [],
            'alerts': [],  # Non-blocking issues that didn't prevent success
            'successIndicators': [],
            'hasStrongSuccess': False
        }
        
        # Combine errors and warnings
        result['allErrors'] = stdout_analysis.get('errors', []) + copilot_logs.get('errors', [])
        result['allWarnings'] = stdout_analysis.get('warnings', []) + copilot_logs.get('warnings', [])
        result['successIndicators'] = (
            stdout_analysis.get('successIndicators', []) +
            copilot_logs.get('successIndicators', [])
        )
        
        # Check for STRONG success indicators that override errors
        # These indicate the actual task completed successfully
        strong_success = self._check_strong_success(output, copilot_logs)
        result['hasStrongSuccess'] = strong_success['has_strong_success']
        
        if strong_success['has_strong_success']:
            # Task actually succeeded - errors become alerts
            result['success'] = True
            
            # Move blocking errors to alerts (they didn't actually block success)
            blocking_errors = [e for e in result['allErrors'] if e.get('blocking')]
            non_blocking_errors = [e for e in result['allErrors'] if not e.get('blocking')]
            
            # Reclassify - these errors didn't prevent success, so they're alerts
            for err in blocking_errors:
                err['reclassified'] = True
                err['original_blocking'] = True
                err['blocking'] = False
            
            result['alerts'] = blocking_errors
            result['allErrors'] = non_blocking_errors
            result['allWarnings'].extend([
                {'type': 'alert', 'message': f"[{e['type']}] {e['message']}", 'original_error': e}
                for e in blocking_errors
            ])
            
            if blocking_errors:
                result['outcome'] = 'Success with alerts'
                result['reason'] = f"Task completed successfully. {len(blocking_errors)} non-critical alert(s): {strong_success['reason']}"
            else:
                result['outcome'] = 'Completed successfully'
                result['reason'] = strong_success['reason']
            
            return result
        
        # No strong success - apply normal error analysis
        has_blocking = (
            stdout_analysis.get('hasBlockingErrors', False) or
            copilot_logs.get('hasBlockingErrors', False)
        )
        
        # Filter out non-critical errors that commonly appear but don't affect deployment
        critical_blocking = self._filter_critical_errors(result['allErrors'])
        
        if critical_blocking:
            result['success'] = False
            result['outcome'] = 'Failed - blocking errors detected'
            result['reason'] = '; '.join(
                f"[{e['type']}] {e['message']}" for e in critical_blocking[:3]
            )
            return result
        
        # Check tool call failures
        failed_tools = [
            t for t in copilot_logs.get('toolCalls', [])
            if t.get('status') in ['failed', 'error'] or t.get('error')
        ]
        if failed_tools:
            result['success'] = False
            result['outcome'] = 'Failed - tool execution errors'
            result['reason'] = '; '.join(
                f"Tool {t['name']}: {t.get('error') or t['status']}" for t in failed_tools[:3]
            )
            return result
        
        # Success with indicators and no critical errors
        if result['successIndicators'] and not critical_blocking:
            result['success'] = True
            result['outcome'] = 'Completed successfully'
            result['reason'] = f"Found success indicators: {', '.join(result['successIndicators'][:2])}"
            return result
        
        # No errors
        if not result['allErrors']:
            result['success'] = True
            result['outcome'] = 'Completed with output'
            result['reason'] = 'No errors detected'
            return result
        
        # Has non-blocking errors only
        if not critical_blocking:
            result['success'] = True
            result['outcome'] = 'Completed with warnings'
            result['alerts'] = result['allErrors']
            result['reason'] = f"Completed with {len(result['allErrors'])} warning(s)"
            return result
        
        # Has blocking errors
        result['success'] = False
        result['outcome'] = 'Failed - errors detected'
        result['reason'] = '; '.join(
            f"[{e['type']}] {e['message']}" for e in result['allErrors'][:3]
        )
        return result
    
    def _check_strong_success(self, output: str, copilot_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Check for strong success indicators that prove the task completed."""
        indicators = []
        
        # Combine all content
        all_content = output
        for log_file in copilot_logs.get('files', []):
            all_content += '\n' + log_file.get('content', '')
        
        # 1. Check for deployed Azure URLs with health check success
        azure_url_patterns = [
            r'https://[a-z0-9\-]+\.azurewebsites\.net',
            r'https://[a-z0-9\-]+\.azurestaticapps\.net',
            r'https://[a-z0-9\-]+\.[a-z0-9\-]+\.azurecontainerapps\.io',
        ]
        
        deployed_urls = []
        for pattern in azure_url_patterns:
            matches = re.findall(pattern, all_content, re.IGNORECASE)
            deployed_urls.extend(matches)
        
        # 2. Check for explicit deployment success messages
        deployment_success_patterns = [
            r'(?:deployment|deploy)\s+(?:succeeded|successful|completed|done)',
            r'successfully\s+deployed',
            r'✅.*(?:deployed|success|complete)',
            r'deployment\s+successful',
            r'app\s+is\s+(?:now\s+)?(?:live|running|deployed)',
            r'azd\s+up.*(?:succeeded|completed)',
            r'Provisioning\s+State:\s*Succeeded',
            r'(?:health|status)[:\s]+(?:✅|healthy|ok|running)',
        ]
        
        for pattern in deployment_success_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                indicators.append(f"Deployment success pattern: {pattern[:30]}")
        
        # 3. Check for health check responses
        health_patterns = [
            r'"status"\s*:\s*"(?:healthy|ok|running)"',
            r'Health.*(?:✅|healthy|ok)',
            r'api/health.*(?:200|ok|healthy)',
        ]
        
        for pattern in health_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                indicators.append("Health check passed")
                break
        
        # 4. Check for azd up success
        if re.search(r'azd\s+up.*SUCCESS|Deployment\s+completed', all_content, re.IGNORECASE):
            indicators.append("AZD deployment succeeded")
        
        # 5. Check for resource creation confirmation
        resource_patterns = [
            r'(?:created|provisioned)\s+(?:resource\s+group|app\s+service|web\s+app|container\s+app)',
            r'Microsoft\.[A-Za-z]+/[a-zA-Z]+.*(?:created|succeeded)',
        ]
        
        for pattern in resource_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                indicators.append("Azure resources created")
                break
        
        # Determine if we have strong success
        has_strong_success = (
            (len(deployed_urls) > 0 and len(indicators) >= 1) or  # URL + at least one success indicator
            len(indicators) >= 2  # Multiple success indicators
        )
        
        reason = ''
        if has_strong_success:
            reasons = []
            if deployed_urls:
                reasons.append(f"Deployed to {deployed_urls[0]}")
            reasons.extend(indicators[:2])
            reason = '; '.join(reasons)
        
        return {
            'has_strong_success': has_strong_success,
            'deployed_urls': list(set(deployed_urls)),
            'indicators': indicators,
            'reason': reason
        }
    
    def _filter_critical_errors(self, errors: List[Dict]) -> List[Dict]:
        """Filter to only truly critical errors that block task completion."""
        # These error types are often noise and don't actually block deployment
        non_critical_types = [
            'oauth_error',  # OAuth for MCP servers often fails but doesn't block Azure deployment
            'copilot_mcp_error',  # MCP errors may not affect the actual task
            'copilot_skill_error',  # Skill errors may be retried or worked around
        ]
        
        # These error messages are often false positives
        non_critical_patterns = [
            r'github-mcp-server',  # GitHub MCP auth doesn't affect Azure deployment
            r'mcp.*oauth',  # MCP OAuth issues
            r'initiating\s+oauth\s+flow',  # OAuth flow attempts
        ]
        
        critical = []
        for err in errors:
            if not err.get('blocking'):
                continue
            
            # Skip non-critical types
            if err.get('type') in non_critical_types:
                continue
            
            # Skip non-critical patterns
            msg = err.get('message', '').lower()
            context = err.get('context', '').lower()
            combined = msg + ' ' + context
            
            is_non_critical = any(
                re.search(pattern, combined, re.IGNORECASE) 
                for pattern in non_critical_patterns
            )
            
            if is_non_critical:
                continue
            
            critical.append(err)
        
        return critical
    
    def _is_non_retryable_error(self, error_message: str) -> bool:
        """Check if error should not trigger a retry."""
        non_retryable = [
            'authentication',
            'login required',
            'permission denied',
            'not authorized',
            'invalid credentials',
            'subscription not found',
            'quota exceeded'
        ]
        return any(e in error_message.lower() for e in non_retryable)
    
    def _extract_artifacts(self, output: str, copilot_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Extract success artifacts from output and logs."""
        artifacts = {
            'deployedUrls': [],
            'createdResources': [],
            'generatedFiles': [],
            'azureResourceIds': [],
            'connectionStrings': [],
            'endpoints': [],
            'skillsUsed': [],
            'toolsInvoked': [],
            'mcpToolsUsed': []
        }
        
        # Combine output with copilot log content
        all_content = output
        for log_file in copilot_logs.get('files', []):
            all_content += '\n' + log_file.get('content', '')
        
        # Extract deployed URLs
        artifacts['deployedUrls'] = self._extract_urls(all_content)
        
        # Extract created Azure resources
        artifacts['createdResources'] = self._extract_resources(all_content)
        
        # Extract generated files/reports
        artifacts['generatedFiles'] = self._extract_generated_files(all_content)
        
        # Extract Azure resource IDs
        artifacts['azureResourceIds'] = self._extract_resource_ids(all_content)
        
        # Extract endpoints
        artifacts['endpoints'] = self._extract_endpoints(all_content)
        
        # Extract skills and tools used
        artifacts['skillsUsed'] = self._extract_skills_used(all_content)
        artifacts['toolsInvoked'] = self._extract_tools_invoked(all_content)
        artifacts['mcpToolsUsed'] = self._extract_mcp_tools(all_content)
        
        return artifacts
    
    def _extract_skills_used(self, content: str) -> List[Dict[str, str]]:
        """Extract Copilot skills that were invoked."""
        skills = []
        seen = set()
        
        # Pattern for skill invocations: skill(skill-name)
        skill_pattern = r'skill\(([a-z0-9\-_]+)\)'
        for match in re.finditer(skill_pattern, content, re.IGNORECASE):
            skill_name = match.group(1)
            if skill_name not in seen:
                seen.add(skill_name)
                skills.append({
                    'name': skill_name,
                    'type': self._get_skill_type(skill_name),
                    'context': self._get_context(content, match.start(), 50)
                })
        
        return skills
    
    def _get_skill_type(self, skill_name: str) -> str:
        """Categorize skill by name."""
        if 'deploy' in skill_name:
            return 'Deployment'
        elif 'diagnostic' in skill_name or 'troubleshoot' in skill_name:
            return 'Diagnostics'
        elif 'security' in skill_name or 'keyvault' in skill_name:
            return 'Security'
        elif 'ai' in skill_name or 'foundry' in skill_name:
            return 'AI/ML'
        elif 'storage' in skill_name or 'cosmos' in skill_name or 'sql' in skill_name:
            return 'Data'
        elif 'network' in skill_name:
            return 'Networking'
        else:
            return 'General'
    
    def _extract_tools_invoked(self, content: str) -> List[Dict[str, Any]]:
        """Extract Copilot tools that were invoked (powershell, view, create, edit, etc.)."""
        tools = []
        tool_counts = {}
        
        # Pattern for tool invocations shown in logs: ● ToolName or ● tool_name(params)
        # Common tools: view, create, edit, powershell, grep, glob, skill, task
        tool_patterns = [
            (r'● (List directory [^\n]+)', 'view', 'directory listing'),
            (r'● (Read [^\n]+)', 'view', 'file read'),
            (r'● (Create [^\n]+)', 'create', 'file create'),
            (r'● (Edit [^\n]+)', 'edit', 'file edit'),
            (r'● (Check [^\n]+)', 'powershell', 'check command'),
            (r'● (Deploy [^\n]+)', 'powershell', 'deployment'),
            (r'● (Verify [^\n]+)', 'powershell', 'verification'),
            (r'● (Run [^\n]+)', 'powershell', 'execution'),
            (r'● (Install [^\n]+)', 'powershell', 'installation'),
            (r'● skill\(([^\)]+)\)', 'skill', 'skill invocation'),
        ]
        
        for pattern, tool_type, action_type in tool_patterns:
            for match in re.finditer(pattern, content):
                tool_counts[tool_type] = tool_counts.get(tool_type, 0) + 1
                # Only add unique descriptions
                desc = match.group(1) if match.lastindex else match.group(0)
                tools.append({
                    'tool': tool_type,
                    'action': action_type,
                    'description': desc[:100] if len(desc) > 100 else desc
                })
        
        # Deduplicate and summarize
        summary = []
        seen_desc = set()
        for tool in tools:
            key = f"{tool['tool']}:{tool['description']}"
            if key not in seen_desc:
                seen_desc.add(key)
                summary.append(tool)
        
        return summary
    
    def _extract_mcp_tools(self, content: str) -> List[Dict[str, str]]:
        """Extract Azure MCP server tools that were actually invoked."""
        mcp_tools = []
        seen = set()
        
        # Look for actual tool invocations (not definitions in system prompt)
        # Patterns that indicate actual use:
        # 1. Tool calls in model responses showing parameters being passed
        # 2. Response sections showing tool results
        # 3. Intent statements mentioning the tool
        
        invocation_patterns = [
            # Tool being called with intent parameter (actual invocation)
            (r'"intent":\s*"[^"]+"\s*}\s*}\s*</invoke>.*?"name":\s*"(azure-[a-z\-_]+)"', 'Azure Tool'),
            # Tool result being returned
            (r'tool_result.*?"name":\s*"(azure-[a-z\-_]+)"', 'Azure Tool'),
            # Calling azure-mcp commands in logs
            (r'calling\s+(azure-mcp-[a-z\-_]+)', 'Azure MCP'),
            # Azure MCP command with actual parameters (not system prompt)
            (r'"command":\s*"[a-z_]+"[^}]*"intent"[^}]*azure-mcp', 'Azure MCP'),
        ]
        
        for pattern, tool_type in invocation_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                tool_name = match.group(1)
                if tool_name not in seen:
                    seen.add(tool_name)
                    mcp_tools.append({
                        'name': tool_name,
                        'type': tool_type,
                        'category': self._get_mcp_tool_category(tool_name)
                    })
        
        # If no explicit invocations found, check for tool names in actual execution contexts
        # (not in the available_skills or function definitions sections)
        if not mcp_tools:
            # Look for azure tools mentioned in output/results sections
            result_patterns = [
                (r'●.*azure-([a-z\-_]+)', 'Azure Tool'),  # Tool output marker
                (r'Invoking.*azure-([a-z\-_]+)', 'Azure Tool'),
            ]
            for pattern, tool_type in result_patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    tool_name = f"azure-{match.group(1)}"
                    if tool_name not in seen and len(tool_name) > 10:  # Avoid partial matches
                        seen.add(tool_name)
                        mcp_tools.append({
                            'name': tool_name,
                            'type': tool_type,
                            'category': self._get_mcp_tool_category(tool_name)
                        })
        
        return mcp_tools
    
    def _get_mcp_tool_category(self, tool_name: str) -> str:
        """Categorize MCP tool by name."""
        categories = {
            'deploy': 'Deployment',
            'appservice': 'App Service',
            'functionapp': 'Functions',
            'storage': 'Storage',
            'cosmos': 'Database',
            'sql': 'Database',
            'keyvault': 'Security',
            'monitor': 'Monitoring',
            'aks': 'Kubernetes',
            'acr': 'Container Registry',
            'role': 'Authorization',
            'subscription': 'Management',
            'group': 'Management',
            'documentation': 'Documentation',
            'bestpractices': 'Best Practices',
        }
        
        tool_lower = tool_name.lower()
        for key, category in categories.items():
            if key in tool_lower:
                return category
        return 'Other'
    
    def _extract_urls(self, content: str) -> List[Dict[str, str]]:
        """Extract deployed URLs from content."""
        urls = []
        seen = set()
        
        # Azure service URL patterns
        url_patterns = [
            # Static Web Apps
            (r'https://[a-z0-9\-]+\.(?:\d+\.)?azurestaticapps\.net/?[^\s\)\]\"\'\`]*', 'Azure Static Web App'),
            # App Service / Web Apps
            (r'https?://[a-z0-9\-]+\.azurewebsites\.net/?[^\s\)\]\"\'\`]*', 'Azure App Service'),
            # Azure Functions
            (r'https://[a-z0-9\-]+\.azurewebsites\.net/api/[^\s\)\]\"\'\`]*', 'Azure Function'),
            # Container Apps
            (r'https://[a-z0-9\-]+\.[a-z0-9\-]+\.azurecontainerapps\.io/?[^\s\)\]\"\'\`]*', 'Azure Container App'),
            # Azure Front Door
            (r'https://[a-z0-9\-]+\.azurefd\.net/?[^\s\)\]\"\'\`]*', 'Azure Front Door'),
            # Azure CDN
            (r'https://[a-z0-9\-]+\.azureedge\.net/?[^\s\)\]\"\'\`]*', 'Azure CDN'),
            # Azure Blob Storage
            (r'https://[a-z0-9]+\.blob\.core\.windows\.net/?[^\s\)\]\"\'\`]*', 'Azure Blob Storage'),
            # Azure API Management
            (r'https://[a-z0-9\-]+\.azure-api\.net/?[^\s\)\]\"\'\`]*', 'Azure API Management'),
            # Cosmos DB
            (r'https://[a-z0-9\-]+\.documents\.azure\.com[^\s\)\]\"\'\`]*', 'Azure Cosmos DB'),
            # Azure SQL
            (r'[a-z0-9\-]+\.database\.windows\.net', 'Azure SQL'),
            # Azure SignalR
            (r'https://[a-z0-9\-]+\.service\.signalr\.net/?[^\s\)\]\"\'\`]*', 'Azure SignalR'),
            # Generic localhost for dev servers
            (r'http://localhost:\d+/?[^\s\)\]\"\'\`]*', 'Local Dev Server'),
        ]
        
        for pattern, service_type in url_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if url not in seen:
                    seen.add(url)
                    urls.append({
                        'url': url,
                        'type': service_type,
                        'context': self._get_context(content, match.start(), 100)
                    })
        
        return urls
    
    def _extract_resources(self, content: str) -> List[Dict[str, str]]:
        """Extract created Azure resource names from content."""
        resources = []
        seen = set()
        
        # Resource creation patterns
        patterns = [
            # az cli create commands
            (r'(?:created|creating)\s+(?:resource\s+group|rg)[:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Resource Group'),
            (r'az\s+group\s+create\s+.*?(?:--name|-n)\s+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Resource Group'),
            (r'(?:created|creating)\s+(?:storage\s+account)[:\s]+["\']?([a-z0-9]+)["\']?', 'Storage Account'),
            (r'az\s+storage\s+account\s+create\s+.*?(?:--name|-n)\s+["\']?([a-z0-9]+)["\']?', 'Storage Account'),
            (r'(?:created|creating)\s+(?:static\s+web\s+app|staticwebapp)[:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Static Web App'),
            (r'az\s+staticwebapp\s+create\s+.*?(?:--name|-n)\s+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Static Web App'),
            (r'(?:created|creating)\s+(?:function\s+app|functionapp)[:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Function App'),
            (r'(?:created|creating)\s+(?:web\s+app|webapp)[:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Web App'),
            (r'(?:created|creating)\s+(?:container\s+app)[:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Container App'),
            (r'(?:created|creating)\s+(?:cosmos\s*db|cosmosdb)\s+(?:account)?[:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Cosmos DB'),
            (r'(?:created|creating)\s+(?:key\s*vault)[:\s]+["\']?([a-zA-Z0-9\-]+)["\']?', 'Key Vault'),
            (r'(?:created|creating)\s+(?:sql\s+server)[:\s]+["\']?([a-zA-Z0-9\-]+)["\']?', 'SQL Server'),
            (r'(?:created|creating)\s+(?:database)[:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?', 'Database'),
            (r'(?:created|creating)\s+(?:container\s+registry|acr)[:\s]+["\']?([a-zA-Z0-9]+)["\']?', 'Container Registry'),
            # JSON output patterns
            (r'"name"\s*:\s*"([a-zA-Z0-9\-_]+)"[^}]*"type"\s*:\s*"Microsoft\.Resources/resourceGroups"', 'Resource Group'),
            (r'"name"\s*:\s*"([a-zA-Z0-9\-_]+)"[^}]*"type"\s*:\s*"Microsoft\.Web/staticSites"', 'Static Web App'),
            (r'"name"\s*:\s*"([a-zA-Z0-9\-_]+)"[^}]*"type"\s*:\s*"Microsoft\.Web/sites"', 'App Service'),
            (r'"name"\s*:\s*"([a-z0-9]+)"[^}]*"type"\s*:\s*"Microsoft\.Storage/storageAccounts"', 'Storage Account'),
        ]
        
        for pattern, resource_type in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                name = match.group(1)
                key = f"{resource_type}:{name}"
                if key not in seen and len(name) > 2:
                    seen.add(key)
                    resources.append({
                        'name': name,
                        'type': resource_type,
                        'context': self._get_context(content, match.start(), 80)
                    })
        
        return resources
    
    def _extract_generated_files(self, content: str) -> List[Dict[str, str]]:
        """Extract generated file paths from content."""
        files = []
        seen = set()
        
        patterns = [
            # Common output file patterns
            (r'(?:saved|created|generated|wrote|writing)\s+(?:to\s+)?[:\s]*["\']?([a-zA-Z]:[\\\/][^\s\"\'\`\n]+\.[a-z]{2,5})["\']?', 'output'),
            (r'(?:saved|created|generated|wrote|writing)\s+(?:to\s+)?[:\s]*["\']?(\.?[\/\\]?[a-zA-Z0-9_\-\.\/\\]+\.[a-z]{2,5})["\']?', 'output'),
            # Report files
            (r'(?:report|results?)\s+(?:saved|file)[:\s]+["\']?([^\s\"\'\`\n]+\.(?:json|html|md|csv|xlsx?))["\']?', 'report'),
            # Download files
            (r'(?:download|exported)[:\s]+["\']?([^\s\"\'\`\n]+\.[a-z]{2,5})["\']?', 'export'),
            # Build output
            (r'(?:built?|compiled?|bundled?)\s+(?:to\s+)?[:\s]*["\']?([^\s\"\'\`\n]+)["\']?', 'build'),
            # Dist folder files
            (r'(dist[\/\\][^\s\"\'\`\n]+)', 'build'),
        ]
        
        for pattern, file_type in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                path = match.group(1)
                if path not in seen and not path.startswith('http'):
                    seen.add(path)
                    files.append({
                        'path': path,
                        'type': file_type,
                        'context': self._get_context(content, match.start(), 60)
                    })
        
        return files[:20]  # Limit to 20 files
    
    def _extract_resource_ids(self, content: str) -> List[Dict[str, str]]:
        """Extract Azure resource IDs from content."""
        resource_ids = []
        seen = set()
        
        # Azure Resource ID pattern
        pattern = r'/subscriptions/[a-f0-9\-]{36}/resourceGroups/([^/]+)/providers/([^/]+/[^/]+)/([^\s\"\'\`\n\]]+)'
        
        for match in re.finditer(pattern, content, re.IGNORECASE):
            full_id = match.group(0)
            if full_id not in seen:
                seen.add(full_id)
                resource_ids.append({
                    'id': full_id,
                    'resourceGroup': match.group(1),
                    'provider': match.group(2),
                    'name': match.group(3).split('/')[0]
                })
        
        return resource_ids[:10]  # Limit to 10 IDs
    
    def _extract_endpoints(self, content: str) -> List[Dict[str, str]]:
        """Extract API endpoints and connection info from content."""
        endpoints = []
        seen = set()
        
        patterns = [
            # API endpoints
            (r'(?:api|endpoint|url)[:\s]+["\']?(https?://[^\s\"\'\`\n]+)["\']?', 'API'),
            # Connection strings (redacted)
            (r'(?:connection\s*string|connstr)[:\s]+["\']?([^"\'\`\n]{20,})["\']?', 'Connection String'),
            # Hostname patterns
            (r'(?:hostname|host|server)[:\s]+["\']?([a-z0-9\-\.]+\.(?:azure|windows|cosmos)\.(?:com|net)[^\s\"\'\`]*)["\']?', 'Host'),
            # Default hostname from deployment
            (r'"defaultHostname"\s*:\s*"([^"]+)"', 'Default Hostname'),
        ]
        
        for pattern, endpoint_type in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1)
                if value not in seen:
                    seen.add(value)
                    # Redact connection strings
                    display_value = value
                    if endpoint_type == 'Connection String':
                        display_value = value[:30] + '...[REDACTED]'
                    endpoints.append({
                        'value': display_value,
                        'type': endpoint_type,
                        'context': self._get_context(content, match.start(), 60)
                    })
        
        return endpoints[:15]
    
    def _get_context(self, content: str, position: int, length: int = 50) -> str:
        """Get surrounding context for a match."""
        start = max(0, position - length // 2)
        end = min(len(content), position + length)
        context = content[start:end].replace('\n', ' ').strip()
        if start > 0:
            context = '...' + context
        if end < len(content):
            context = context + '...'
        return context
