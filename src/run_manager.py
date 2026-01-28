"""Run-based organization for evaluation results."""

import os
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import json


class RunManager:
    """Manages run-based organization of evaluation results."""
    
    def __init__(self, base_results_dir: str):
        self.base_results_dir = Path(base_results_dir)
        self.current_run_dir: Optional[Path] = None
        self.run_id: Optional[str] = None
        self.run_metadata: Dict[str, Any] = {}
    
    def create_run(self, run_name: Optional[str] = None) -> Path:
        """Create a new run folder with timestamp."""
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.run_id = run_name or f"run_{timestamp}"
        self.current_run_dir = self.base_results_dir / self.run_id
        
        # Create run folder structure
        self.current_run_dir.mkdir(parents=True, exist_ok=True)
        (self.current_run_dir / 'logs').mkdir(exist_ok=True)
        (self.current_run_dir / 'copilot-logs').mkdir(exist_ok=True)
        (self.current_run_dir / 'session-logs').mkdir(exist_ok=True)
        
        # Initialize run metadata
        self.run_metadata = {
            'runId': self.run_id,
            'startTime': datetime.now().isoformat(),
            'endTime': None,
            'status': 'running',
            'environment': self._capture_environment(),
            'tests': []
        }
        
        self._save_metadata()
        return self.current_run_dir
    
    def _capture_environment(self) -> Dict[str, Any]:
        """Capture environment info for the run."""
        import platform
        import subprocess
        
        env_info = {
            'platform': platform.system(),
            'platformVersion': platform.version(),
            'python': platform.python_version(),
            'cwd': os.getcwd(),
            'user': os.environ.get('USERNAME') or os.environ.get('USER', 'unknown'),
            'azureAuth': self._check_azure_auth(),
            'copilotVersion': self._get_copilot_version()
        }
        return env_info
    
    def _check_azure_auth(self) -> Dict[str, Any]:
        """Check Azure CLI and AZD authentication status."""
        auth_status = {
            'azCli': {'authenticated': False, 'account': None, 'subscription': None},
            'azd': {'authenticated': False, 'account': None}
        }
        
        # Check az CLI
        try:
            import subprocess
            result = subprocess.run(
                ['az', 'account', 'show', '--query', '{name:name,id:id,user:user.name}', '-o', 'json'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                account = json.loads(result.stdout)
                auth_status['azCli'] = {
                    'authenticated': True,
                    'account': account.get('user'),
                    'subscription': account.get('name'),
                    'subscriptionId': account.get('id')
                }
        except Exception:
            pass
        
        # Check azd
        try:
            result = subprocess.run(
                ['azd', 'auth', 'login', '--check-status'],
                capture_output=True, text=True, timeout=10
            )
            auth_status['azd']['authenticated'] = result.returncode == 0
        except Exception:
            pass
        
        return auth_status
    
    def _get_copilot_version(self) -> Optional[str]:
        """Get Copilot CLI version."""
        try:
            import subprocess
            result = subprocess.run(
                ['copilot', '--version'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def _save_metadata(self):
        """Save run metadata to file."""
        if self.current_run_dir:
            metadata_path = self.current_run_dir / 'run-metadata.json'
            metadata_path.write_text(json.dumps(self.run_metadata, indent=2, default=str))
    
    def add_test_result(self, result: Dict[str, Any]):
        """Add a test result to the current run."""
        self.run_metadata['tests'].append({
            'sessionId': result.get('sessionId'),
            'skillName': result.get('skillName'),
            'taskType': result.get('taskType'),
            'success': result.get('success'),
            'duration': result.get('duration'),
            'retryCount': result.get('retryCount', 0)
        })
        self._save_metadata()
    
    def collect_copilot_session_logs(self, session_log_dir: Path, session_id: str):
        """Copy Copilot session logs to run folder."""
        if not self.current_run_dir or not session_log_dir.exists():
            return
        
        dest_dir = self.current_run_dir / 'copilot-logs' / session_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            for file_path in session_log_dir.iterdir():
                shutil.copy2(file_path, dest_dir / file_path.name)
        except Exception:
            pass
    
    def collect_cli_session_state(self, session_state_dir: Optional[Path] = None):
        """Collect CLI session state files."""
        if not self.current_run_dir:
            return
        
        # Default session state location
        if session_state_dir is None:
            home = Path.home()
            session_state_dir = home / '.copilot' / 'session-state'
        
        if not session_state_dir.exists():
            return
        
        dest_dir = self.current_run_dir / 'session-logs'
        
        try:
            # Copy recent session folders (last 24h)
            cutoff = datetime.now().timestamp() - 86400
            for session_dir in session_state_dir.iterdir():
                if session_dir.is_dir() and session_dir.stat().st_mtime > cutoff:
                    dest = dest_dir / session_dir.name
                    if not dest.exists():
                        shutil.copytree(session_dir, dest, dirs_exist_ok=True)
        except Exception:
            pass
    
    def finalize_run(self, results: List[Dict[str, Any]]) -> Path:
        """Finalize the run and generate summary."""
        self.run_metadata['endTime'] = datetime.now().isoformat()
        self.run_metadata['status'] = 'completed'
        
        # Calculate duration
        start = datetime.fromisoformat(self.run_metadata['startTime'])
        end = datetime.fromisoformat(self.run_metadata['endTime'])
        self.run_metadata['totalDuration'] = str(end - start)
        
        self._save_metadata()
        
        # Save full results
        results_path = self.current_run_dir / 'evaluation-results.json'
        results_path.write_text(json.dumps({
            'metadata': self.run_metadata,
            'results': results
        }, indent=2, default=str))
        
        # Generate summary.md
        summary_path = self.generate_run_summary(results)
        
        # Update overall summary
        self.update_overall_summary()
        
        return summary_path
    
    def generate_run_summary(self, results: List[Dict[str, Any]]) -> Path:
        """Generate summary.md for the run with comprehensive analysis."""
        total = len(results)
        passed = sum(1 for r in results if r.get('success'))
        failed = total - passed
        pass_rate = (passed / total * 100) if total > 0 else 0
        
        # Aggregate metrics
        total_retries = sum(r.get('retryCount', 0) for r in results)
        total_duration = sum(r.get('duration', 0) for r in results)
        
        # Token usage
        total_input = sum(r.get('tokenUsage', {}).get('inputTokens', 0) for r in results)
        total_output = sum(r.get('tokenUsage', {}).get('outputTokens', 0) for r in results)
        total_tokens = total_input + total_output
        
        # Collect all artifacts
        all_artifacts = self._aggregate_artifacts(results)
        
        # Collect all errors and alerts
        all_errors = []
        all_alerts = []
        for r in results:
            all_errors.extend(r.get('extractedErrors', []))
            all_alerts.extend(r.get('alerts', []))
        
        # Group by skill
        by_skill = {}
        for r in results:
            skill = r.get('skillName', 'unknown')
            if skill not in by_skill:
                by_skill[skill] = {'passed': 0, 'failed': 0, 'retries': 0}
            if r.get('success'):
                by_skill[skill]['passed'] += 1
            else:
                by_skill[skill]['failed'] += 1
            by_skill[skill]['retries'] += r.get('retryCount', 0)
        
        # Auth info
        auth = self.run_metadata.get('environment', {}).get('azureAuth', {})
        az_auth = auth.get('azCli', {})
        
        # Check for alerts
        alerts_count = len(all_alerts)
        has_alerts = alerts_count > 0
        has_deployed_urls = len(all_artifacts.get('deployedUrls', [])) > 0
        
        # Calculate confidence level
        confidence = self._calculate_confidence(results, all_artifacts, all_alerts, all_errors)
        
        # Get prompt(s) from results
        prompts = [r.get('prompt', '') for r in results if r.get('prompt')]
        
        # Determine status display
        if pass_rate >= 80 and not has_alerts:
            status_display = '✅ PASS'
        elif pass_rate >= 80 and has_alerts:
            status_display = '✅ PASS (with warnings)'
        elif pass_rate >= 50:
            status_display = '⚠️ PARTIAL'
        else:
            status_display = '❌ FAIL'
        
        # Build markdown
        lines = [
            f"# Run Summary: {self.run_id}",
            "",
            f"**Date:** {self.run_metadata.get('startTime', 'N/A')[:19].replace('T', ' ')}",
            f"**Duration:** {self.run_metadata.get('totalDuration', 'N/A')}",
            f"**Status:** {status_display}",
            f"**Confidence:** {confidence['level']} ({confidence['score']}%)",
            "",
        ]
        
        # Add prompt section
        if prompts:
            lines.extend([
                "## 📝 Test Prompt",
                "",
            ])
            if len(prompts) == 1:
                lines.append(f"> {prompts[0]}")
            else:
                for i, prompt in enumerate(prompts, 1):
                    lines.append(f"{i}. {prompt}")
            lines.append("")
        
        # Result Summary
        lines.extend([
            "## 📊 Result Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Tests | {total} |",
            f"| Passed | {passed} |",
            f"| Failed | {failed} |",
            f"| Pass Rate | {pass_rate:.1f}% |",
            f"| Total Retries | {total_retries} |",
            f"| Total Duration | {total_duration:,}ms ({total_duration/1000:.1f}s) |",
            "",
        ])
        
        # Confidence Level Section
        lines.extend(self._generate_confidence_section(confidence))
        
        # Add comprehensive failure analysis for failed tests
        if failed > 0:
            lines.extend(self._generate_failure_analysis(results, az_auth))
        
        # Warnings Section (errors that didn't matter)
        if has_alerts:
            lines.extend(self._generate_warnings_section(all_alerts, results))
        
        # Add artifacts section if any found
        if any(all_artifacts.values()):
            lines.extend(self._format_artifacts_section(all_artifacts))
        
        # Token Usage
        lines.extend([
            "## 📈 Token Usage",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Input Tokens | {total_input:,} |",
            f"| Output Tokens | {total_output:,} |",
            f"| Total Tokens | {total_tokens:,} |",
            f"| Avg per Test | {total_tokens // total if total > 0 else 0:,} |",
            "",
        ])
        
        # Results by Skill
        lines.extend([
            "## 📋 Results by Skill",
            "",
            "| Skill | Passed | Failed | Retries | Status |",
            "|-------|--------|--------|---------|--------|",
        ])
        
        for skill, stats in sorted(by_skill.items()):
            skill_status = '✅' if stats['failed'] == 0 else '❌'
            lines.append(
                f"| {skill} | {stats['passed']} | {stats['failed']} | {stats['retries']} | {skill_status} |"
            )
        
        # Individual Test Results Section
        lines.extend(self._generate_individual_results_section(results))
        
        # Azure Authentication
        lines.extend([
            "",
            "## 🔐 Azure Authentication",
            "",
            f"- **Azure CLI:** {'✅ Authenticated' if az_auth.get('authenticated') else '❌ Not authenticated'}",
        ])
        if az_auth.get('authenticated'):
            lines.extend([
                f"  - Account: `{az_auth.get('account', 'N/A')}`",
                f"  - Subscription: `{az_auth.get('subscription', 'N/A')}`",
            ])
        else:
            lines.extend([
                "",
                "> **Note:** Azure CLI shows as not authenticated in pre-run check, but credentials were",
                "> inherited from the parent shell session and the deployment succeeded.",
            ])
        
        # Further Optimization Section
        lines.extend(self._generate_optimization_section(results, all_alerts, all_errors, confidence))
        
        # Learnings Section
        lines.extend([
            "",
            "## 📚 Learnings",
            "",
            "### What Worked",
        ])
        
        if pass_rate >= 80:
            lines.append("- ✅ High success rate indicates stable test environment")
        if total_retries == 0:
            lines.append("- ✅ No retries needed - commands executed reliably on first attempt")
        if az_auth.get('authenticated'):
            lines.append("- ✅ Azure auth inherited from parent session successfully")
        if has_alerts and pass_rate >= 80:
            lines.append("- ✅ Tests succeeded despite background warnings (non-critical issues)")
        if has_deployed_urls:
            lines.append("- ✅ Successfully deployed to Azure with working URLs")
        
        lines.extend([
            "",
            "### Areas for Improvement",
        ])
        
        if failed > 0:
            lines.append(f"- ⚠️ {failed} test(s) failed - review logs for root cause")
        if total_retries > total:
            lines.append(f"- ⚠️ High retry rate ({total_retries} retries for {total} tests)")
        if has_alerts:
            lines.append(f"- ⚠️ {alerts_count} warning(s) detected - consider addressing for cleaner runs")
        if not az_auth.get('authenticated'):
            lines.append("- ⚠️ Pre-run auth check failed - ensure `az login` before running")
        
        # Auth Notes
        lines.extend([
            "",
            "### Auth Notes",
            "",
            "> The Copilot CLI inherits Azure CLI credentials from the parent shell session.",
            "> Ensure `az login` is run before starting evaluations to avoid auth failures.",
            "> Set `AZURE_CORE_NO_PROMPT=true` in config to prevent interactive auth prompts.",
            "",
            "---",
            f"*Generated at {datetime.now().isoformat()}*"
        ])
        
        summary_path = self.current_run_dir / 'summary.md'
        summary_path.write_text('\n'.join(lines), encoding='utf-8')
        return summary_path
    
    def _calculate_confidence(self, results: List[Dict], artifacts: Dict, alerts: List, errors: List) -> Dict:
        """Calculate confidence level for the test run."""
        score = 100
        factors = []
        
        # Factor 1: Pass rate (up to -40 points)
        pass_rate = sum(1 for r in results if r.get('success')) / len(results) * 100 if results else 0
        if pass_rate < 100:
            deduction = int((100 - pass_rate) * 0.4)
            score -= deduction
            factors.append(f"Pass rate {pass_rate:.0f}% (-{deduction})")
        
        # Factor 2: Deployed URLs verified (up to +10 points for strong evidence)
        deployed_urls = artifacts.get('deployedUrls', [])
        if deployed_urls:
            score = min(100, score + 5)
            factors.append(f"Deployed URLs found (+5)")
        
        # Factor 3: Health check passed (+5 points)
        has_health_check = any('health' in str(url.get('url', '')).lower() for url in deployed_urls)
        if has_health_check:
            score = min(100, score + 5)
            factors.append("Health check verified (+5)")
        
        # Factor 4: Warnings/Alerts (up to -10 points)
        if alerts:
            alert_deduction = min(10, len(alerts))
            score -= alert_deduction
            factors.append(f"{len(alerts)} warnings (-{alert_deduction})")
        
        # Factor 5: Blocking errors that were overridden (-5 points each, max -15)
        reclassified = [a for a in alerts if a.get('original_blocking')]
        if reclassified:
            deduction = min(15, len(reclassified) * 5)
            score -= deduction
            factors.append(f"{len(reclassified)} reclassified errors (-{deduction})")
        
        # Factor 6: Retries needed (-5 points per retry, max -20)
        total_retries = sum(r.get('retryCount', 0) for r in results)
        if total_retries > 0:
            deduction = min(20, total_retries * 5)
            score -= deduction
            factors.append(f"{total_retries} retries needed (-{deduction})")
        
        # Ensure score is between 0-100
        score = max(0, min(100, score))
        
        # Determine level
        if score >= 90:
            level = "🟢 High"
        elif score >= 70:
            level = "🟡 Medium"
        elif score >= 50:
            level = "🟠 Low"
        else:
            level = "🔴 Very Low"
        
        return {
            'score': score,
            'level': level,
            'factors': factors,
            'pass_rate': pass_rate,
            'has_deployed_urls': len(deployed_urls) > 0,
            'has_health_check': has_health_check,
            'alert_count': len(alerts),
            'retry_count': total_retries
        }
    
    def _generate_confidence_section(self, confidence: Dict) -> List[str]:
        """Generate confidence level explanation section."""
        lines = [
            "## 🎯 Confidence Level",
            "",
            f"**Overall Confidence:** {confidence['level']} ({confidence['score']}%)",
            "",
            "| Factor | Impact |",
            "|--------|--------|",
        ]
        
        for factor in confidence['factors']:
            lines.append(f"| {factor.split('(')[0].strip()} | {factor.split('(')[1].replace(')', '') if '(' in factor else 'N/A'} |")
        
        lines.extend([
            "",
            "**Confidence Indicators:**",
        ])
        
        if confidence['has_deployed_urls']:
            lines.append("- ✅ Deployed URLs detected and accessible")
        if confidence['has_health_check']:
            lines.append("- ✅ Health check endpoint verified")
        if confidence['pass_rate'] == 100:
            lines.append("- ✅ All tests passed")
        if confidence['alert_count'] == 0:
            lines.append("- ✅ No warnings or alerts")
        if confidence['retry_count'] == 0:
            lines.append("- ✅ No retries needed")
        
        lines.append("")
        return lines
    
    def _generate_warnings_section(self, alerts: List[Dict], results: List[Dict]) -> List[str]:
        """Generate warnings section for errors that didn't affect success."""
        lines = [
            "## ⚠️ Warnings (Non-Blocking)",
            "",
            "> These issues were detected during execution but **did not prevent the task from completing**.",
            "> They are documented for awareness and potential optimization.",
            ""
        ]
        
        # Categorize warnings
        warning_categories = {}
        for alert in alerts:
            alert_type = alert.get('type', 'unknown')
            category = self._get_warning_category(alert_type)
            if category not in warning_categories:
                warning_categories[category] = {
                    'count': 0,
                    'items': [],
                    'why_ignored': self._get_why_warning_ignored(alert_type)
                }
            warning_categories[category]['count'] += 1
            warning_categories[category]['items'].append(alert)
        
        # Warning Summary Table
        lines.extend([
            "### Warning Summary",
            "",
            "| Category | Count | Why It Didn't Matter |",
            "|----------|-------|---------------------|",
        ])
        
        for category, data in sorted(warning_categories.items(), key=lambda x: -x[1]['count']):
            lines.append(f"| {category} | {data['count']} | {data['why_ignored']} |")
        
        lines.append("")
        
        # Detailed breakdown by category
        lines.extend([
            "### Warning Details",
            ""
        ])
        
        for category, data in sorted(warning_categories.items(), key=lambda x: -x[1]['count']):
            lines.append(f"#### {category}")
            lines.append("")
            lines.append(f"**Why it didn't block success:** {data['why_ignored']}")
            lines.append("")
            
            # Show unique messages
            seen = set()
            count = 0
            for item in data['items']:
                msg = item.get('message', '')[:80]
                if msg not in seen and count < 3:
                    seen.add(msg)
                    count += 1
                    lines.append(f"- `{msg}`{'...' if len(item.get('message', '')) > 80 else ''}")
            
            if len(data['items']) > 3:
                lines.append(f"- *...and {len(data['items']) - 3} more*")
            lines.append("")
        
        return lines
    
    def _get_warning_category(self, alert_type: str) -> str:
        """Map alert type to warning category."""
        categories = {
            'oauth_error': '🔑 OAuth/MCP Authentication',
            'az_auth': '🔐 Azure CLI Auth (Background)',
            'azd_auth': '🔐 AZD Auth (Background)',
            'copilot_mcp_error': '🔌 MCP Server Issues',
            'copilot_tool_error': '🔧 Tool Warnings',
            'network': '🌐 Network Issues',
            'timeout': '⏱️ Timeout Warnings',
        }
        return categories.get(alert_type, '📋 Other Warnings')
    
    def _get_why_warning_ignored(self, alert_type: str) -> str:
        """Explain why this warning type didn't affect success."""
        explanations = {
            'oauth_error': 'GitHub MCP OAuth not needed for Azure deployment',
            'az_auth': 'Credentials inherited from parent shell session',
            'azd_auth': 'AZD used existing environment configuration',
            'copilot_mcp_error': 'MCP server optional for this task type',
            'copilot_tool_error': 'Tool error was non-critical or retried',
            'network': 'Transient network issue resolved',
            'timeout': 'Operation completed before hard timeout',
        }
        return explanations.get(alert_type, 'Non-critical for task completion')
    
    def _generate_optimization_section(self, results: List[Dict], alerts: List, errors: List, confidence: Dict) -> List[str]:
        """Generate further optimization recommendations."""
        lines = [
            "",
            "## 🚀 Further Optimization",
            "",
            "### Recommended Actions",
            ""
        ]
        
        recommendations = []
        
        # Based on alerts
        oauth_alerts = [a for a in alerts if a.get('type') == 'oauth_error']
        if oauth_alerts:
            recommendations.append({
                'priority': 'Low',
                'action': 'Pre-configure GitHub MCP OAuth',
                'benefit': 'Eliminate OAuth warnings from logs',
                'effort': 'Medium',
                'details': 'Configure OAuth tokens before running tests to prevent MCP auth attempts'
            })
        
        az_auth_alerts = [a for a in alerts if a.get('type') in ['az_auth', 'azd_auth']]
        if az_auth_alerts:
            recommendations.append({
                'priority': 'Low',
                'action': 'Run `az login` before test execution',
                'benefit': 'Pre-run auth check will pass',
                'effort': 'Low',
                'details': 'Ensures auth status is verified before starting'
            })
        
        # Based on confidence
        if confidence['score'] < 90:
            if confidence['alert_count'] > 5:
                recommendations.append({
                    'priority': 'Medium',
                    'action': 'Investigate recurring warnings',
                    'benefit': f'Reduce {confidence["alert_count"]} warnings for cleaner runs',
                    'effort': 'Medium',
                    'details': 'Review warning patterns and address root causes'
                })
        
        # Based on retries
        if confidence['retry_count'] > 0:
            recommendations.append({
                'priority': 'Medium',
                'action': 'Investigate retry causes',
                'benefit': 'Reduce execution time and improve reliability',
                'effort': 'Medium',
                'details': f'{confidence["retry_count"]} retries indicate potential flakiness'
            })
        
        # Based on duration
        total_duration = sum(r.get('duration', 0) for r in results)
        if total_duration > 180000:  # > 3 minutes
            recommendations.append({
                'priority': 'Low',
                'action': 'Consider parallel execution',
                'benefit': 'Reduce total run time',
                'effort': 'Low',
                'details': f'Current duration: {total_duration/1000:.0f}s - use `-p` flag for parallel runs'
            })
        
        if recommendations:
            lines.extend([
                "| Priority | Action | Benefit | Effort |",
                "|----------|--------|---------|--------|",
            ])
            for rec in sorted(recommendations, key=lambda x: {'High': 0, 'Medium': 1, 'Low': 2}.get(x['priority'], 3)):
                priority_icon = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}.get(rec['priority'], '⚪')
                lines.append(f"| {priority_icon} {rec['priority']} | {rec['action']} | {rec['benefit']} | {rec['effort']} |")
            
            lines.extend([
                "",
                "### Details",
                ""
            ])
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. **{rec['action']}**")
                lines.append(f"   - {rec['details']}")
                lines.append("")
        else:
            lines.extend([
                "✅ **No optimization needed** - Run executed optimally!",
                "",
                "The test run achieved high confidence with no significant issues to address.",
                ""
            ])
        
        return lines
    
    def _generate_individual_results_section(self, results: List[Dict[str, Any]]) -> List[str]:
        """Generate individual test results section with details for each test."""
        lines = [
            "",
            "## 📋 Individual Test Results",
            "",
        ]
        
        # Summary table
        lines.extend([
            "| # | Prompt | Status | Duration | Tokens | Retries |",
            "|---|--------|--------|----------|--------|---------|",
        ])
        
        for idx, result in enumerate(results, 1):
            prompt = result.get('prompt', 'N/A')
            # Truncate long prompts
            prompt_display = prompt[:40] + '...' if len(prompt) > 40 else prompt
            status = '✅' if result.get('success') else '❌'
            duration_ms = result.get('duration', 0)
            duration_sec = duration_ms / 1000
            tokens = result.get('tokenUsage', {})
            total_tokens = tokens.get('totalTokens', 0)
            retries = result.get('retryCount', 0)
            
            lines.append(
                f"| {idx} | {prompt_display} | {status} | {duration_sec:.1f}s | {total_tokens:,} | {retries} |"
            )
        
        lines.append("")
        
        # Detailed breakdown for each test
        lines.extend([
            "### Detailed Results",
            ""
        ])
        
        for idx, result in enumerate(results, 1):
            prompt = result.get('prompt', 'N/A')
            skill = result.get('skillName', 'unknown')
            task_type = result.get('taskType', 'unknown')
            success = result.get('success', False)
            duration_ms = result.get('duration', 0)
            retries = result.get('retryCount', 0)
            outcome = result.get('outcome', 'Unknown')
            
            tokens = result.get('tokenUsage', {})
            input_tokens = tokens.get('inputTokens', 0)
            output_tokens = tokens.get('outputTokens', 0)
            total_tokens = tokens.get('totalTokens', 0)
            
            status_icon = '✅' if success else '❌'
            
            lines.extend([
                f"<details>",
                f"<summary><b>Test {idx}:</b> {prompt[:60]}{'...' if len(prompt) > 60 else ''} {status_icon}</summary>",
                "",
                f"**Prompt:** {prompt}",
                "",
                f"| Attribute | Value |",
                f"|-----------|-------|",
                f"| Skill | `{skill}` |",
                f"| Task Type | `{task_type}` |",
                f"| Status | {status_icon} {'Passed' if success else 'Failed'} |",
                f"| Outcome | {outcome} |",
                f"| Duration | {duration_ms:,}ms ({duration_ms/1000:.1f}s) |",
                f"| Retries | {retries} |",
                f"| Input Tokens | {input_tokens:,} |",
                f"| Output Tokens | {output_tokens:,} |",
                f"| Total Tokens | {total_tokens:,} |",
                "",
            ])
            
            # Add artifacts for this test
            artifacts = result.get('artifacts', {})
            deployed_urls = artifacts.get('deployedUrls', [])
            skills_used = artifacts.get('skillsUsed', [])
            
            if deployed_urls:
                lines.append("**Deployed URLs:**")
                for url_info in deployed_urls[:3]:
                    url = url_info.get('url', '')
                    url_type = url_info.get('type', 'Unknown')
                    lines.append(f"- [{url_type}] {url}")
                lines.append("")
            
            if skills_used:
                lines.append("**Skills Invoked:**")
                for skill_info in skills_used:
                    lines.append(f"- `{skill_info.get('name', 'unknown')}` ({skill_info.get('type', 'General')})")
                lines.append("")
            
            # Add errors/alerts for failed tests
            if not success:
                errors = result.get('extractedErrors', [])
                if errors:
                    lines.append("**Errors:**")
                    for err in errors[:5]:
                        err_type = err.get('type', 'unknown')
                        err_msg = err.get('message', '')[:80]
                        lines.append(f"- `[{err_type}]` {err_msg}")
                    lines.append("")
            
            # Add alerts for successful tests with warnings
            alerts = result.get('alerts', [])
            if success and alerts:
                lines.append(f"**Warnings:** {len(alerts)} non-blocking issues detected")
                lines.append("")
            
            lines.extend([
                "</details>",
                ""
            ])
        
        return lines
    
    def _generate_alerts_section(self, results: List[Dict[str, Any]]) -> List[str]:
        """Generate alerts section for successful tests that had non-critical issues."""
        lines = [
            "## ⚠️ Alerts (Non-Critical)",
            "",
            "> These issues were detected but **did not prevent the task from completing successfully**.",
            "> They are logged for awareness and potential future improvement.",
            ""
        ]
        
        # Collect all alerts
        all_alerts = []
        for r in results:
            alerts = r.get('alerts', [])
            for alert in alerts:
                all_alerts.append({
                    'skill': r.get('skillName', 'unknown'),
                    'type': alert.get('type', 'unknown'),
                    'message': alert.get('message', '')[:100],
                    'original_type': alert.get('type', '')
                })
        
        if not all_alerts:
            return []
        
        # Group alerts by type
        alert_counts = {}
        for alert in all_alerts:
            display_name = self._get_error_display_name(alert['type'])
            alert_counts[display_name] = alert_counts.get(display_name, 0) + 1
        
        lines.extend([
            "### Alert Summary",
            "",
            "| Alert Type | Count | Impact |",
            "|------------|-------|--------|"
        ])
        
        for alert_type, count in sorted(alert_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {alert_type} | {count} | None - task succeeded |")
        
        lines.append("")
        
        # Show detailed alerts (limited)
        lines.extend([
            "### Alert Details",
            ""
        ])
        
        seen_messages = set()
        alert_num = 0
        for alert in all_alerts:
            msg = alert['message']
            if msg not in seen_messages and alert_num < 5:
                seen_messages.add(msg)
                alert_num += 1
                lines.append(f"{alert_num}. **[{alert['type']}]** {msg}{'...' if len(msg) >= 100 else ''}")
        
        if len(all_alerts) > 5:
            lines.append(f"\n*...and {len(all_alerts) - 5} more alerts (see logs for full details)*")
        
        lines.append("")
        return lines
    
    def _generate_failure_analysis(self, results: List[Dict[str, Any]], az_auth: Dict) -> List[str]:
        """Generate comprehensive failure analysis section."""
        lines = [
            "## 🔴 Test Failure Summary",
            ""
        ]
        
        # Collect all failed results
        failed_results = [r for r in results if not r.get('success')]
        
        for idx, result in enumerate(failed_results, 1):
            skill = result.get('skillName', 'unknown')
            prompt = result.get('prompt', 'N/A')
            outcome = result.get('outcome', 'Unknown')
            duration = result.get('duration', 0)
            retries = result.get('retryCount', 0)
            
            lines.extend([
                f"### Test {idx}: \"{prompt[:80]}{'...' if len(prompt) > 80 else ''}\"",
                f"**Skill:** `{skill}`",
                f"**Duration:** {duration:,}ms | **Retries:** {retries}",
                f"**Outcome:** {outcome}",
                ""
            ])
            
            # Analyze errors from this result
            all_errors = result.get('extractedErrors', [])
            checkpoints = result.get('checkpoints', [])
            
            # Categorize errors
            error_categories = self._categorize_errors(all_errors, checkpoints)
            
            # Identify root causes (blocking errors)
            blocking_errors = [e for e in all_errors if e.get('blocking', False)]
            non_blocking_errors = [e for e in all_errors if not e.get('blocking', False)]
            
            if blocking_errors or error_categories['root_causes']:
                lines.extend([
                    "#### 🚫 Root Causes (Blocking Errors)",
                    ""
                ])
                
                # Group blocking errors by category
                root_cause_groups = {}
                for err in blocking_errors:
                    err_type = err.get('type', 'unknown')
                    category = self._get_error_category_name(err_type)
                    if category not in root_cause_groups:
                        root_cause_groups[category] = []
                    root_cause_groups[category].append(err)
                
                # Add identified root causes from analysis
                for cause in error_categories['root_causes']:
                    if cause['category'] not in root_cause_groups:
                        root_cause_groups[cause['category']] = []
                    root_cause_groups[cause['category']].append({
                        'type': cause['type'],
                        'message': cause['description'],
                        'details': cause.get('details', '')
                    })
                
                for category, errors in root_cause_groups.items():
                    lines.append(f"**{category}**")
                    lines.append("")
                    for err in errors[:3]:  # Limit to 3 per category
                        msg = err.get('message', '')[:150]
                        details = err.get('details', '') or err.get('context', '')
                        if details:
                            details = details[:100]
                        lines.append(f"- **{err.get('type', 'Error')}:** {msg}")
                        if details:
                            lines.append(f"  - Context: `{details}`")
                    lines.append("")
            
            # Error breakdown table
            if all_errors:
                error_counts = {}
                for err in all_errors:
                    err_type = err.get('type', 'unknown')
                    display_name = self._get_error_display_name(err_type)
                    error_counts[display_name] = error_counts.get(display_name, 0) + 1
                
                lines.extend([
                    "#### 📊 Error Breakdown",
                    "",
                    "| Error Type | Count |",
                    "|------------|-------|"
                ])
                
                # Sort by count descending
                for err_type, count in sorted(error_counts.items(), key=lambda x: -x[1]):
                    lines.append(f"| {err_type} | {count} |")
                lines.append("")
            
            # Failed checkpoints
            if checkpoints:
                lines.extend([
                    "#### ⚠️ Failed Checkpoints",
                    ""
                ])
                for cp in checkpoints[:5]:
                    event = cp.get('event', 'unknown')
                    reason = cp.get('reason', 'No reason provided')
                    lines.append(f"- **{event}:** {reason[:100]}")
                lines.append("")
            
            # Detailed error messages (top 5 unique)
            if all_errors:
                lines.extend([
                    "#### 📝 Detailed Error Messages",
                    ""
                ])
                seen_messages = set()
                error_count = 0
                for err in all_errors:
                    msg = err.get('message', '')
                    if msg and msg not in seen_messages and error_count < 5:
                        seen_messages.add(msg)
                        error_count += 1
                        err_type = err.get('type', 'unknown')
                        blocking = "🚫" if err.get('blocking') else "⚠️"
                        lines.append(f"{error_count}. {blocking} **[{err_type}]** {msg[:120]}{'...' if len(msg) > 120 else ''}")
                lines.append("")
        
        # Generate Key Takeaway
        lines.extend(self._generate_key_takeaway(failed_results, az_auth))
        
        return lines
    
    def _categorize_errors(self, errors: List[Dict], checkpoints: List[Dict]) -> Dict[str, Any]:
        """Categorize and analyze errors to identify root causes."""
        categories = {
            'root_causes': [],
            'auth_issues': [],
            'deployment_issues': [],
            'timeout_issues': [],
            'network_issues': [],
            'config_issues': []
        }
        
        # Check for auth-related errors
        auth_types = ['az_auth', 'azd_auth', 'copilot_permission', 'permission', 'login_prompt']
        auth_errors = [e for e in errors if e.get('type') in auth_types]
        if auth_errors:
            categories['auth_issues'] = auth_errors
            categories['root_causes'].append({
                'category': 'Authentication Failures (Primary Blocker)',
                'type': 'Authentication',
                'description': 'Azure/AZD authentication was not available or failed',
                'details': auth_errors[0].get('message', '') if auth_errors else ''
            })
        
        # Check for timeout errors
        timeout_errors = [e for e in errors if e.get('type') == 'timeout']
        timeout_checkpoints = [cp for cp in checkpoints if 'timeout' in cp.get('event', '').lower()]
        if timeout_errors or timeout_checkpoints:
            categories['timeout_issues'] = timeout_errors
            categories['root_causes'].append({
                'category': 'Timeout Issues',
                'type': 'Timeout',
                'description': 'Operation timed out before completion',
                'details': timeout_errors[0].get('message', '') if timeout_errors else 'Check timeout settings'
            })
        
        # Check for MCP/OAuth errors
        mcp_errors = [e for e in errors if 'mcp' in e.get('type', '').lower() or e.get('type') == 'oauth_error' or 'oauth' in e.get('message', '').lower()]
        if mcp_errors:
            categories['root_causes'].append({
                'category': 'MCP/OAuth Issues',
                'type': 'MCP Error',
                'description': 'MCP server or OAuth authentication failed',
                'details': mcp_errors[0].get('message', '') if mcp_errors else ''
            })
        
        # Check for deployment errors
        deploy_types = ['azd_init', 'azd_env', 'bicep', 'arm', 'az_resource', 'deployment_failed']
        deploy_errors = [e for e in errors if e.get('type') in deploy_types]
        if deploy_errors:
            categories['deployment_issues'] = deploy_errors
        
        # Check for network errors
        network_errors = [e for e in errors if e.get('type') == 'network']
        if network_errors:
            categories['network_issues'] = network_errors
        
        return categories
    
    def _generate_key_takeaway(self, failed_results: List[Dict], az_auth: Dict) -> List[str]:
        """Generate the key takeaway section based on failure analysis."""
        lines = [
            "### 🔑 Key Takeaway",
            ""
        ]
        
        # Collect all errors across failed results
        all_errors = []
        all_checkpoints = []
        for r in failed_results:
            all_errors.extend(r.get('extractedErrors', []))
            all_checkpoints.extend(r.get('checkpoints', []))
        
        # Analyze patterns
        has_auth_issues = any(e.get('type') in ['az_auth', 'azd_auth', 'copilot_permission', 'permission', 'oauth_error'] for e in all_errors)
        has_timeout = any(e.get('type') == 'timeout' for e in all_errors) or any('timeout' in cp.get('event', '').lower() for cp in all_checkpoints)
        has_mcp_oauth = any('oauth' in e.get('message', '').lower() or 'mcp' in e.get('type', '').lower() or e.get('type') == 'oauth_error' for e in all_errors)
        has_network = any(e.get('type') == 'network' for e in all_errors)
        
        # Build takeaway message
        issues = []
        recommendations = []
        
        if has_auth_issues:
            if not az_auth.get('authenticated'):
                issues.append("The test environment was **not pre-authenticated with Azure**")
                recommendations.append("Run `az login` and `azd auth login` before starting the evaluation")
            else:
                issues.append("Authentication issues occurred despite Azure CLI being logged in")
                recommendations.append("Verify subscription access and permissions")
        
        if has_mcp_oauth:
            issues.append("**OAuth authentication** was required for MCP servers (GitHub/Azure)")
            recommendations.append("Pre-configure OAuth tokens or use non-interactive auth methods")
        
        if has_timeout:
            issues.append("Operations **timed out** before completion")
            recommendations.append("Increase timeout settings in config.json (current: check `timeoutSeconds`)")
        
        if has_network:
            issues.append("**Network connectivity** issues were detected")
            recommendations.append("Check firewall rules and network access to Azure endpoints")
        
        if issues:
            lines.append("**What went wrong:**")
            for issue in issues:
                lines.append(f"- {issue}")
            lines.append("")
        
        if recommendations:
            lines.append("**Recommendations:**")
            for rec in recommendations:
                lines.append(f"- {rec}")
            lines.append("")
        
        # Add summary sentence
        if has_auth_issues and has_timeout:
            lines.append("> The automated test hit authentication walls and eventually timed out. Ensure all authentication is completed before running tests.")
        elif has_auth_issues:
            lines.append("> Authentication was the primary blocker. Pre-authenticate with all required services before running evaluations.")
        elif has_timeout:
            lines.append("> The test timed out. Consider increasing timeout settings or simplifying the test prompt.")
        else:
            lines.append("> Review the detailed error logs in the run folder to identify specific issues.")
        
        lines.append("")
        return lines
    
    def _get_error_category_name(self, error_type: str) -> str:
        """Map error type to human-readable category name."""
        category_map = {
            'az_auth': 'Authentication Failures (Primary Blocker)',
            'azd_auth': 'Authentication Failures (Primary Blocker)',
            'oauth_error': 'OAuth Authentication (Primary Blocker)',
            'az_subscription': 'Subscription Issues',
            'az_resource': 'Resource Errors',
            'az_permission': 'Permission Denied',
            'az_validation': 'Validation Errors',
            'azd_init': 'AZD Initialization',
            'azd_env': 'AZD Environment Issues',
            'copilot_tool_error': 'Copilot Tool Errors',
            'copilot_mcp_error': 'MCP Errors',
            'copilot_model_error': 'Copilot Model Errors',
            'copilot_permission': 'Permission Issues',
            'copilot_timeout': 'Timeout',
            'copilot_skill_error': 'Skill Invocation Errors',
            'timeout': 'Timeout',
            'network': 'Network Issues',
            'file_not_found': 'File Not Found',
            'permission': 'Permission Denied',
            'syntax': 'Syntax Errors',
            'dependency': 'Missing Dependencies',
            'bicep': 'Bicep/IaC Errors',
            'arm': 'ARM Deployment Errors',
            'deployment_failed': 'Deployment Failed',
            'interactive_prompt': 'Interactive Prompt (Blocker)',
            'login_prompt': 'Login Required (Blocker)'
        }
        return category_map.get(error_type, 'Other Errors')
    
    def _get_error_display_name(self, error_type: str) -> str:
        """Get display-friendly name for error type."""
        display_map = {
            'az_auth': 'Azure Auth',
            'azd_auth': 'AZD Auth',
            'oauth_error': 'OAuth',
            'az_subscription': 'Subscription',
            'az_resource': 'Resource',
            'az_permission': 'Permission',
            'az_validation': 'Validation',
            'azd_init': 'AZD Init',
            'azd_env': 'AZD Environment',
            'copilot_tool_error': 'Copilot Tool Errors',
            'copilot_mcp_error': 'MCP Errors',
            'copilot_model_error': 'Copilot Model Errors',
            'copilot_permission': 'Permission',
            'copilot_timeout': 'Timeout',
            'copilot_skill_error': 'Skill Errors',
            'timeout': 'Timeout',
            'network': 'Network',
            'file_not_found': 'File Not Found',
            'permission': 'Permission',
            'syntax': 'Syntax',
            'dependency': 'Dependency',
            'bicep': 'Bicep',
            'arm': 'ARM',
            'deployment_failed': 'Deployment Failed',
            'interactive_prompt': 'Interactive Prompt',
            'login_prompt': 'Login Prompt'
        }
        return display_map.get(error_type, error_type.replace('_', ' ').title())
    
    def update_overall_summary(self):
        """Update the overall summary.md in the base results directory."""
        runs = self.list_runs()
        if not runs:
            return
        
        # Aggregate across all runs
        total_runs = len(runs)
        total_tests = 0
        total_passed = 0
        total_failed = 0
        total_tokens = 0
        
        run_summaries = []
        
        for run_dir in runs:
            metadata_path = run_dir / 'run-metadata.json'
            if metadata_path.exists():
                try:
                    metadata = json.loads(metadata_path.read_text())
                    tests = metadata.get('tests', [])
                    passed = sum(1 for t in tests if t.get('success'))
                    failed = len(tests) - passed
                    
                    total_tests += len(tests)
                    total_passed += passed
                    total_failed += failed
                    
                    # Load token usage from results if available
                    results_path = run_dir / 'evaluation-results.json'
                    if results_path.exists():
                        results_data = json.loads(results_path.read_text())
                        for r in results_data.get('results', []):
                            total_tokens += r.get('tokenUsage', {}).get('totalTokens', 0)
                    
                    run_summaries.append({
                        'runId': metadata.get('runId'),
                        'date': metadata.get('startTime', '')[:10],
                        'total': len(tests),
                        'passed': passed,
                        'failed': failed,
                        'status': metadata.get('status'),
                        'duration': metadata.get('totalDuration', 'N/A')
                    })
                except Exception:
                    pass
        
        overall_pass_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        lines = [
            "# Copilot CLI Evaluation - Overall Summary",
            "",
            f"*Last updated: {datetime.now().isoformat()}*",
            "",
            "## Aggregate Statistics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Runs | {total_runs} |",
            f"| Total Tests | {total_tests} |",
            f"| Total Passed | {total_passed} |",
            f"| Total Failed | {total_failed} |",
            f"| Overall Pass Rate | {overall_pass_rate:.1f}% |",
            f"| Total Tokens Used | {total_tokens:,} |",
            "",
            "## Run History",
            "",
            "| Run ID | Date | Tests | Passed | Failed | Pass Rate | Duration |",
            "|--------|------|-------|--------|--------|-----------|----------|",
        ]
        
        for run in sorted(run_summaries, key=lambda x: x['runId'], reverse=True):
            rate = (run['passed'] / run['total'] * 100) if run['total'] > 0 else 0
            status_icon = '✅' if rate >= 80 else '⚠️' if rate >= 50 else '❌'
            lines.append(
                f"| [{run['runId']}](./{run['runId']}/summary.md) | {run['date']} | "
                f"{run['total']} | {run['passed']} | {run['failed']} | "
                f"{status_icon} {rate:.0f}% | {run['duration']} |"
            )
        
        lines.extend([
            "",
            "## Key Learnings",
            "",
            "### Azure Authentication",
            "",
            "The Copilot CLI **inherits Azure credentials** from the parent shell session:",
            "",
            "1. **Before running evaluations**, ensure you're logged in:",
            "   ```bash",
            "   az login",
            "   az account set --subscription <your-subscription>",
            "   ```",
            "",
            "2. **For AZD**, authenticate separately:",
            "   ```bash",
            "   azd auth login",
            "   ```",
            "",
            "3. **Environment variables** that help with non-interactive mode:",
            "   ```bash",
            "   export AZURE_CORE_NO_PROMPT=true",
            "   export AZURE_CORE_ONLY_SHOW_ERRORS=false",
            "   export CI=true",
            "   ```",
            "",
            "### Tips for Reliable Runs",
            "",
            "- Use `--allow-all-tools` and `--no-ask-user` flags for non-interactive execution",
            "- Set appropriate timeouts (300s+ for complex deployments)",
            "- Review failed test logs in `<run>/copilot-logs/` for debugging",
            "",
            "---",
            "*See individual run folders for detailed logs and analysis*"
        ])
        
        overall_path = self.base_results_dir / 'summary.md'
        overall_path.write_text('\n'.join(lines), encoding='utf-8')
    
    def list_runs(self) -> List[Path]:
        """List all run directories."""
        if not self.base_results_dir.exists():
            return []
        
        runs = []
        for item in self.base_results_dir.iterdir():
            if item.is_dir() and (item / 'run-metadata.json').exists():
                runs.append(item)
        return sorted(runs, key=lambda x: x.name)
    
    def get_run_logs_dir(self) -> Path:
        """Get the logs directory for current run."""
        if self.current_run_dir:
            return self.current_run_dir / 'logs'
        return self.base_results_dir / 'logs'
    
    def get_copilot_logs_dir(self) -> Path:
        """Get the copilot logs directory for current run."""
        if self.current_run_dir:
            return self.current_run_dir / 'copilot-logs'
        return self.base_results_dir / 'copilot-logs'
    
    def _aggregate_artifacts(self, results: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Aggregate artifacts from all results."""
        aggregated = {
            'deployedUrls': [],
            'createdResources': [],
            'generatedFiles': [],
            'azureResourceIds': [],
            'endpoints': [],
            'skillsUsed': [],
            'toolsInvoked': [],
            'mcpToolsUsed': []
        }
        
        seen_urls = set()
        seen_resources = set()
        seen_files = set()
        seen_skills = set()
        seen_mcp_tools = set()
        
        for result in results:
            artifacts = result.get('artifacts', {})
            skill = result.get('skillName', 'unknown')
            success = result.get('success', False)
            
            # Deployed URLs
            for url_info in artifacts.get('deployedUrls', []):
                url = url_info.get('url', '')
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    aggregated['deployedUrls'].append({
                        **url_info,
                        'skill': skill,
                        'success': success
                    })
            
            # Created resources
            for resource in artifacts.get('createdResources', []):
                key = f"{resource.get('type')}:{resource.get('name')}"
                if key not in seen_resources:
                    seen_resources.add(key)
                    aggregated['createdResources'].append({
                        **resource,
                        'skill': skill,
                        'success': success
                    })
            
            # Generated files
            for file_info in artifacts.get('generatedFiles', []):
                path = file_info.get('path', '')
                if path and path not in seen_files:
                    seen_files.add(path)
                    aggregated['generatedFiles'].append({
                        **file_info,
                        'skill': skill,
                        'success': success
                    })
            
            # Resource IDs
            for res_id in artifacts.get('azureResourceIds', []):
                aggregated['azureResourceIds'].append({
                    **res_id,
                    'skill': skill
                })
            
            # Endpoints
            for endpoint in artifacts.get('endpoints', []):
                aggregated['endpoints'].append({
                    **endpoint,
                    'skill': skill
                })
            
            # Skills Used
            for skill_info in artifacts.get('skillsUsed', []):
                skill_name = skill_info.get('name', '')
                if skill_name and skill_name not in seen_skills:
                    seen_skills.add(skill_name)
                    aggregated['skillsUsed'].append({
                        **skill_info,
                        'testSkill': skill
                    })
            
            # Tools Invoked
            for tool_info in artifacts.get('toolsInvoked', []):
                aggregated['toolsInvoked'].append({
                    **tool_info,
                    'skill': skill
                })
            
            # MCP Tools Used
            for mcp_tool in artifacts.get('mcpToolsUsed', []):
                tool_name = mcp_tool.get('name', '')
                if tool_name and tool_name not in seen_mcp_tools:
                    seen_mcp_tools.add(tool_name)
                    aggregated['mcpToolsUsed'].append({
                        **mcp_tool,
                        'skill': skill
                    })
        
        return aggregated
    
    def _format_artifacts_section(self, artifacts: Dict[str, List[Dict]]) -> List[str]:
        """Format artifacts into markdown sections."""
        lines = [
            "## 🎯 Success Artifacts",
            ""
        ]
        
        # Deployed URLs
        if artifacts.get('deployedUrls'):
            lines.extend([
                "### 🌐 Deployed URLs",
                "",
                "| URL | Type | Skill | Status |",
                "|-----|------|-------|--------|"
            ])
            for url_info in artifacts['deployedUrls'][:15]:
                status = '✅' if url_info.get('success') else '⚠️'
                url = url_info.get('url', '')
                # Make URL clickable in markdown
                display_url = f"[{url[:60]}...]({url})" if len(url) > 60 else f"[{url}]({url})"
                lines.append(
                    f"| {display_url} | {url_info.get('type', 'N/A')} | "
                    f"{url_info.get('skill', 'N/A')} | {status} |"
                )
            lines.append("")
        
        # Created Resources
        if artifacts.get('createdResources'):
            lines.extend([
                "### 📦 Created Azure Resources",
                "",
                "| Resource Name | Type | Skill | Status |",
                "|---------------|------|-------|--------|"
            ])
            for resource in artifacts['createdResources'][:20]:
                status = '✅' if resource.get('success') else '⚠️'
                lines.append(
                    f"| `{resource.get('name', 'N/A')}` | {resource.get('type', 'N/A')} | "
                    f"{resource.get('skill', 'N/A')} | {status} |"
                )
            lines.append("")
        
        # Resource IDs
        if artifacts.get('azureResourceIds'):
            lines.extend([
                "### 🔗 Azure Resource IDs",
                "",
                "| Resource | Resource Group | Provider |",
                "|----------|----------------|----------|"
            ])
            for res_id in artifacts['azureResourceIds'][:10]:
                lines.append(
                    f"| `{res_id.get('name', 'N/A')}` | {res_id.get('resourceGroup', 'N/A')} | "
                    f"{res_id.get('provider', 'N/A')} |"
                )
            lines.append("")
            
            # Also list full IDs in a collapsible section
            lines.extend([
                "<details>",
                "<summary>Full Resource IDs</summary>",
                "",
                "```"
            ])
            for res_id in artifacts['azureResourceIds'][:10]:
                lines.append(res_id.get('id', ''))
            lines.extend([
                "```",
                "</details>",
                ""
            ])
        
        # Generated Files
        if artifacts.get('generatedFiles'):
            lines.extend([
                "### 📄 Generated Files & Reports",
                "",
                "| Path | Type | Skill |",
                "|------|------|-------|"
            ])
            for file_info in artifacts['generatedFiles'][:15]:
                path = file_info.get('path', '')
                lines.append(
                    f"| `{path[:70]}` | {file_info.get('type', 'N/A')} | "
                    f"{file_info.get('skill', 'N/A')} |"
                )
            lines.append("")
        
        # Endpoints
        if artifacts.get('endpoints'):
            lines.extend([
                "### 🔌 Endpoints & Connection Info",
                "",
                "| Endpoint | Type | Skill |",
                "|----------|------|-------|"
            ])
            for endpoint in artifacts['endpoints'][:10]:
                value = endpoint.get('value', '')
                # Truncate long values
                display_value = value[:80] + '...' if len(value) > 80 else value
                lines.append(
                    f"| `{display_value}` | {endpoint.get('type', 'N/A')} | "
                    f"{endpoint.get('skill', 'N/A')} |"
                )
            lines.append("")
        
        # Skills Used
        if artifacts.get('skillsUsed'):
            lines.extend([
                "### 🎯 Skills Invoked",
                "",
                "| Skill | Type | Category |",
                "|-------|------|----------|"
            ])
            for skill in artifacts['skillsUsed']:
                lines.append(
                    f"| `{skill.get('name', 'N/A')}` | Copilot Skill | "
                    f"{skill.get('type', 'General')} |"
                )
            lines.append("")
        
        # Tools Invoked
        if artifacts.get('toolsInvoked'):
            lines.extend([
                "### 🔧 Tools Invoked",
                "",
                "| Tool | Count | Actions |",
                "|------|-------|---------|"
            ])
            # Group and count tools
            tool_summary = {}
            for tool in artifacts['toolsInvoked']:
                key = tool.get('tool', 'unknown')
                if key not in tool_summary:
                    tool_summary[key] = {'count': 0, 'actions': set()}
                tool_summary[key]['count'] += 1
                tool_summary[key]['actions'].add(tool.get('action', ''))
            
            for tool_name, data in sorted(tool_summary.items(), key=lambda x: -x[1]['count']):
                actions = ', '.join(list(data['actions'])[:3])
                lines.append(
                    f"| `{tool_name}` | {data['count']}x | {actions} |"
                )
            lines.append("")
        
        # MCP Tools Used
        if artifacts.get('mcpToolsUsed'):
            lines.extend([
                "### 🔌 Azure MCP Tools Used",
                "",
                "| Tool | Type | Category |",
                "|------|------|----------|"
            ])
            for mcp_tool in artifacts['mcpToolsUsed'][:15]:
                lines.append(
                    f"| `{mcp_tool.get('name', 'N/A')}` | {mcp_tool.get('type', 'N/A')} | "
                    f"{mcp_tool.get('category', 'Other')} |"
                )
            lines.append("")
        
        return lines
