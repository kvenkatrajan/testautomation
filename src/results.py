"""Results tracking and report generation."""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class ResultsManager:
    """Manages test results and generates reports."""
    
    def __init__(self, results_dir: str):
        self.results_dir = Path(results_dir)
        self.results: List[Dict[str, Any]] = []
    
    def initialize(self):
        """Create results directory if it doesn't exist."""
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def add_result(self, result: Dict[str, Any]):
        """Add a test result."""
        self.results.append(result)
    
    def save_results(self, filename: Optional[str] = None) -> Path:
        """Save results to JSON file."""
        timestamp = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
        output_file = filename or f"evaluation-results-{timestamp}.json"
        output_path = self.results_dir / output_file
        
        summary = self.generate_summary()
        
        output = {
            'metadata': {
                'generatedAt': datetime.now().isoformat(),
                'totalTests': len(self.results),
                **summary
            },
            'results': self.results
        }
        
        output_path.write_text(json.dumps(output, indent=2, default=str), encoding='utf-8')
        return output_path
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics from results."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.get('success', False))
        failed = total - passed
        
        # Aggregate token usage
        token_usage = {
            'totalInputTokens': 0,
            'totalOutputTokens': 0,
            'totalTokens': 0,
            'avgInputTokens': 0,
            'avgOutputTokens': 0,
            'avgTotalTokens': 0
        }
        
        for result in self.results:
            if result.get('tokenUsage'):
                token_usage['totalInputTokens'] += result['tokenUsage'].get('inputTokens', 0)
                token_usage['totalOutputTokens'] += result['tokenUsage'].get('outputTokens', 0)
                token_usage['totalTokens'] += result['tokenUsage'].get('totalTokens', 0)
        
        if total > 0:
            token_usage['avgInputTokens'] = round(token_usage['totalInputTokens'] / total)
            token_usage['avgOutputTokens'] = round(token_usage['totalOutputTokens'] / total)
            token_usage['avgTotalTokens'] = round(token_usage['totalTokens'] / total)
        
        # Group by model
        by_model = {}
        for result in self.results:
            model = result.get('model', 'unknown')
            if model not in by_model:
                by_model[model] = {
                    'total': 0, 'passed': 0, 'failed': 0,
                    'totalTokens': 0, 'totalDuration': 0
                }
            by_model[model]['total'] += 1
            by_model[model]['totalDuration'] += result.get('duration', 0)
            if result.get('tokenUsage'):
                by_model[model]['totalTokens'] += result['tokenUsage'].get('totalTokens', 0)
            if result.get('success'):
                by_model[model]['passed'] += 1
            else:
                by_model[model]['failed'] += 1
        
        # Calculate averages
        for model in by_model:
            by_model[model]['avgDuration'] = round(by_model[model]['totalDuration'] / by_model[model]['total'])
            by_model[model]['avgTokens'] = round(by_model[model]['totalTokens'] / by_model[model]['total'])
            del by_model[model]['totalDuration']
        
        # Group by task type
        by_task_type = {}
        for result in self.results:
            task_type = result.get('taskType', 'unknown')
            if task_type not in by_task_type:
                by_task_type[task_type] = {'total': 0, 'passed': 0, 'failed': 0}
            by_task_type[task_type]['total'] += 1
            if result.get('success'):
                by_task_type[task_type]['passed'] += 1
            else:
                by_task_type[task_type]['failed'] += 1
        
        # Group by skill
        by_skill = {}
        for result in self.results:
            skill = result.get('skillName', 'unknown')
            if skill not in by_skill:
                by_skill[skill] = {'total': 0, 'passed': 0, 'failed': 0, 'totalRetries': 0}
            by_skill[skill]['total'] += 1
            by_skill[skill]['totalRetries'] += result.get('retryCount', 0)
            if result.get('success'):
                by_skill[skill]['passed'] += 1
            else:
                by_skill[skill]['failed'] += 1
        
        # Calculate avg retries
        for skill in by_skill:
            by_skill[skill]['avgRetries'] = by_skill[skill]['totalRetries'] / by_skill[skill]['total']
            del by_skill[skill]['totalRetries']
        
        # Collect failed checkpoints
        failed_checkpoints = [
            {
                'skillName': r.get('skillName'),
                'prompt': r.get('prompt'),
                'checkpoints': r.get('checkpoints', []),
                'extractedErrors': r.get('extractedErrors', []),
                'logFile': r.get('logFile')
            }
            for r in self.results if not r.get('success')
        ]
        
        # Aggregate error types
        error_type_count = {}
        for result in self.results:
            for err in result.get('extractedErrors', []):
                err_type = err.get('type', 'unknown')
                error_type_count[err_type] = error_type_count.get(err_type, 0) + 1
        
        # Aggregate artifacts
        artifacts_summary = self._aggregate_artifacts()
        
        return {
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'passRate': f"{(passed / total * 100):.2f}%" if total > 0 else "0%"
            },
            'tokenUsage': token_usage,
            'byModel': by_model,
            'byTaskType': by_task_type,
            'bySkill': by_skill,
            'errorTypeCount': error_type_count,
            'failedCheckpoints': failed_checkpoints,
            'artifacts': artifacts_summary
        }
    
    def load_previous_results(self, filename: str) -> Dict[str, Any]:
        """Load results from a previous run."""
        file_path = self.results_dir / filename
        return json.loads(file_path.read_text(encoding='utf-8'))
    
    def list_result_files(self) -> List[str]:
        """List all result files."""
        return [
            f.name for f in self.results_dir.iterdir()
            if f.name.startswith('evaluation-results-') and f.name.endswith('.json')
        ]
    
    def generate_report(self) -> str:
        """Generate a text report from results."""
        summary = self.generate_summary()
        
        lines = [
            '',
            '=' * 60,
            '           COPILOT CLI EVALUATION REPORT',
            '=' * 60,
            '',
            f"Total Tests: {summary['summary']['total']}",
            f"Passed: {summary['summary']['passed']}",
            f"Failed: {summary['summary']['failed']}",
            f"Pass Rate: {summary['summary']['passRate']}",
            '',
            '-' * 40,
            'Token Usage:',
            '-' * 40,
            f"  Total Input Tokens:  {summary['tokenUsage']['totalInputTokens']:,}",
            f"  Total Output Tokens: {summary['tokenUsage']['totalOutputTokens']:,}",
            f"  Total Tokens:        {summary['tokenUsage']['totalTokens']:,}",
            f"  Avg per Test:        {summary['tokenUsage']['avgTotalTokens']:,} tokens",
        ]
        
        # By model
        if summary['byModel']:
            lines.extend(['', '-' * 40, 'Results by Model:', '-' * 40])
            for model, stats in summary['byModel'].items():
                rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
                lines.append(
                    f"  {model:<25} {stats['passed']}/{stats['total']} ({rate:.1f}%) "
                    f"[{stats.get('avgTokens', 0)} avg tokens, {stats.get('avgDuration', 0)}ms avg]"
                )
        
        # By task type
        lines.extend(['', '-' * 40, 'Results by Task Type:', '-' * 40])
        for task_type, stats in summary['byTaskType'].items():
            rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
            lines.append(f"  {task_type:<15} {stats['passed']}/{stats['total']} ({rate:.1f}%)")
        
        # By skill
        lines.extend(['', '-' * 40, 'Results by Skill:', '-' * 40])
        for skill, stats in summary['bySkill'].items():
            rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
            lines.append(
                f"  {skill[:30]:<32} {stats['passed']}/{stats['total']} ({rate:.1f}%) "
                f"[avg retries: {stats.get('avgRetries', 0):.1f}]"
            )
        
        # Error types
        if summary['errorTypeCount']:
            lines.extend(['', '-' * 40, 'Errors by Type:', '-' * 40])
            sorted_errors = sorted(summary['errorTypeCount'].items(), key=lambda x: -x[1])
            for err_type, count in sorted_errors:
                lines.append(f"  {err_type:<25} {count} occurrence(s)")
        
        # Failed tests
        if summary['failedCheckpoints']:
            lines.extend(['', '-' * 40, 'Failed Tests:', '-' * 40])
            for failure in summary['failedCheckpoints']:
                lines.append(f"\n  Skill: {failure['skillName']}")
                lines.append(f"  Prompt: {failure['prompt'][:50]}...")
                if failure.get('logFile'):
                    lines.append(f"  Log: {failure['logFile']}")
                for cp in failure.get('checkpoints', []):
                    lines.append(f"    - {cp.get('event')}: {cp.get('reason', 'unknown')}")
                for err in failure.get('extractedErrors', [])[:3]:
                    lines.append(f"    - [{err.get('type')}] {err.get('message')}")
        
        # Artifacts summary
        artifacts = summary.get('artifacts', {})
        if any(artifacts.values()):
            lines.extend(['', '-' * 40, 'Success Artifacts:', '-' * 40])
            
            if artifacts.get('deployedUrls'):
                lines.append('\n  Deployed URLs:')
                for url_info in artifacts['deployedUrls'][:10]:
                    lines.append(f"    - [{url_info.get('type')}] {url_info.get('url')}")
            
            if artifacts.get('createdResources'):
                lines.append('\n  Created Resources:')
                for resource in artifacts['createdResources'][:10]:
                    lines.append(f"    - [{resource.get('type')}] {resource.get('name')}")
            
            if artifacts.get('generatedFiles'):
                lines.append('\n  Generated Files:')
                for file_info in artifacts['generatedFiles'][:5]:
                    lines.append(f"    - {file_info.get('path')}")
        
        lines.extend(['', '=' * 60])
        return '\n'.join(lines)
    
    def _aggregate_artifacts(self) -> Dict[str, List]:
        """Aggregate artifacts from all results."""
        aggregated = {
            'deployedUrls': [],
            'createdResources': [],
            'generatedFiles': [],
            'azureResourceIds': [],
            'endpoints': []
        }
        
        seen_urls = set()
        seen_resources = set()
        
        for result in self.results:
            artifacts = result.get('artifacts', {})
            skill = result.get('skillName', 'unknown')
            
            # Deployed URLs
            for url_info in artifacts.get('deployedUrls', []):
                url = url_info.get('url', '')
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    aggregated['deployedUrls'].append({
                        'url': url,
                        'type': url_info.get('type', 'Unknown'),
                        'skill': skill
                    })
            
            # Created resources
            for resource in artifacts.get('createdResources', []):
                key = f"{resource.get('type')}:{resource.get('name')}"
                if key not in seen_resources:
                    seen_resources.add(key)
                    aggregated['createdResources'].append({
                        'name': resource.get('name'),
                        'type': resource.get('type'),
                        'skill': skill
                    })
            
            # Generated files
            for file_info in artifacts.get('generatedFiles', []):
                aggregated['generatedFiles'].append({
                    'path': file_info.get('path'),
                    'type': file_info.get('type'),
                    'skill': skill
                })
            
            # Resource IDs
            for res_id in artifacts.get('azureResourceIds', []):
                aggregated['azureResourceIds'].append({
                    'id': res_id.get('id'),
                    'name': res_id.get('name'),
                    'resourceGroup': res_id.get('resourceGroup'),
                    'skill': skill
                })
            
            # Endpoints
            for endpoint in artifacts.get('endpoints', []):
                aggregated['endpoints'].append({
                    'value': endpoint.get('value'),
                    'type': endpoint.get('type'),
                    'skill': skill
                })
        
        return aggregated
