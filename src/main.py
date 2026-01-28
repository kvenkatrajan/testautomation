#!/usr/bin/env python3
"""Main CLI entry point for Copilot CLI Evaluator."""

import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .prompts import load_prompts, load_config, filter_test_cases, get_skills_and_types
from .runner import CopilotCliRunner
from .results import ResultsManager
from .run_manager import RunManager

console = Console()


@click.command()
@click.option('-r', '--run', 'run_eval', is_flag=True, help='Run evaluation')
@click.option('-p', '--parallel', is_flag=True, help='Run tests in parallel tabs')
@click.option('--report', is_flag=True, help='Generate report from latest results')
@click.option('--list', 'list_items', is_flag=True, help='List available skills and task types')
@click.option('-c', '--config', 'config_path', default='config.json', help='Path to config file')
@click.option('--prompts', 'prompts_path', default='azure-skills-prompts.json', help='Path to prompts file')
@click.option('-s', '--skills', help='Comma-separated list of skills to test')
@click.option('-t', '--task-types', help='Comma-separated list of task types to test')
@click.option('-l', '--limit', type=int, help='Limit number of tests')
@click.option('--random', 'randomize', is_flag=True, help='Randomize test order')
@click.option('-o', '--output', help='Output results filename')
@click.option('-w', '--work-dir', default='.', help='Working directory for tests')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
@click.option('--adhoc', help='Run a single ad-hoc prompt')
@click.option('--adhoc-skill', default='adhoc', help='Skill name for ad-hoc prompt')
@click.option('--adhoc-type', default='adhoc', help='Task type for ad-hoc prompt')
@click.option('-i', '--interactive', is_flag=True, help='Interactive mode - select prompts to run')
@click.option('--dry-run', is_flag=True, help='Show what would be run without executing')
@click.option('-m', '--model', help='Model to use for testing (e.g., claude-opus-4.5, gpt-5)')
@click.option('--run-name', help='Custom name for this evaluation run')
@click.option('--no-run-folder', is_flag=True, help='Disable run-based folder organization')
@click.version_option(version='1.0.0')
def main(
    run_eval, parallel, report, list_items, config_path, prompts_path,
    skills, task_types, limit, randomize, output, work_dir, verbose,
    adhoc, adhoc_skill, adhoc_type, interactive, dry_run, model,
    run_name, no_run_folder
):
    """Evaluation tool for Copilot CLI Azure skills."""
    try:
        root_dir = Path.cwd()
        
        # Load configuration
        config_file = root_dir / config_path
        config = load_config(str(config_file))
        
        # Override with command line options
        if prompts_path:
            config['promptsFile'] = prompts_path
        if work_dir:
            config['workingDirectory'] = work_dir
        
        prompts_file = root_dir / config.get('promptsFile', 'azure-skills-prompts.json')
        results_dir = root_dir / config.get('resultsDir', 'results')
        
        # Ensure results directory exists
        results_dir.mkdir(parents=True, exist_ok=True)
        
        if list_items:
            list_skills_and_types(str(prompts_file))
            return
        
        if report:
            generate_report(str(results_dir))
            return
        
        if adhoc:
            run_adhoc_prompt(config, str(results_dir), adhoc, adhoc_skill, adhoc_type, 
                          verbose, dry_run, model, work_dir)
            return
        
        if run_eval or interactive:
            run_evaluation(config, str(prompts_file), str(results_dir),
                         skills, task_types, limit, randomize, output,
                         work_dir, verbose, parallel, interactive, dry_run, model,
                         run_name, no_run_folder)
            return
        
        # Default: show help
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run_evaluation(
    config, prompts_file, results_dir, skills, task_types, limit,
    randomize, output, work_dir, verbose, parallel, interactive, dry_run, model,
    run_name=None, no_run_folder=False
):
    """Run the evaluation."""
    console.print("\n[cyan]🚀 Starting Copilot CLI Evaluation[/cyan]\n")
    
    # Initialize run manager for run-based organization
    run_manager = None
    if not no_run_folder:
        run_manager = RunManager(results_dir)
        run_dir = run_manager.create_run(run_name)
        console.print(f"[dim]Run folder: {run_dir}[/dim]")
        # Update logs directory to use run folder
        config['logsDir'] = str(run_manager.get_run_logs_dir())
    
    # Apply model override
    if model:
        config['copilotOptions'] = config.get('copilotOptions', {})
        config['copilotOptions']['model'] = model
        console.print(f"[cyan]Using model: {model}[/cyan]\n")
    
    # Load test cases
    all_test_cases = load_prompts(prompts_file)
    console.print(f"[dim]Loaded {len(all_test_cases)} test cases from prompts file[/dim]")
    
    # Filter test cases
    skills_list = skills.split(',') if skills else None
    task_types_list = task_types.split(',') if task_types else None
    
    test_cases = filter_test_cases(
        all_test_cases,
        skills=skills_list,
        task_types=task_types_list,
        limit=limit,
        randomize=randomize
    )
    
    # Interactive mode
    if interactive:
        test_cases = interactive_select(test_cases, all_test_cases)
    
    console.print(f"[dim]Running {len(test_cases)} test cases[/dim]\n")
    
    if not test_cases:
        console.print("[yellow]No test cases to run. Check your filters.[/yellow]")
        return
    
    # Dry run mode
    if dry_run:
        console.print("[yellow]Dry run - showing what would be executed:[/yellow]\n")
        for tc in test_cases:
            console.print(f"  [{tc['taskType']}] {tc['skillName']}: \"{tc['prompt'][:50]}...\"")
        console.print(f"\n[dim]Total: {len(test_cases)} prompts would be executed[/dim]")
        return
    
    # Initialize runner and results
    runner = CopilotCliRunner(config)
    runner.initialize()
    
    results_manager = ResultsManager(
        str(run_manager.get_run_logs_dir().parent) if run_manager else results_dir
    )
    results_manager.initialize()
    
    # Set up callbacks
    if verbose:
        runner.on_started = lambda info: console.print(
            f"[blue]Starting: {info['skillName']} - \"{info['prompt'][:40]}...\"[/blue]"
        )
        runner.on_output = lambda info: console.print(f"[dim]{info['data']}[/dim]", end='')
    
    work_path = str(Path(config.get('workingDirectory', '.')).resolve())
    
    # Run tests
    run_sequential(runner, results_manager, test_cases, work_path, verbose, run_manager)
    
    # Finalize run and generate summaries
    if run_manager:
        summary_path = run_manager.finalize_run(results_manager.results)
        console.print(f"\n[green]✅ Run summary: {summary_path}[/green]")
        
        # Collect CLI session logs
        run_manager.collect_cli_session_state()
    
    # Save results
    saved_path = results_manager.save_results(output)
    console.print(f"\n[green]✅ Results saved to: {saved_path}[/green]")
    
    # Print report
    report_text = results_manager.generate_report()
    console.print(report_text)


def run_sequential(runner, results_manager, test_cases, work_dir, verbose, run_manager=None):
    """Run tests sequentially."""
    total = len(test_cases)
    
    for i, test_case in enumerate(test_cases, 1):
        progress = f"[{i}/{total}]"
        console.print(f"[yellow]{progress} Testing: {test_case['skillName']}[/yellow]")
        console.print(f"[dim]  Prompt: \"{test_case['prompt'][:50]}...\"[/dim]")
        
        result = runner.run_prompt(
            test_case['skillName'],
            test_case['taskType'],
            test_case['prompt'],
            work_dir
        )
        
        results_manager.add_result(result)
        
        # Track in run manager
        if run_manager:
            run_manager.add_test_result(result)
            # Collect copilot logs for this session
            if result.get('copilotLogDir'):
                run_manager.collect_copilot_session_logs(
                    Path(result['copilotLogDir']),
                    result['sessionId']
                )
        
        if result['success']:
            console.print(f"[green]  ✓ Passed ({result['duration']}ms, {result['retryCount']} retries)[/green]")
        else:
            console.print(f"[red]  ✗ Failed: {result['outcome']}[/red]")
            if verbose:
                for cp in result.get('checkpoints', []):
                    console.print(f"[red]    - {cp['event']}: {cp.get('reason', 'unknown')}[/red]")
                for err in result.get('extractedErrors', [])[:3]:
                    console.print(f"[red]    [{err['type']}] {err['message']}[/red]")
        
        if verbose:
            console.print(f"[dim]    Log: {result.get('logFile')}[/dim]")


def generate_report(results_dir):
    """Generate report from latest results."""
    results_manager = ResultsManager(results_dir)
    
    files = results_manager.list_result_files()
    if not files:
        console.print("[yellow]No results files found.[/yellow]")
        return
    
    # Load latest
    files.sort(reverse=True)
    latest_file = files[0]
    console.print(f"[cyan]Loading results from: {latest_file}[/cyan]\n")
    
    data = results_manager.load_previous_results(latest_file)
    results_manager.results = data.get('results', [])
    
    report_text = results_manager.generate_report()
    console.print(report_text)


def list_skills_and_types(prompts_file):
    """List available skills and task types."""
    all_test_cases = load_prompts(prompts_file)
    info = get_skills_and_types(all_test_cases)
    
    console.print("\n[cyan]📋 Available Skills:[/cyan]\n")
    table = Table(show_header=True)
    table.add_column("Skill", style="yellow")
    table.add_column("Prompts", justify="right")
    
    for skill, count in sorted(info['skills'].items()):
        table.add_row(skill, str(count))
    
    console.print(table)
    
    console.print("\n[cyan]📋 Available Task Types:[/cyan]\n")
    table2 = Table(show_header=True)
    table2.add_column("Task Type", style="yellow")
    table2.add_column("Prompts", justify="right")
    
    for task_type, count in sorted(info['taskTypes'].items()):
        table2.add_row(task_type, str(count))
    
    console.print(table2)
    console.print(f"\n[dim]Total: {len(all_test_cases)} prompts[/dim]\n")


def run_adhoc_prompt(config, results_dir, prompt, skill, task_type, verbose, dry_run, model, work_dir):
    """Run a single ad-hoc prompt."""
    console.print("\n[cyan]🚀 Running Ad-hoc Prompt[/cyan]\n")
    
    # Apply model override
    if model:
        config['copilotOptions'] = config.get('copilotOptions', {})
        config['copilotOptions']['model'] = model
    
    console.print(f"[dim]Skill: {skill}[/dim]")
    console.print(f"[dim]Task Type: {task_type}[/dim]")
    console.print(f"[dim]Prompt: \"{prompt}\"[/dim]\n")
    
    if dry_run:
        console.print("[yellow]Dry run - not executing[/yellow]")
        return
    
    # Initialize run manager for run-based organization
    run_manager = RunManager(results_dir)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir = run_manager.create_run(f"testrun_{timestamp}")
    console.print(f"[dim]Run folder: {run_dir}[/dim]\n")
    
    # Update logs directory to use run folder
    config['logsDir'] = str(run_manager.get_run_logs_dir())
    
    runner = CopilotCliRunner(config)
    runner.initialize()
    
    results_manager = ResultsManager(str(run_manager.get_run_logs_dir().parent))
    results_manager.initialize()
    
    if verbose:
        runner.on_output = lambda info: console.print(f"[dim]{info['data']}[/dim]", end='')
    
    work_path = str(Path(work_dir).resolve())
    result = runner.run_prompt(skill, task_type, prompt, work_path)
    
    results_manager.add_result(result)
    
    # Track in run manager
    run_manager.add_test_result(result)
    
    # Collect copilot logs for this session
    if result.get('copilotLogDir'):
        run_manager.collect_copilot_session_logs(
            Path(result['copilotLogDir']),
            result['sessionId']
        )
    
    # Finalize run and generate summaries
    summary_path = run_manager.finalize_run(results_manager.results)
    
    # Collect CLI session logs
    run_manager.collect_cli_session_state()
    
    # Print comprehensive summary
    print_run_summary(result, run_manager, summary_path)


def print_run_summary(result, run_manager, summary_path):
    """Print comprehensive run summary to console."""
    from rich.panel import Panel
    from rich.table import Table
    
    # Status - check for alerts
    alerts = result.get('alerts', [])
    has_alerts = len(alerts) > 0
    
    if result['success'] and has_alerts:
        status = "✅ PASSED (with alerts)"
        status_color = "green"
    elif result['success']:
        status = "✅ PASSED"
        status_color = "green"
    else:
        status = "❌ FAILED"
        status_color = "red"
    
    console.print(f"\n[bold {status_color}]{'=' * 60}[/bold {status_color}]")
    console.print(f"[bold {status_color}]                    RUN SUMMARY: {status}[/bold {status_color}]")
    console.print(f"[bold {status_color}]{'=' * 60}[/bold {status_color}]\n")
    
    # Basic info table
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Label", style="cyan")
    info_table.add_column("Value")
    
    info_table.add_row("Run ID", run_manager.run_id)
    info_table.add_row("Skill", result.get('skillName', 'N/A'))
    info_table.add_row("Task Type", result.get('taskType', 'N/A'))
    info_table.add_row("Model", result.get('model', 'N/A'))
    info_table.add_row("Duration", f"{result.get('duration', 0):,}ms")
    info_table.add_row("Retry Attempts", str(result.get('retryCount', 0)))
    info_table.add_row("Outcome", result.get('outcome', 'N/A'))
    
    console.print(info_table)
    
    # Token usage
    token_usage = result.get('tokenUsage', {})
    if token_usage.get('totalTokens', 0) > 0:
        console.print(f"\n[cyan]Token Usage:[/cyan]")
        console.print(f"  Input: {token_usage.get('inputTokens', 0):,}")
        console.print(f"  Output: {token_usage.get('outputTokens', 0):,}")
        console.print(f"  Total: {token_usage.get('totalTokens', 0):,}")
    
    # Alerts section (for success with alerts)
    if result['success'] and has_alerts:
        console.print(f"\n[yellow]⚠️ Alerts ({len(alerts)} - did not block success):[/yellow]")
        seen = set()
        for alert in alerts[:5]:
            msg = alert.get('message', '')[:60]
            if msg not in seen:
                seen.add(msg)
                console.print(f"  • [{alert.get('type')}] {msg}")
        if len(alerts) > 5:
            console.print(f"  [dim]...and {len(alerts) - 5} more[/dim]")
    
    # Failure details
    if not result['success']:
        console.print(f"\n[red]Failure Summary:[/red]")
        console.print(f"  Outcome: {result.get('outcome', 'Unknown')}")
        
        # Checkpoints
        checkpoints = result.get('checkpoints', [])
        if checkpoints:
            console.print(f"\n[red]Failed Checkpoints:[/red]")
            for cp in checkpoints[:5]:
                console.print(f"  • [{cp.get('event')}] {cp.get('reason', 'No reason')}")
        
        # Errors
        errors = result.get('extractedErrors', [])
        if errors:
            console.print(f"\n[red]Errors ({len(errors)} total):[/red]")
            for err in errors[:5]:
                msg = err.get('message', '')[:80]
                console.print(f"  • [{err.get('type')}] {msg}")
    
    # Artifacts
    artifacts = result.get('artifacts', {})
    has_artifacts = any(artifacts.get(k) for k in ['deployedUrls', 'createdResources', 'generatedFiles', 'azureResourceIds'])
    
    if has_artifacts:
        console.print(f"\n[green]🎯 Artifacts:[/green]")
        
        # Deployed URLs
        deployed_urls = artifacts.get('deployedUrls', [])
        if deployed_urls:
            console.print(f"\n  [cyan]Deployed URLs ({len(deployed_urls)}):[/cyan]")
            for url_info in deployed_urls[:5]:
                console.print(f"    🌐 [{url_info.get('type')}] {url_info.get('url')}")
        
        # Created resources
        resources = artifacts.get('createdResources', [])
        if resources:
            console.print(f"\n  [cyan]Created Azure Resources ({len(resources)}):[/cyan]")
            for res in resources[:5]:
                console.print(f"    📦 [{res.get('type')}] {res.get('name')}")
        
        # Generated files
        files = artifacts.get('generatedFiles', [])
        if files:
            console.print(f"\n  [cyan]Generated Files ({len(files)}):[/cyan]")
            for f in files[:5]:
                console.print(f"    📄 {f.get('path')}")
        
        # Azure resource IDs
        resource_ids = artifacts.get('azureResourceIds', [])
        if resource_ids:
            console.print(f"\n  [cyan]Azure Resource IDs ({len(resource_ids)}):[/cyan]")
            for res_id in resource_ids[:3]:
                console.print(f"    🔗 {res_id.get('name')} ({res_id.get('resourceGroup')})")
    
    # File locations
    console.print(f"\n[dim]{'─' * 50}[/dim]")
    console.print(f"[dim]Summary:     {summary_path}[/dim]")
    console.print(f"[dim]Log file:    {result.get('logFile')}[/dim]")
    console.print(f"[dim]Run folder:  {run_manager.current_run_dir}[/dim]")
    console.print(f"[dim]{'─' * 50}[/dim]\n")


def interactive_select(test_cases, all_test_cases):
    """Interactive prompt selection."""
    info = get_skills_and_types(all_test_cases)
    
    console.print("\n[cyan]📋 Select what to run:[/cyan]\n")
    console.print("  1. All prompts")
    console.print("  2. By skill")
    console.print("  3. By task type")
    console.print("  4. Pick specific prompts")
    console.print("  5. Enter ad-hoc prompt")
    
    choice = click.prompt("\nChoice (1-5)", type=str, default="1")
    
    if choice == '1':
        return test_cases
    
    elif choice == '2':
        skill_list = list(info['skills'].keys())
        console.print("\n[cyan]Available skills:[/cyan]")
        for i, s in enumerate(skill_list, 1):
            console.print(f"  {i}. {s} ({info['skills'][s]} prompts)")
        selection = click.prompt("\nEnter skill numbers (comma-separated) or names", type=str)
        selected = _parse_selection(selection, skill_list)
        return [tc for tc in test_cases if tc['skillName'] in selected]
    
    elif choice == '3':
        type_list = list(info['taskTypes'].keys())
        console.print("\n[cyan]Available task types:[/cyan]")
        for i, t in enumerate(type_list, 1):
            console.print(f"  {i}. {t} ({info['taskTypes'][t]} prompts)")
        selection = click.prompt("\nEnter type numbers (comma-separated) or names", type=str)
        selected = _parse_selection(selection, type_list)
        return [tc for tc in test_cases if tc['taskType'] in selected]
    
    elif choice == '4':
        console.print("\n[cyan]Available prompts:[/cyan]")
        for i, tc in enumerate(test_cases[:50], 1):
            console.print(f"  {i:3}. [{tc['skillName']}] {tc['prompt'][:50]}...")
        if len(test_cases) > 50:
            console.print(f"[dim]  ... and {len(test_cases) - 50} more[/dim]")
        selection = click.prompt("\nEnter prompt numbers (comma-separated, ranges like 1-5)", type=str)
        indices = _parse_number_ranges(selection)
        return [tc for i, tc in enumerate(test_cases, 1) if i in indices]
    
    elif choice == '5':
        prompt = click.prompt("\nEnter your prompt", type=str)
        skill = click.prompt("Skill name", type=str, default="adhoc")
        task_type = click.prompt("Task type", type=str, default="adhoc")
        return [{
            'skillName': skill,
            'taskType': task_type,
            'description': 'Interactive ad-hoc prompt',
            'prompt': prompt
        }]
    
    console.print("[yellow]Invalid choice, running all prompts[/yellow]")
    return test_cases


def _parse_selection(input_str, items):
    """Parse selection string into list of items."""
    result = []
    for part in input_str.split(','):
        part = part.strip()
        try:
            num = int(part)
            if 1 <= num <= len(items):
                result.append(items[num - 1])
        except ValueError:
            if part in items:
                result.append(part)
    return result


def _parse_number_ranges(input_str):
    """Parse number ranges like '1,3,5-10'."""
    result = []
    for part in input_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                result.extend(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                result.append(int(part))
            except ValueError:
                pass
    return result


if __name__ == '__main__':
    main()
