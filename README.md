# Copilot CLI Evaluator

A Python CLI tool for evaluating Copilot CLI Azure skills. Runs prompts, captures detailed logs including Copilot debug output, and generates comprehensive reports with pass/fail analysis and token usage tracking.

## Features

- **Batch Testing**: Run multiple prompts from a JSON file
- **Ad-hoc Testing**: Test single prompts on demand
- **Filtering**: Filter by skill name, task type, or custom criteria
- **Model Selection**: Choose which model to use (default: claude-opus-4.5)
- **Token Tracking**: Track input/output tokens per test and aggregate
- **Detailed Logging**: Capture stdout, stderr, and Copilot debug logs
- **Log Analysis**: Automatically detect errors, warnings, and success indicators
- **Interactive Mode**: Select prompts interactively
- **Non-Interactive Azure**: Auto-configure az/azd for CI environments
- **Run-Based Organization**: Group results by evaluation run with timestamps
- **Auto-Generated Summaries**: summary.md for each run + overall summary

## Installation

`ash
pip install -r requirements.txt
`

## Quick Start

`ash
# List available skills and task types
python -m src.main --list

# Run all tests (creates timestamped run folder)
python -m src.main --run

# Run with custom run name
python -m src.main --run --run-name "release-test-v1.5"

# Run specific skill tests
python -m src.main --run --skills azure-functions,azure-cosmos-db

# Run with specific model
python -m src.main --run --model gpt-5 --limit 10

# Run ad-hoc prompt
python -m src.main --adhoc "Create an Azure Function with HTTP trigger"

# Dry run - see what would execute
python -m src.main --run --skills azure-deploy --dry-run

# Generate report from latest results
python -m src.main --report

# Disable run folder organization (flat results)
python -m src.main --run --no-run-folder
`

## CLI Options

`
Options:
  -r, --run              Run evaluation
  -p, --parallel         Run tests in parallel tabs
  --report               Generate report from latest results
  --list                 List available skills and task types
  -c, --config PATH      Path to config file (default: config.json)
  --prompts PATH         Path to prompts file
  -s, --skills TEXT      Comma-separated list of skills to test
  -t, --task-types TEXT  Comma-separated list of task types to test
  -l, --limit INTEGER    Limit number of tests
  --random               Randomize test order
  -o, --output TEXT      Output results filename
  -w, --work-dir TEXT    Working directory for tests (default: .)
  -v, --verbose          Verbose output
  --adhoc TEXT           Run a single ad-hoc prompt
  -i, --interactive      Interactive mode - select prompts to run
  --dry-run              Show what would be run without executing
  -m, --model TEXT       Model to use (default: claude-opus-4.5)
  --run-name TEXT        Custom name for this evaluation run
  --no-run-folder        Disable run-based folder organization
  --version              Show version
  -h, --help             Show help message
`

## Azure Authentication Inheritance

**Important**: Copilot CLI inherits Azure credentials from the parent shell session.

### Before Running Evaluations

`ash
# 1. Login to Azure CLI
az login

# 2. Set your subscription (optional)
az account set --subscription "My Subscription"

# 3. Login to AZD if needed
azd auth login

# 4. Now run evaluations
python -m src.main --run
`

### How Auth Inheritance Works

1. When you run `az login`, credentials are cached in `~/.azure/`
2. The Copilot CLI process inherits your shell's environment
3. Azure SDK automatically discovers cached credentials
4. No additional login is needed within Copilot CLI

### Environment Variables for CI

`ash
export AZURE_CORE_NO_PROMPT=true      # Prevents auth prompts
export AZURE_CORE_ONLY_SHOW_ERRORS=false
export AZURE_SUBSCRIPTION_ID=<guid>   # Pre-select subscription
export CI=true                        # Generic CI flag
`

## Results Structure

Results are now organized by run:

`
results/
├── summary.md                        # Overall summary across all runs
├── run_2026-01-28_14-30-00/
│   ├── summary.md                    # Run-specific summary with learnings
│   ├── evaluation-results.json       # Full results data
│   ├── run-metadata.json             # Run metadata (auth, env, timing)
│   ├── logs/                         # Session logs
│   ├── copilot-logs/                 # Copilot debug logs by session
│   └── session-logs/                 # CLI session state files
└── run_2026-01-28_10-15-00/
    └── ...
`

### Summary.md Contents

Each run generates a summary.md with:

- **Result Summary**: Pass/fail counts, pass rate
- **Token Usage**: Input/output/total tokens
- **Results by Skill**: Breakdown per skill
- **Issues Encountered**: Errors and their types
- **Azure Authentication**: Auth status at run time
- **Learnings**: Auto-generated insights

## Project Structure

`
.
├── azure-skills-prompts.json  # Test prompts by skill
├── config.json                # Configuration
├── requirements.txt           # Python dependencies
├── results/                   # Test results (organized by run)
│   ├── summary.md             # Overall summary
│   └── run_<timestamp>/       # Individual run folders
└── src/
    ├── main.py               # CLI entry point
    ├── runner.py             # Copilot CLI execution
    ├── results.py            # Results tracking
    ├── run_manager.py        # Run-based organization
    ├── prompts.py            # Prompt loading/filtering
    └── logger.py             # Log management/parsing
`

## Prerequisites

- Python 3.8+
- Copilot CLI installed and authenticated
- Azure CLI logged in (`az login`) for Azure-related tests
