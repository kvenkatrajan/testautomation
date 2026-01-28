"""Prompt loading and filtering utilities."""

import json
import random
from pathlib import Path
from typing import List, Dict, Any, Optional


def load_prompts(prompts_file: str) -> List[Dict[str, Any]]:
    """Load test cases from prompts JSON file."""
    with open(prompts_file, 'r', encoding='utf-8') as f:
        skills = json.load(f)
    
    test_cases = []
    for skill_name, skill_data in skills.items():
        for prompt in skill_data.get('prompts', []):
            test_cases.append({
                'skillName': skill_name,
                'taskType': skill_data.get('taskType', 'unknown'),
                'description': skill_data.get('description', ''),
                'prompt': prompt
            })
    
    return test_cases


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from JSON file."""
    with open(config_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_skills_and_types(test_cases: List[Dict]) -> Dict[str, Dict[str, int]]:
    """Get counts of skills and task types."""
    skills = {}
    task_types = {}
    
    for tc in test_cases:
        skills[tc['skillName']] = skills.get(tc['skillName'], 0) + 1
        task_types[tc['taskType']] = task_types.get(tc['taskType'], 0) + 1
    
    return {'skills': skills, 'taskTypes': task_types}


def filter_test_cases(
    test_cases: List[Dict],
    skills: Optional[List[str]] = None,
    task_types: Optional[List[str]] = None,
    limit: Optional[int] = None,
    randomize: bool = False
) -> List[Dict]:
    """Filter test cases by skills, task types, limit, and randomization."""
    filtered = test_cases.copy()
    
    if skills:
        filtered = [tc for tc in filtered if tc['skillName'] in skills]
    
    if task_types:
        filtered = [tc for tc in filtered if tc['taskType'] in task_types]
    
    if randomize:
        random.shuffle(filtered)
    
    if limit and limit > 0:
        filtered = filtered[:limit]
    
    return filtered


def group_by_skill(test_cases: List[Dict]) -> Dict[str, List[Dict]]:
    """Group test cases by skill name."""
    grouped = {}
    for tc in test_cases:
        if tc['skillName'] not in grouped:
            grouped[tc['skillName']] = []
        grouped[tc['skillName']].append(tc)
    return grouped


def group_by_task_type(test_cases: List[Dict]) -> Dict[str, List[Dict]]:
    """Group test cases by task type."""
    grouped = {}
    for tc in test_cases:
        if tc['taskType'] not in grouped:
            grouped[tc['taskType']] = []
        grouped[tc['taskType']].append(tc)
    return grouped
