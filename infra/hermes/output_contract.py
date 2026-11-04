"""Load the single SOC output skill; no tools, dispatch or status decisions."""
from pathlib import Path
import importlib.util
import re


def policy(directory=None):
    here = Path(__file__).resolve().parent if directory is None else Path(directory)
    candidates = [p for p in (here / 'skills/soc-output/SKILL.md', here / 'SKILL.md') if p.is_file()]
    if len(candidates) != 1:
        raise ValueError('soc_output_skill_missing_or_ambiguous')
    raw = candidates[0].read_bytes()
    return policy_text(raw)


def policy_text(raw):
    if not 1 <= len(raw) <= 16384:
        raise ValueError('soc_output_skill_size')
    text = raw.decode('utf-8')
    parts = text.split('---\n', 2)
    if (len(parts) != 3 or parts[0] or
            not re.search(r'^name: soc-output$', parts[1], re.M) or
            not re.search(r'^description: \S[^\r\n]+$', parts[1], re.M)):
        raise ValueError('soc_output_skill_frontmatter')
    body = parts[2].strip()
    markers = ('<!-- soc-output-policy:start -->', '<!-- soc-output-policy:end -->', 'SOC_OUTPUT_CONTRACT_V1')
    if (any(body.count(m) != 1 for m in markers) or
            not body.startswith(markers[0]) or not body.endswith(markers[1]) or
            not body.index(markers[0]) < body.index(markers[2]) < body.index(markers[1])):
        raise ValueError('soc_output_skill_contract')
    return body


def normalize_tables(text):
    path = Path(__file__).resolve().with_name('chat_markdown.py')
    spec = importlib.util.spec_from_file_location('_soc_output_markdown', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.normalize_tables(text)
