#!/usr/bin/env python3
"""Narrow, idempotent installer with same-parent snapshots and atomic replacements."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

import auto_audit as audit
import monitor

ROOTS = ['.claude/skills', '.codex/skills', '.agents/skills', '.hermes/skills',
         '.gemini/skills', '.gemini/config/skills', '.codebuddy/skills', '.qoder/skills',
         '.qoder-cn/skills', '.grok/skills', '.qwen/skills', '.kimi-code/skills',
         '.workbuddy/skills', '.workbuddy-ai/skills', '.zcode/skills', '.openclaw/skills',
         '.cursor/skills', '.trae-cn/skills', '.roo/skills', '.continue/skills',
         '.kiro/skills', '.aider-desk/skills', '.config/goose/skills']


def local_proxy_env():
    """Pass only credential-free loopback proxies to the GUI worker."""
    result = {}
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                 'http_proxy', 'https_proxy', 'all_proxy'):
        value = os.environ.get(name)
        if not value: continue
        try: parsed = urlsplit(value)
        except ValueError: continue
        if (parsed.scheme in {'http', 'https', 'socks5', 'socks5h'} and
                parsed.hostname in {'127.0.0.1', 'localhost', '::1'} and
                parsed.port and not parsed.username and not parsed.password):
            result[name] = value
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def replace(path, content, mode=0o600):
    data = content.encode() if isinstance(content, str) else content
    assert data
    if path.suffix == '.json': json.loads(data)
    if path.suffix == '.plist': plistlib.loads(data)
    if path.exists() and path.read_bytes() == data: return None
    before = digest(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = None
    if path.exists():
        backup = path.with_name(path.name + '.bak-' + time.strftime('%Y%m%d'))
        number = 1
        while backup.exists():
            number += 1
            backup = path.with_name(path.name + '.bak-' + time.strftime('%Y%m%d') + '-v' + str(number))
        shutil.copy2(path, backup)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(name, stat.S_IMODE(path.stat().st_mode) if path.exists() else mode)
        if digest(path) != before: raise ValueError('Concurrent modification: ' + str(path))
        assert Path(name).read_bytes() == data
        os.replace(name, path)
        assert path.read_bytes() == data
    finally:
        if os.path.exists(name): os.unlink(name)
    return {'path': str(path), 'before_sha256': before, 'after_sha256': digest(path),
            'backup': str(backup) if backup else None}


def settings_hook(data, command):
    hooks = data.setdefault('hooks', {})
    for event in ('SessionStart', 'UserPromptSubmit', 'PostToolUse', 'Stop'):
        entries = hooks.setdefault(event, [])
        if any(h.get('command') == command for item in entries for h in item.get('hooks', [])): continue
        item = {'hooks': [{'type': 'command', 'command': command, 'timeout': 5}]}
        if event == 'PostToolUse': item['matcher'] = '*'
        entries.append(item)
    return data


def plan():
    home = Path.home()
    skill = audit.REPO / 'automation/skills/nlpm-auto-audit'
    entry = home / '.local/bin/nlpm-auto-audit'
    python = Path(sys.executable).resolve()
    command = shlex.quote(str(entry)) + ' hook'
    replacements = {}
    replacements[entry] = '#!/bin/sh\nexec ' + shlex.quote(str(python)) + ' ' + shlex.quote(str(audit.REPO / 'automation/monitor.py')) + ' "$@"\n'
    for path in (home / '.claude/settings.json', home / '.codex/hooks.json'):
        if path.is_symlink(): path = path.resolve()
        data = json.loads(path.read_text()) if path.exists() else {}
        replacements[path] = json.dumps(settings_hook(data, command), ensure_ascii=False, indent=2) + '\n'
    config_path = audit.STATE / 'config.json'
    config = json.loads(config_path.read_text()) if config_path.exists() else {
        'backend': 'codex', 'debounce_seconds': 20, 'poll_seconds': 5,
        'timeout_seconds': 240, 'max_background_audits_per_hour': 6,
        'mode': 'read-only-audit', 'existing_corpus': 'baseline-without-model-audits'}
    replacements[config_path] = json.dumps(config, ensure_ascii=False, indent=2) + '\n'
    launch = home / 'Library/LaunchAgents/local.rex.nlpm-auto-audit.plist'
    replacements[launch] = plistlib.dumps({
        'Label': 'local.rex.nlpm-auto-audit',
        'ProgramArguments': [str(python), str(audit.REPO / 'automation/monitor.py'), 'daemon'],
        'WorkingDirectory': str(audit.REPO), 'RunAtLoad': True, 'KeepAlive': True,
        'ThrottleInterval': 30,
        'EnvironmentVariables': {'PATH': os.environ.get('PATH', '/usr/bin:/bin:/usr/sbin:/sbin'),
                                 **local_proxy_env()},
        'StandardOutPath': str(audit.STATE / 'daemon.stdout'),
        'StandardErrorPath': str(audit.STATE / 'daemon.stderr')})
    links, watchers = [], set()
    for relative in ROOTS:
        directory = home / relative
        if not directory.is_dir(): continue
        target = directory / 'nlpm-auto-audit'
        if os.path.lexists(target) and target.resolve() != skill.resolve(): raise ValueError('Existing conflicting entry: ' + str(target))
        if not os.path.lexists(target): links.append(target)
        for child in directory.iterdir():
            if child.is_dir() and not audit.forbidden(child) and not child.name.startswith('.') and not child.name.startswith('_'):
                watchers.add(str(child.resolve()))
    watchers.update([str(skill.resolve()), str(audit.REPO), str(home / 'Developer/cc-suite')])
    if (home / 'governance').is_dir(): watchers.add(str((home / 'governance').resolve()))
    return replacements, links, sorted(watchers), skill


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    replacements, links, watchers, skill = plan()
    changed = [str(p) for p, value in replacements.items() if not p.exists() or p.read_bytes() != (value.encode() if isinstance(value, str) else value)]
    if not args.apply:
        print(json.dumps({'files': changed, 'new_links': [str(p) for p in links], 'watch_roots': len(watchers)}, ensure_ascii=False))
        return 0
    # Validate canonical Skill YAML and all executable entrypoints before changing user config.
    report = audit.structural(skill, {'SKILL.md': (skill / 'SKILL.md').read_text()})
    if report['status'] != 'PASS': raise ValueError(json.dumps(report))
    for path in (audit.REPO / 'automation').glob('*.py'): compile(path.read_text(), str(path), 'exec')
    records = []
    for path, content in replacements.items():
        record = replace(path, content, 0o755 if path.name == 'nlpm-auto-audit' else 0o600)
        if record: records.append(record)
    for path in links:
        temp = path.with_name('.' + path.name + '.tmp-' + str(os.getpid()))
        os.symlink(skill, temp)
        if os.path.lexists(path): raise ValueError('Concurrent new Skill entry: ' + str(path))
        os.replace(temp, path)
    with monitor.registry() as data:
        for name in watchers:
            if name not in data['roots']: data['roots'].append(name)
        monitor.scan(data)
    paths = [Path.home() / relative / 'nlpm-auto-audit/SKILL.md' for relative in ROOTS if (Path.home() / relative).is_dir()]
    assert {str(p.resolve()) for p in paths} == {str(skill / 'SKILL.md')}
    assert len({p.stat().st_ino for p in paths}) == 1
    receipt = {'time': time.time(), 'files': records, 'new_links': [str(p) for p in links],
               'skill_roots': [str(p.parent.parent) for p in paths], 'unique_skill_inode': 1,
               'watch_roots': len(watchers), 'launch_agent': 'local.rex.nlpm-auto-audit'}
    path = audit.STATE / 'install-receipts' / (time.strftime('%Y%m%dT%H%M%S') + '-' + str(os.getpid()) + '.json')
    audit.atomic(path, receipt)
    print(json.dumps({'receipt': str(path), 'changed_files': len(records), 'new_links': len(links),
                      'skill_roots': len(paths), 'unique_skill_inode': 1, 'watch_roots': len(watchers)}, ensure_ascii=False))
    return 0


if __name__ == '__main__': sys.exit(main())
