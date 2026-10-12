#!/usr/bin/env python3
"""Native hook queue plus a filesystem fallback for shared agent artifacts."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time

import auto_audit as audit


@contextmanager
def registry():
    state = audit.STATE
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / 'registry.lock').open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        path = state / 'registry.json'
        data = audit.load_json(path) if path.exists() else {'roots': [], 'baseline': {}, 'pending': {}, 'runs': []}
        yield data
        audit.atomic(path, data)


def inventory(root):
    result = {}
    for path in audit.observed_files(root):
        try: result[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError: continue
    return result


def scan(data, roots=None, now=None):
    now = time.time() if now is None else now
    for name in roots or data['roots']:
        root = Path(name)
        if not root.is_dir() or audit.forbidden(root): continue
        current = inventory(root)
        previous = data['baseline'].get(name)
        if previous is None:
            data['baseline'][name] = current
            continue  # existing corpus is baselined; never bulk-audit it on startup
        changed = {p for p in set(previous) | set(current) if previous.get(p) != current.get(p)}
        if changed:
            units = {str(audit.root_for(Path(p))) for p in changed}
            for unit in units:
                pending = data['pending'].setdefault(unit, {'paths': [], 'changed_at': now})
                pending['paths'] = sorted(set(pending['paths']) | changed)
                pending['changed_at'] = now
                pending.pop('blocked', None)
        data['baseline'][name] = current


def register(root):
    root = root.resolve()
    if not root.is_dir() or audit.forbidden(root) or root == Path.home(): return
    # Only a concrete artifact unit/project is registered; parent workspace routers aren't scanned broadly.
    if not ((root / '.git').exists() or (root / 'SKILL.md').is_file() or (root / '.claude-plugin').is_dir()): return
    with registry() as data:
        if str(root) not in data['roots']: data['roots'].append(str(root))
        scan(data, [str(root)])


def hook(payload):
    if os.environ.get('NLPM_AUTO_AUDIT_ACTIVE') == '1': return {}
    cwd = Path(payload.get('cwd') or os.getcwd()).resolve()
    event = payload.get('hook_event_name', '')
    if event in {'SessionStart', 'UserPromptSubmit'}:
        register(cwd)
        return {}
    raw = payload.get('tool_input') or payload.get('toolInput') or {}
    tool = str(payload.get('tool_name', '')).lower().split('__')[-1]
    names = [raw.get('file_path'), raw.get('path')] if tool in {'write', 'edit', 'multiedit', 'apply_patch'} else []
    # apply_patch and shell edits are also caught by snapshot comparison and the filesystem fallback.
    for name in names:
        if not isinstance(name, str): continue
        path = Path(name)
        if not path.is_absolute(): path = cwd / path
        if not path.is_file() or not audit.artifact(path): continue
        unit = audit.root_for(path)
        if audit.forbidden(unit) or unit == Path.home(): continue
        with registry() as data:
            data['pending'][str(unit)] = {'paths': [str(path.resolve())], 'changed_at': time.time()}
        register(unit)
    with registry() as data: scan(data, [str(cwd)] if str(cwd) in data['roots'] else [])
    return {}


def drain(config, now=None):
    now = time.time() if now is None else now
    with registry() as data:
        data['runs'] = [t for t in data['runs'] if now - t < 3600]
        ready = [(k, v) for k, v in data['pending'].items()
                 if now - v['changed_at'] >= config.get('debounce_seconds', 20) and not v.get('blocked')]
        if not ready: return 'IDLE'
        if len(data['runs']) >= config.get('max_background_audits_per_hour', 6): return 'THROTTLED'
        name, task = sorted(ready, key=lambda item: item[1]['changed_at'])[0]
        claimed_at = task['changed_at']
        data['runs'].append(now)
    audit.atomic(audit.STATE / 'heartbeat.json', {'pid': os.getpid(), 'time': time.time(), 'status': 'RUNNING', 'root': name})
    report = audit.run(Path(name), config.get('backend', 'codex'),
                       config.get('timeout_seconds', 240), focus=task['paths'])
    with registry() as data:
        if report.get('deduplicated') and now in data['runs']: data['runs'].remove(now)
        task = data['pending'].get(name)
        if task and task['changed_at'] == claimed_at:
            if report['status'] in {'AUDIT_COMPLETE', 'FINDINGS'}: del data['pending'][name]
            elif report['status'] == 'STALE_SOURCE': task['changed_at'] = time.time()
            elif report['status'] != 'BUSY':
                task['blocked'] = report['status']
                task['report_path'] = report.get('report_path')
    return report['status']


def daemon():
    config = audit.load_json(audit.STATE / 'config.json')
    with (audit.STATE / 'daemon.lock').open('a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return
        def stop(*_): raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while True:
            try:
                with registry() as data: scan(data)
                status = drain(config)
                audit.atomic(audit.STATE / 'heartbeat.json', {'pid': os.getpid(), 'time': time.time(), 'status': status})
            except (OSError, ValueError) as exc:
                audit.atomic(audit.STATE / 'heartbeat.json', {'pid': os.getpid(), 'time': time.time(), 'status': 'BLOCKED_MONITOR', 'reason': str(exc)})
            time.sleep(config.get('poll_seconds', 5))


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    runner = sub.add_parser('run')
    runner.add_argument('root', nargs='?', type=Path, default=Path.cwd())
    runner.add_argument('--backend', choices=['codex', 'claude'], default='codex')
    runner.add_argument('--timeout', type=int, default=240)
    runner.add_argument('--threshold', type=int)
    runner.add_argument('--changed-path', action='append', dest='focus')
    sub.add_parser('hook')
    sub.add_parser('daemon')
    status = sub.add_parser('status')
    status.add_argument('root', nargs='?', type=Path)
    sub.add_parser('retry-blocked')
    args = parser.parse_args(argv)
    if args.command == 'run':
        options = [str(args.root), '--backend', args.backend, '--timeout', str(args.timeout)]
        if args.threshold is not None: options += ['--threshold', str(args.threshold)]
        for path in args.focus or []: options += ['--changed-path', path]
        return audit.main(options)
    if args.command == 'hook':
        try: print(json.dumps(hook(json.load(sys.stdin))))
        except (OSError, ValueError, TypeError) as exc:
            print(json.dumps({'systemMessage': 'NLPM auto-audit queue failed: ' + str(exc)}))
    elif args.command == 'daemon': daemon()
    elif args.command == 'retry-blocked':
        with registry() as data:
            for item in data['pending'].values(): item.pop('blocked', None)
    else:
        path = audit.STATE / 'registry.json'
        data = json.loads(path.read_text()) if path.exists() else {'roots': [], 'pending': {}}
        heartbeat = audit.STATE / 'heartbeat.json'
        result = {'roots': len(data['roots']), 'pending': data['pending'],
                  'heartbeat': json.loads(heartbeat.read_text()) if heartbeat.exists() else {'status': 'NOT_RUNNING'}}
        if args.root:
            name = str(args.root.resolve())
            latest = audit.STATE / 'latest' / (hashlib.sha256(name.encode()).hexdigest() + '.json')
            result['pending'] = {k: v for k, v in data['pending'].items() if k == name}
            result['latest'] = json.loads(latest.read_text()) if latest.exists() else {'status': 'NOT_RUN'}
        print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__': sys.exit(main())
