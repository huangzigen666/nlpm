"""Negative fixtures check audit completion, secrecy, source drift and event deduplication."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import auto_audit as audit
import monitor
import install


class AutoAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='nlpm-auto-test-')
        self.directory = Path(self.tmp.name).resolve()
        self.skill = self.directory / 'demo'
        self.skill.mkdir()
        self.path = self.skill / 'SKILL.md'
        self.path.write_text('---\nname: demo\ndescription: Use when reviewing migrations, checking SQL, or validating transactions\n---\n# Demo\n')
        self.state = self.directory / 'state'
        self.state_patch = patch.object(audit, 'STATE', self.state)
        self.state_patch.start()
        self.contents = {'SKILL.md': self.path.read_text()}
        self.value = {'security': {'findings': []}, 'scoring': [{'path': 'SKILL.md', 'score': 100, 'penalties': []}],
                      'consistency': {'findings': []}, 'nl_tests': []}

    def tearDown(self):
        self.state_patch.stop()
        self.tmp.cleanup()

    def model(self, *_args, **_kwargs):
        return 0, json.dumps({'type': 'item.completed', 'item': {'type': 'agent_message', 'text': json.dumps(self.value)}}), ''

    def run_mock(self):
        real = audit.execute
        def call(args, **kwargs):
            if args[0] == 'codex':
                self.assertIn('read-only', args)
                self.assertIn('features.hooks=false', args)
                self.assertIn('features.plugins=false', args)
                self.assertIn('features.shell_tool=false', args)
                self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', args)
                self.assertEqual(kwargs['env']['NLPM_AUTO_AUDIT_ACTIVE'], '1')
                latest = next((self.state / 'latest').glob('*.json'))
                self.assertEqual(json.loads(latest.read_text())['status'], 'RUNNING')
                return self.model(args, **kwargs)
            return real(args, **kwargs)
        with patch.object(audit, 'execute', side_effect=call): return audit.run(self.skill)

    def test_complete_four_stages_and_no_specs_not_a_test_pass(self):
        result = self.run_mock()
        self.assertEqual(result['status'], 'AUDIT_COMPLETE')
        self.assertEqual(result['structural']['status'], 'PASS')
        self.assertEqual(result['nl_tests_status'], 'NOT_APPLICABLE')
        self.assertEqual(result['runtime_behavior'], 'NOT_VERIFIED_BY_SPEC_EVALUATION')

    def test_missing_model_stage_blocks(self):
        del self.value['security']
        self.assertEqual(self.run_mock()['status'], 'BLOCKED_INVALID_RESULT')

    def test_unscored_file_blocks(self):
        self.value['scoring'] = []
        self.assertEqual(self.run_mock()['status'], 'BLOCKED_INVALID_RESULT')

    def test_wrong_penalty_arithmetic_blocks(self):
        self.value['scoring'][0]['penalties'] = [{'rule': 'R04', 'penalty': -15, 'reason': 'Generic trigger'}]
        self.assertEqual(self.run_mock()['status'], 'BLOCKED_INVALID_RESULT')

    def test_low_score_is_a_finding(self):
        self.value['scoring'][0].update(score=60, penalties=[{'rule': 'R04', 'penalty': -25, 'reason': 'Missing description'}, {'rule': 'R04', 'penalty': -15, 'reason': 'Generic trigger'}])
        self.assertEqual(self.run_mock()['status'], 'FINDINGS')

    def test_unknown_rubric_rule_blocks(self):
        self.value['scoring'][0].update(score=90, penalties=[{'rule': 'R99', 'penalty': -10, 'reason': 'Invented rule'}])
        self.assertEqual(self.run_mock()['status'], 'BLOCKED_INVALID_RESULT')

    def test_same_sources_and_rules_reuse_the_completed_result(self):
        calls = []
        original = self.model
        def model(*args, **kwargs):
            calls.append(1)
            return original(*args, **kwargs)
        self.model = model
        first = self.run_mock()
        second = self.run_mock()
        self.assertEqual(first['status'], 'AUDIT_COMPLETE')
        self.assertTrue(second['deduplicated'])
        self.assertEqual(len(calls), 1)

    def test_outside_authorized_local_roots_is_rejected(self):
        self.assertTrue(audit.forbidden(Path('/etc')))
        self.assertTrue(audit.forbidden(Path.home() / '我的第二大脑'))

    def test_bad_yaml_and_name_are_detected_before_model_judgment(self):
        self.contents['SKILL.md'] = '---\nname: wrong\ndescription: [unclosed\n---\n# Demo\n'
        self.assertEqual(audit.structural(self.skill, self.contents)['status'], 'FINDINGS')
        self.contents['SKILL.md'] = self.path.read_text().replace('name: demo', 'name: wrong')
        report = audit.structural(self.skill, self.contents)
        self.assertTrue(any(f['rule'] == 'skill/name-parent' for f in report['findings']))

    def test_root_skill_name_and_real_reference_are_valid(self):
        (self.skill / 'references').mkdir()
        (self.skill / 'references/guide.md').write_text('# Guide\n')
        self.path.write_text(self.path.read_text() + 'See references/guide.md.\n')
        contents, _ = audit.snapshot(self.skill)
        self.assertIn('references/guide.md', contents)
        self.assertEqual(audit.structural(self.skill, contents)['status'], 'PASS')

    def test_changed_artifact_receipt_names_the_limited_model_scope(self):
        (self.skill / 'AGENTS.md').write_text('# Project rules\n')
        (self.skill / '.nlpm-test').mkdir()
        (self.skill / '.nlpm-test/other.spec.md').write_text('---\nartifact: AGENTS.md\ntype: memory\n---\n# Other\n')
        self.value['nl_tests'] = []
        original = self.model
        def model(args, **kwargs):
            self.assertIn('changed_artifacts', kwargs['prompt'])
            self.assertIn('AGENTS.md', kwargs['prompt'])
            self.assertIn('SKILL.md', kwargs['prompt'])
            return original(args, **kwargs)
        self.model = model
        real = audit.execute
        def call(args, **kwargs):
            return self.model(args, **kwargs) if args[0] == 'codex' else real(args, **kwargs)
        with patch.object(audit, 'execute', side_effect=call):
            result = audit.run(self.skill, focus=[self.path])
        self.assertEqual(result['status'], 'AUDIT_COMPLETE')
        self.assertEqual(result['coverage']['mode'], 'changed_artifacts')
        self.assertEqual(result['coverage']['targets'], ['SKILL.md'])
        self.assertEqual(result['coverage']['native_checker_scope'], 'full_snapshot')
        self.assertNotIn('.nlpm-test/other.spec.md', result['coverage']['included_paths'])

    def test_changed_non_artifact_cannot_be_reported_clean(self):
        result = audit.run(self.skill, focus=[self.skill / 'missing.py'])
        self.assertEqual(result['status'], 'BLOCKED_INVALID_RESULT')

    def test_changed_spec_brings_its_declared_artifact_into_scope(self):
        directory = self.skill / '.nlpm-test'
        directory.mkdir()
        spec = directory / 'demo.spec.md'
        spec.write_text('---\nartifact: SKILL.md\ntype: skill\n---\n# Case\n')
        self.value['nl_tests'] = [{'path': '.nlpm-test/demo.spec.md', 'status': 'PASS', 'details': 'Artifact exists'}]
        original = self.model
        def model(args, **kwargs):
            self.assertIn('"targets": ["SKILL.md"]', kwargs['prompt'])
            return original(args, **kwargs)
        self.model = model
        real = audit.execute
        def call(args, **kwargs):
            return self.model(args, **kwargs) if args[0] == 'codex' else real(args, **kwargs)
        with patch.object(audit, 'execute', side_effect=call):
            result = audit.run(self.skill, focus=[spec])
        self.assertEqual(result['status'], 'AUDIT_COMPLETE')
        self.assertEqual(result['targets'], ['SKILL.md'])
        self.assertEqual(result['specs'], ['.nlpm-test/demo.spec.md'])

    def test_missing_reference_is_deterministic(self):
        self.contents['SKILL.md'] += 'See references/missing.md.\n'
        result = audit.structural(self.skill, self.contents)
        self.assertTrue(any(f['rule'] == 'reference' for f in result['findings']))

    def test_secret_env_headers_and_literals_are_removed(self):
        secret = 'sk-' + 'A' * 30
        raw = json.dumps({'mcpServers': {'x': {'env': {'TOKEN': secret}, 'headers': {'Authorization': 'Bearer abc'}}}, 'text': secret})
        output = audit.redacted(raw, '.mcp.json')
        self.assertNotIn(secret, output)
        self.assertNotIn('Bearer abc', output)
        self.assertIn('[REDACTED]', output)
        self.assertNotIn('secret-content', audit.redacted('{"env":"secret-content"', '.mcp.json'))

    def test_external_file_symlink_is_rejected(self):
        outside = self.directory / 'external.json'
        outside.write_text('{}')
        (self.skill / 'hooks.json').symlink_to(outside)
        with self.assertRaises(ValueError): audit.snapshot(self.skill)

    def test_auth_failure_preserves_blocked_status(self):
        real = audit.execute
        def call(args, **kwargs):
            if args[0] == 'codex': return 1, '', 'OAuth session expired'
            return real(args, **kwargs)
        with patch.object(audit, 'execute', side_effect=call):
            self.assertEqual(audit.run(self.skill)['status'], 'BLOCKED_AUTH')

    def test_worker_tool_call_blocks(self):
        self.model = lambda *_a, **_kw: (0, json.dumps({'type': 'item.completed', 'item': {'type': 'command_execution', 'command': 'unsafe'}}), '')
        self.assertEqual(self.run_mock()['status'], 'BLOCKED_INVALID_RESULT')

    def test_recovered_transport_message_is_not_a_tool_call(self):
        original = self.model
        self.model = lambda *a, **kw: (0, json.dumps({'type': 'item.completed', 'item': {'type': 'error', 'message': 'Falling back to HTTPS'}}) + '\n' + original(*a, **kw)[1], '')
        self.assertEqual(self.run_mock()['status'], 'AUDIT_COMPLETE')

    def test_unrecovered_error_cannot_be_clean(self):
        self.model = lambda *_a, **_kw: (0, json.dumps({'type': 'item.completed', 'item': {'type': 'error', 'message': 'Transport failure'}}), '')
        self.assertEqual(self.run_mock()['status'], 'BLOCKED_INVALID_RESULT')

    def test_packed_input_roundtrips_every_path_and_reference(self):
        contents = {'SKILL.md': self.path.read_text(), 'codex/SKILL.md': self.path.read_text()}
        references = {'rules/SKILL.md': self.path.read_text()}
        packed = audit.packed_inputs(contents, references)
        self.assertEqual(len(packed['texts']), 1)
        self.assertEqual({p: packed['texts'][i] for p, i in packed['artifacts'].items()}, contents)
        self.assertEqual({p: packed['texts'][i] for p, i in packed['knowledge'].items()}, references)

    def test_native_schema_restricts_rule_identifiers(self):
        identifiers = audit.SCHEMA['properties']['scoring']['items']['properties']['penalties']['items']['properties']['rule']['enum']
        self.assertIn('--', identifiers)
        self.assertIn('R51', identifiers)
        self.assertNotIn('-- (name matches parent directory)', identifiers)
        self.assertNotIn('R99', identifiers)

    def test_worker_disables_each_configured_mcp_server(self):
        home = self.directory / 'home'
        (home / '.codex').mkdir(parents=True)
        (home / '.codex/config.toml').write_text('[mcp_servers.github]\nurl="https://example.invalid"\n[mcp_servers."local-reader"]\ncommand="reader"\n')
        with patch.object(audit.Path, 'home', return_value=home):
            args = audit.codex_worker_args(self.directory)
        self.assertIn('mcp_servers.github.enabled=false', args)
        self.assertIn('mcp_servers.local-reader.enabled=false', args)
        self.assertNotIn('mcp_servers={}', args)

    def test_changed_source_invalidates_result(self):
        original = self.model
        def model(*args, **kwargs):
            self.path.write_text(self.path.read_text() + 'Concurrent edit\n')
            return original(*args, **kwargs)
        self.model = model
        self.assertEqual(self.run_mock()['status'], 'STALE_SOURCE')

    def test_missing_spec_result_blocks(self):
        (self.skill / '.nlpm-test').mkdir()
        (self.skill / '.nlpm-test/demo.spec.md').write_text('---\nartifact: SKILL.md\ntype: skill\n---\n# Spec\n')
        self.assertEqual(self.run_mock()['status'], 'BLOCKED_INVALID_RESULT')

    def test_monitor_baselines_without_auditing_old_corpus_and_deduplicates(self):
        data = {'roots': [str(self.skill)], 'baseline': {}, 'pending': {}, 'runs': []}
        monitor.scan(data, now=1)
        self.assertEqual(data['pending'], {})
        self.path.write_text(self.path.read_text() + 'Edit 1\n')
        monitor.scan(data, now=2)
        self.assertEqual(len(data['pending']), 1)
        monitor.scan(data, now=3)
        self.assertEqual(len(data['pending']), 1)
        self.assertEqual(data['pending'][str(self.skill)]['changed_at'], 2)

    def test_native_hook_recursion_guard(self):
        with patch.dict(os.environ, {'NLPM_AUTO_AUDIT_ACTIVE': '1'}):
            self.assertEqual(monitor.hook({'cwd': str(self.skill), 'hook_event_name': 'PostToolUse', 'tool_input': {'file_path': str(self.path)}}), {})
        self.assertFalse((self.state / 'registry.json').exists())

    def test_read_tool_does_not_queue_an_audit(self):
        monitor.register(self.skill)
        monitor.hook({'cwd': str(self.skill), 'hook_event_name': 'PostToolUse', 'tool_name': 'Read', 'tool_input': {'file_path': str(self.path)}})
        with monitor.registry() as data: self.assertEqual(data['pending'], {})

    def test_hook_registration_is_idempotent_and_preserves_existing_hooks(self):
        data = {'enabledPlugins': {'nlpm@xiaolai': False}, 'hooks': {'Stop': [{'hooks': [{'command': 'existing'}]}]}}
        installed = install.settings_hook(data, 'entry hook')
        once = json.dumps(installed)
        twice = json.dumps(install.settings_hook(installed, 'entry hook'))
        self.assertEqual(once, twice)
        self.assertFalse(installed['enabledPlugins']['nlpm@xiaolai'])
        self.assertEqual(installed['hooks']['Stop'][0]['hooks'][0]['command'], 'existing')

    def test_gui_worker_accepts_only_credential_free_loopback_proxy(self):
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://127.0.0.1:7892',
                                     'HTTP_PROXY': 'http://user:pass@localhost:7892',
                                     'ALL_PROXY': 'http://remote.example:7892'}, clear=True):
            values = install.local_proxy_env()
        self.assertEqual(values, {'HTTPS_PROXY': 'http://127.0.0.1:7892'})

    def test_timeout_stops_subprocess(self):
        code, _, _ = audit.execute([sys.executable, '-c', 'import time;time.sleep(20)'], cwd=self.skill, timeout=0.1)
        self.assertEqual(code, 124)

    def test_interrupted_audit_has_a_terminal_receipt(self):
        real = audit.execute
        def interrupted(args, **kwargs):
            if args[0] == 'codex': raise SystemExit(0)
            return real(args, **kwargs)
        with patch.object(audit, 'execute', side_effect=interrupted):
            with self.assertRaises(SystemExit): audit.run(self.skill)
        latest = next((self.state / 'latest').glob('*.json'))
        result = json.loads(latest.read_text())
        self.assertEqual(result['status'], 'INTERRUPTED')
        self.assertTrue(result['finished_at'])

    def test_empty_queue_is_idle_when_hourly_budget_exhausted(self):
        config = {'max_background_audits_per_hour': 1}
        with monitor.registry() as data: data['runs'] = [100]
        with patch.object(monitor, 'time') as clock:
            clock.time.return_value = 101
            self.assertEqual(monitor.drain(config, now=101), 'IDLE')

    def test_corrupt_runtime_state_recovers_from_valid_mirror(self):
        path = self.state / 'example.json'
        audit.atomic(path, {'version': 1})
        audit.atomic(path, {'version': 2})
        path.write_text('{broken')
        self.assertEqual(audit.load_json(path), {'version': 1})
        self.assertEqual(json.loads(path.read_text()), {'version': 1})

    def test_reference_edits_trigger_the_containing_skill_audit(self):
        directory = self.skill / 'references'
        directory.mkdir()
        path = directory / 'guide.md'
        path.write_text('# Old\n')
        data = {'roots': [str(self.skill)], 'baseline': {}, 'pending': {}, 'runs': []}
        monitor.scan(data, now=1)
        path.write_text('# New\n')
        monitor.scan(data, now=2)
        self.assertIn(str(self.skill), data['pending'])


if __name__ == '__main__': unittest.main()
