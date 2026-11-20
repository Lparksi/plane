# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import hashlib
import importlib.util
import json
import re
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_audit_image import blob, image, tar_bytes

spec = importlib.util.spec_from_file_location('backend_gate', Path(__file__).with_name('verify_backend_fixtures.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class BackendFixtureGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.archive = str(root / 'image.tar.gz')
        self.report_path = str(root / 'report.json')
        self.lock_path = str(root / 'uv.lock')
        Path(self.lock_path).write_text('[[package]]\nname = "pyjwt"\nversion = "2.15.1"\n'
                                       '[[package.wheels]]\nhash = "' + gate.PYJWT_WHEEL + '"\n')
        self.contents = {gate.AWS_PATH: b'before\nfake-public-example\nafter\n',
                         gate.JWT_PATH: b'before\nsynthetic-jwt\nafter\n'}
        specs = {path: {'rule': gate.SPECS[path]['rule'], 'file': hashlib.sha256(data).hexdigest(),
                        'match': hashlib.sha256(data.splitlines()[1]).hexdigest(),
                        'pattern': re.compile(re.escape(data.splitlines()[1]))} for path, data in self.contents.items()}
        p = patch.object(gate, 'SPECS', specs)
        p.start()
        self.addCleanup(p.stop)
        self.rebuild()

    def rebuild(self, contents=None):
        contents = self.contents if contents is None else contents
        layer = tar_bytes({path.lstrip('/'): data for path, data in contents.items()})
        image(self.archive, {blob(layer): layer})
        with tarfile.open(self.archive, 'r:gz') as archive:
            manifest = json.load(archive.extractfile('manifest.json'))[0]
            config = json.load(archive.extractfile(manifest['Config']))
        self.image_id = 'sha256:' + manifest['Config'].split('/')[-1]
        diff = config['rootfs']['diff_ids'][0]
        self.report = {'SchemaVersion': 2, 'ArtifactType': 'container_image',
                       'Metadata': {'ImageID': self.image_id, 'DiffIDs': [diff]},
                       'Results': [{'Target': path, 'Secrets': [{'RuleID': gate.SPECS[path]['rule'],
                         'Layer': {'DiffID': diff}, 'StartLine': 2, 'EndLine': 2}]} for path in self.contents]}

    def check(self, exit_code=1):
        Path(self.report_path).write_text(json.dumps(self.report))
        return gate.verify(self.report_path, self.archive, self.lock_path, self.image_id, exit_code)

    def test_known_findings_bound(self):
        self.assertIsNone(self.check())
        self.report['Results'].pop()
        self.assertIsNone(self.check())

    def test_unknown_rule_target_duplicate_fail(self):
        self.report['Results'][0]['Secrets'][0]['RuleID'] = 'private-key'
        with self.assertRaises(gate.Rejected): self.check()
        self.rebuild()
        self.report['Results'][0]['Target'] = '/other/path'
        with self.assertRaises(gate.Rejected): self.check()
        self.rebuild()
        self.report['Results'][0]['Secrets'].append(dict(self.report['Results'][0]['Secrets'][0]))
        with self.assertRaises(gate.Rejected): self.check()
        self.rebuild()
        self.report['Results'].append({'Target': '/unknown', 'Secrets': [{'RuleID': 'jwt-token'}]})
        with self.assertRaises(gate.Rejected): self.check()

    def test_range_diff_identity_exit_enforced(self):
        self.report['Results'][0]['Secrets'][0]['StartLine'] = 1
        with self.assertRaises(gate.Rejected): self.check()
        self.rebuild()
        self.report['Results'][0]['Secrets'][0]['Layer']['DiffID'] = 'sha256:' + 'a' * 64
        with self.assertRaises(gate.Rejected): self.check()
        self.rebuild()
        self.report['Metadata']['ImageID'] = 'sha256:' + '0' * 64
        with self.assertRaises(gate.Rejected): self.check()
        self.rebuild()
        with self.assertRaises(gate.Rejected): self.check(exit_code=0)

    def test_file_match_lock_fail(self):
        changed = dict(self.contents)
        changed[gate.JWT_PATH] += b'unknown extra content'
        self.rebuild(changed)
        with self.assertRaises(gate.Rejected): self.check()
        self.rebuild()
        with patch.dict(gate.SPECS[gate.AWS_PATH], {'match': '0' * 64}):
            with self.assertRaises(gate.Rejected): self.check()
        Path(self.lock_path).write_text('unverified')
        with self.assertRaises(Exception): self.check()

    def test_same_known_file_in_multiple_layers_and_shadow_change(self):
        first = tar_bytes({gate.AWS_PATH.lstrip('/'): self.contents[gate.AWS_PATH]})
        second = tar_bytes({path.lstrip('/'): data for path, data in self.contents.items()})
        image(self.archive, {blob(first): first, blob(second): second})
        with tarfile.open(self.archive, 'r:gz') as archive:
            manifest = json.load(archive.extractfile('manifest.json'))[0]
            config = json.load(archive.extractfile(manifest['Config']))
        self.image_id = 'sha256:' + manifest['Config'].split('/')[-1]
        diffs = config['rootfs']['diff_ids']
        self.report['Metadata'] = {'ImageID': self.image_id, 'DiffIDs': diffs}
        for section in self.report['Results']:
            section['Secrets'][0]['Layer']['DiffID'] = diffs[-1]
        self.assertIsNone(self.check())
        changed = tar_bytes({gate.AWS_PATH.lstrip('/'): b'shadow content'})
        image(self.archive, {blob(changed): changed, blob(second): second})
        with tarfile.open(self.archive, 'r:gz') as archive:
            manifest = json.load(archive.extractfile('manifest.json'))[0]
            config = json.load(archive.extractfile(manifest['Config']))
        self.image_id = 'sha256:' + manifest['Config'].split('/')[-1]
        self.report['Metadata'] = {'ImageID': self.image_id, 'DiffIDs': config['rootfs']['diff_ids']}
        for section in self.report['Results']:
            section['Secrets'][0]['Layer']['DiffID'] = config['rootfs']['diff_ids'][-1]
        with self.assertRaises(gate.Rejected): self.check()


if __name__ == '__main__':
    unittest.main()
