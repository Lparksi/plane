# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import hashlib
import importlib.util
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_audit_image import blob, image, tar_bytes

spec = importlib.util.spec_from_file_location("fixture_gate", Path(__file__).with_name("verify_trivy_fixtures.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class FixtureGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = str(self.root / "image.tar.gz")
        self.report_path = str(self.root / "report.json")
        self.lock_path = str(self.root / "pnpm-lock.yaml")
        Path(self.lock_path).write_bytes(gate.LOCK_RESOLUTION)
        self.block = b"-----BEGIN PRIVATE KEY-----\nsynthetic-fixture\n-----END PRIVATE KEY-----"
        self.contents = b"prefix\n" + self.block + b"\nend\n"
        self.hashes = {gate.SRC: hashlib.sha256(self.contents).hexdigest(), gate.LIB: hashlib.sha256(self.contents).hexdigest()}
        self.patches = [patch.object(gate, "FILE_HASHES", self.hashes), patch.object(gate, "BLOCK_HASH", hashlib.sha256(self.block).hexdigest())]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.rebuild()

    def rebuild(self, bundle=None):
        files = {gate.SRC.lstrip('/'): self.contents, gate.LIB.lstrip('/'): self.contents,
                 gate.BUNDLE.lstrip('/'): self.contents if bundle is None else bundle}
        layer = tar_bytes(files)
        image(self.archive, {blob(layer): layer})
        with tarfile.open(self.archive, "r:gz") as archive:
            manifest = json.load(archive.extractfile("manifest.json"))[0]
            config = json.load(archive.extractfile(manifest["Config"]))
        self.image_id = "sha256:" + manifest["Config"].split("/")[-1]
        diff = config["rootfs"]["diff_ids"][0]
        self.report = {"SchemaVersion": 2, "ArtifactType": "container_image",
                       "Metadata": {"ImageID": self.image_id, "DiffIDs": [diff]},
                       "Results": [{"Target": path, "Secrets": [{"RuleID": "private-key", "Layer": {"DiffID": diff}, "StartLine": 2, "EndLine": 3}]} for path in (gate.SRC, gate.LIB, gate.BUNDLE)]}

    def check(self):
        Path(self.report_path).write_text(json.dumps(self.report))
        return gate.verify(self.report_path, self.archive, self.lock_path, self.image_id, 1)

    def test_exact_fixtures_accepted(self):
        self.assertIsNone(self.check())

    def test_unknown_rule_or_target_blocked(self):
        self.report["Results"][0]["Secrets"][0]["RuleID"] = "jwt-token"
        with self.assertRaises(gate.Rejected):
            self.check()
        self.rebuild()
        self.report["Results"][0]["Target"] = "/unverified/path"
        with self.assertRaises(gate.Rejected):
            self.check()

    def test_range_layer_and_duplicate_are_bound(self):
        self.report["Results"][0]["Secrets"][0]["StartLine"] = 999
        self.report["Results"][0]["Secrets"][0]["EndLine"] = 999
        with self.assertRaises(gate.Rejected):
            self.check()
        self.rebuild()
        self.report["Results"][0]["Secrets"][0]["Layer"]["DiffID"] = "sha256:" + "a" * 64
        with self.assertRaises(gate.Rejected):
            self.check()
        self.rebuild()
        self.report["Results"][0]["Secrets"].append(dict(self.report["Results"][0]["Secrets"][0]))
        with self.assertRaises(gate.Rejected):
            self.check()

    def test_altered_bundle_block_and_source_file_blocked(self):
        self.rebuild(bundle=self.contents.replace(b"synthetic-fixture", b"altered-fixture"))
        with self.assertRaises(gate.Rejected):
            self.check()
        self.rebuild()
        with patch.object(gate, "FILE_HASHES", {**self.hashes, gate.SRC: "0" * 64}):
            with self.assertRaises(gate.Rejected):
                self.check()

    def test_lock_or_image_identity_mismatch_blocked(self):
        Path(self.lock_path).write_text("unverified")
        with self.assertRaises(gate.Rejected):
            self.check()
        Path(self.lock_path).write_bytes(gate.LOCK_RESOLUTION)
        self.report["Metadata"]["ImageID"] = "sha256:" + "0" * 64
        with self.assertRaises(gate.Rejected):
            self.check()


if __name__ == "__main__":
    unittest.main()
