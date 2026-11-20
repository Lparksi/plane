# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import gzip
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from pathlib import Path

spec = importlib.util.spec_from_file_location("audit_image", Path(__file__).with_name("audit_image.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def tar_bytes(files):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tar:
        for name, content in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(content)
            tar.addfile(item, io.BytesIO(content))
    return data.getvalue()


def blob(content):
    return "blobs/sha256/" + hashlib.sha256(content).hexdigest()


def image(path, layers, references=None, config_refs=None, extra_config=None, extras=None):
    refs = references if references is not None else list(layers)
    diffids = []
    for name in config_refs if config_refs is not None else refs:
        content = layers.get(name, b"")
        if content.startswith(b"\x1f\x8b"):
            content = gzip.decompress(content)
        diffids.append("sha256:" + hashlib.sha256(content).hexdigest())
    config = json.dumps({"rootfs": {"diff_ids": diffids}, **(extra_config or {})}).encode()
    config_name = blob(config)
    with tarfile.open(path, mode="w:gz") as tar:
        manifest = json.dumps([{"Config": config_name, "Layers": refs}]).encode()
        for name, content in {**layers, config_name: config, "manifest.json": manifest, **(extras or {})}.items():
            item = tarfile.TarInfo(name)
            item.size = len(content)
            tar.addfile(item, io.BytesIO(content))


class ImageAuditTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = str(Path(self.dir.name) / "image.tar.gz")
        self.a = "blobs/sha256/" + "a" * 64
        self.b = "blobs/sha256/" + "b" * 64

    def test_inspects_oci_layers_and_legacy(self):
        legacy = "c" * 64 + "/layer.tar"
        data = tar_bytes({"etc/test": b"safe"})
        image(self.path, {blob(data): data, legacy: tar_bytes({"usr/test": b"safe"})})
        self.assertEqual(audit.audit(self.path), 2)

    def test_compressed_oci_layer(self):
        data = gzip.compress(tar_bytes({"etc/test": b"safe"}))
        image(self.path, {blob(data): data})
        self.assertEqual(audit.audit(self.path), 1)

    def test_secrets_in_older_deleted_layers_are_blocked(self):
        private = b"-----BEGIN " + b"PRIVATE KEY-----"
        old = tar_bytes({"opt/token": private})
        new = tar_bytes({"opt/.wh.token": b""})
        image(self.path, {blob(old): old, blob(new): new})
        with self.assertRaises(ValueError):
            audit.audit(self.path)

    def test_blocks_env_and_missing_or_invalid_layers(self):
        image(self.path, {self.a: tar_bytes({"app/.env": b"x"})})
        with self.assertRaises(ValueError):
            audit.audit(self.path)
        image(self.path, {self.a: tar_bytes({"safe": b"x"})}, [self.a, self.b])
        with self.assertRaises(ValueError):
            audit.audit(self.path)
        image(self.path, {self.a: b"invalid-compression"})
        with self.assertRaises(tarfile.TarError):
            audit.audit(self.path)

    def test_rejects_traversal_and_nested_gzip_secret(self):
        bad_path = tar_bytes({"../escape": b"x"})
        image(self.path, {blob(bad_path): bad_path})
        with self.assertRaisesRegex(ValueError, "unsafe path"):
            audit.audit(self.path)
        secret = b"ghp_" + b"a" * 36
        layer = tar_bytes({"payload.txt.gz": gzip.compress(secret)})
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "GitHub token"):
            audit.audit(self.path)

    def test_nested_zip_and_depth_limit(self):
        contents = io.BytesIO()
        with zipfile.ZipFile(contents, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("deep.gz", gzip.compress(b"ghp_" + b"a" * 36))
        layer = tar_bytes({"inside.zip": contents.getvalue()})
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "GitHub token"):
            audit.audit(self.path)
        data = b"safe"
        for _ in range(7):
            data = gzip.compress(data)
        layer = tar_bytes({"nested.gz": data})
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "depth"):
            audit.audit(self.path)

    def test_unsupported_archives_and_byte_budget_fail_closed(self):
        layer = tar_bytes({"unsupported.7z": b"7z\xbc\xaf\x27\x1c" + b"x"})
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            audit.audit(self.path)
        layer = tar_bytes({"large.txt": b"x" * 500})
        image(self.path, {blob(layer): layer})
        with patch.object(audit, "MAX_TOTAL_BYTES", 100):
            with self.assertRaisesRegex(ValueError, "limit"):
                audit.audit(self.path)

    def test_secret_in_filename_and_archive_metadata(self):
        layer = tar_bytes({"tmp/ghp_" + "a" * 36: b"safe"})
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "secret in path"):
            audit.audit(self.path)
        contents = io.BytesIO()
        with zipfile.ZipFile(contents, "w") as z:
            z.comment = ("ghp_" + "a" * 36).encode()
            z.writestr("safe", b"safe")
        layer = tar_bytes({"inside.zip": contents.getvalue()})
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "GitHub token|archive metadata"):
            audit.audit(self.path)

    def test_member_and_time_limits_fail_closed(self):
        layer = tar_bytes({"a": b"a", "b": b"b"})
        image(self.path, {blob(layer): layer})
        with patch.object(audit, "MAX_MEMBERS", 1):
            with self.assertRaisesRegex(ValueError, "member limit"):
                audit.audit(self.path)
        with patch.object(audit, "MAX_SECONDS", -1):
            with self.assertRaisesRegex(ValueError, "time limit"):
                audit.audit(self.path)

    def test_archive_link_and_pax_secrets(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as tar:
            item = tarfile.TarInfo("safe")
            item.type = tarfile.SYMTYPE
            item.linkname = "../../outside"
            tar.addfile(item)
        layer = data.getvalue()
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "escapes"):
            audit.audit(self.path)
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as tar:
            item = tarfile.TarInfo("safe")
            item.pax_headers = {"custom": "ghp_" + "a" * 36}
            tar.addfile(item, io.BytesIO(b""))
        layer = data.getvalue()
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "archive metadata"):
            audit.audit(self.path)

    def test_unknown_outer_content_and_descriptor_secret_fail(self):
        layer = tar_bytes({"safe": b"safe"})
        image(self.path, {blob(layer): layer}, extras={"unexpected": b"data"})
        with self.assertRaisesRegex(ValueError, "Unreferenced"):
            audit.audit(self.path)
        descriptor = json.dumps({"token": "ghp_" + "a" * 36}).encode()
        image(self.path, {blob(layer): layer}, extras={blob(descriptor): descriptor})
        with self.assertRaisesRegex(ValueError, "descriptor"):
            audit.audit(self.path)

    def test_archive_config_and_link_target_secrets_fail(self):
        layer = tar_bytes({"safe": b"safe"})
        image(self.path, {blob(layer): layer}, extra_config={"secret": "ghp_" + "a" * 36})
        with self.assertRaisesRegex(ValueError, "image config"):
            audit.audit(self.path)
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as tar:
            item = tarfile.TarInfo("safe-link")
            item.type = tarfile.SYMTYPE
            item.linkname = "ghp_" + "a" * 36
            tar.addfile(item)
        layer = data.getvalue()
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "link target"):
            audit.audit(self.path)

    def test_config_identity_and_layer_order(self):
        a = tar_bytes({"a": b"a"})
        b = tar_bytes({"b": b"b"})
        layers = {blob(a): a, blob(b): b}
        image(self.path, layers, references=[blob(b), blob(a)], config_refs=[blob(a), blob(b)])
        with self.assertRaisesRegex(ValueError, "diff ID"):
            audit.audit(self.path)
        image(self.path, layers)
        with self.assertRaisesRegex(ValueError, "image ID"):
            audit.audit(self.path, {"Id": "sha256:" + "0" * 64})

    def test_base_requires_digest_exact_id_and_order(self):
        digest = "sha256:" + "a" * 64
        image_id = "sha256:" + "b" * 64
        ref = "docker.io/library/example@" + digest
        target = {"RootFS": {"Layers": ["l1", "l2"]}}
        base = [{"Id": image_id, "RepoDigests": [ref], "RootFS": {"Layers": ["l1"]}}]
        with patch.object(audit.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(base).encode()
            self.assertEqual(audit.classify_layers(target, ref, image_id), (1, 1))
            with self.assertRaises(ValueError):
                audit.classify_layers(target, "docker.io/library/example:latest", image_id)
            with self.assertRaises(ValueError):
                audit.classify_layers(target, ref, "sha256:" + "c" * 64)
            target["RootFS"]["Layers"] = ["l2", "l1"]
            with self.assertRaises(ValueError):
                audit.classify_layers(target, ref, image_id)

    def test_unverified_botocore_file_is_not_exempted(self):
        fake = b'{"PrivateKey":"-----BEGIN PRIVATE KEY-----"}'
        path = "usr/local/lib/python3.12/site-packages/botocore/data/iam/2010-05-08/examples-1.json"
        self.assertEqual(audit.strip_verified_public_example(path, fake), fake)
        self.assertEqual(audit.finding(fake), "private key")

    def test_temporary_aws_key_in_nested_gzip(self):
        secret = b"ASIA" + b"A" * 16
        layer = tar_bytes({"payload.gz": gzip.compress(secret)})
        image(self.path, {blob(layer): layer})
        with self.assertRaisesRegex(ValueError, "AWS access key"):
            audit.audit(self.path)

    def test_only_documented_aws_example_is_allowed(self):
        self.assertIsNone(audit.finding(b"AKIAIOSFODNN7EXAMPLE"))
        self.assertEqual(audit.finding(b"AKIAAAAAAAAAAEXAMPLE"), "AWS access key")

    def test_rejects_wrong_blob_digest(self):
        image(self.path, {self.a: tar_bytes({"safe": b"x"})})
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            audit.audit(self.path)

    def test_error_does_not_print_sensitive_or_control_characters_in_path(self):
        token = "ghp_" + "a" * 36
        path = "tmp/" + token + "\x1b[31m/.env"
        layer = tar_bytes({path: b"x"})
        image(self.path, {blob(layer): layer})
        metadata = Path(self.dir.name) / "metadata.json"
        with tarfile.open(self.path, "r:gz") as archive:
            manifest = json.load(archive.extractfile("manifest.json"))[0]
            config = json.load(archive.extractfile(manifest["Config"]))
        metadata.write_text(json.dumps([{"Id": "sha256:" + manifest["Config"].split("/")[-1],
                                         "RootFS": {"Layers": config["rootfs"]["diff_ids"]}}]))
        result = subprocess.run([sys.executable, spec.origin, self.path, str(metadata)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(token, result.stderr)
        self.assertNotIn("\x1b", result.stderr)
        self.assertIn("path SHA-256: " + hashlib.sha256(path.encode()).hexdigest(), result.stderr)

    def test_metadata_scanned(self):
        path = Path(self.dir.name) / "metadata.json"
        path.write_bytes(b"prefix " + b"ghp_" + b"a" * 36)
        with self.assertRaises(ValueError):
            audit.audit_metadata(str(path))


if __name__ == "__main__":
    unittest.main()
