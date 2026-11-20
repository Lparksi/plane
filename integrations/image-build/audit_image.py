# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Inspect every docker-save layer without extracting or printing file contents."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import lzma
import json
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
import zipfile
import tarfile
from pathlib import PurePosixPath

CHUNK = 1024 * 1024
OVERLAP = 512
MAX_DEPTH = 5
MAX_MEMBERS = 200_000
MAX_TOTAL_BYTES = 2 * 1024**3
MAX_ARCHIVE_BYTES = 256 * 1024**2
MAX_SECONDS = 180
PROGRESS = {"completed": 0, "total": 0}
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")
GITHUB_TOKEN = re.compile(rb"(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")
AWS_KEY = re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}")
PATTERNS = (("private key", PRIVATE_KEY), ("GitHub token", GITHUB_TOKEN), ("AWS access key", AWS_KEY))
# AWS documentation's public example, not a general EXAMPLE suffix exemption:
# https://docs.aws.amazon.com/keyspaces/latest/devguide/create.keypair.html
AWS_DOCUMENTED_EXAMPLE = b"AKIAIOSFODNN7EXAMPLE"


def finding(data: bytes) -> str | None:
    for label, pattern in PATTERNS:
        for match in pattern.finditer(data):
            if label == "AWS access key" and match.group() == AWS_DOCUMENTED_EXAMPLE:
                continue
            return label
    return None


def check_path(path: str) -> str | None:
    if finding(path.encode("utf-8", "surrogateescape")):
        return "possible secret in path"
    if (path.startswith("/") or "\\" in path or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or ".." in path.split("/")):
        return "unsafe path"
    parts = PurePosixPath(path).parts
    name = parts[-1] if parts else ""
    if ".git" in parts:
        return "repository metadata"
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "environment file"
    if name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}:
        return "private key filename"
    return None


def strip_verified_public_example(path: str, data: bytes) -> bytes:
    # This exact public AWS SDK documentation example includes one published
    # demonstration private key. Do not exempt the file or other values.
    suffix = "botocore/data/iam/2010-05-08/examples-1.json"
    if not path.endswith(suffix) or hashlib.sha256(data).hexdigest() != "4f912aac51590625652fd76c37e4f90e78a05355273125df555c012b4d005ab5":
        return data
    try:
        value = json.loads(data)["examples"]["UploadServerCertificate"][0]["input"]["PrivateKey"]
        if not isinstance(value, str) or hashlib.sha256(value.encode()).hexdigest() != "205d8cafd33fbce643ae4889ded6ddf85ad50cd1edeb73f435a6d2ae9d26f3de":
            return data
        literal = json.dumps(value, ensure_ascii=False).encode()
        return data.replace(literal, b'"public-doc-example"', 1) if data.count(literal) == 1 else data
    except (ValueError, TypeError, KeyError, IndexError):
        return data


class AuditFailure(ValueError):
    """Controlled error with no untrusted content in its message."""


class PathFailure(AuditFailure):
    pass


class MetadataFailure(AuditFailure):
    pass


class MatchFailure(AuditFailure):
    pass


class UnsupportedFailure(AuditFailure):
    pass


class LimitFailure(AuditFailure):
    pass


def path_hash(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8", "surrogateescape")).hexdigest()


class Budget:
    def __init__(self):
        self.entries = 0
        self.bytes = 0
        self.deadline = time.monotonic() + MAX_SECONDS

    def tick(self, size=0, entry=False):
        self.bytes += size
        self.entries += int(entry)
        if time.monotonic() > self.deadline:
            raise LimitFailure("Inspection time limit exceeded")
        if self.bytes > MAX_TOTAL_BYTES:
            raise LimitFailure("Expanded byte limit exceeded")
        if self.entries > MAX_MEMBERS:
            raise LimitFailure("Archive member limit exceeded")


def inspect_content(source, name: str, size: int, budget: Budget, depth: int = 0) -> None:
    budget.tick(entry=True)
    if depth > MAX_DEPTH:
        raise LimitFailure("Nested archive depth limit exceeded")
    reason = check_path(name)
    if reason:
        raise PathFailure(f"{reason}; path SHA-256: {path_hash(name)}")
    first = source.read(512)
    budget.tick(len(first))
    kind = None
    if first.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        kind = "zip"
    elif first.startswith(b"\x1f\x8b"):
        kind = "gzip"
    elif first.startswith(b"BZh"):
        kind = "bzip2"
    elif first.startswith(b"\xfd7zXZ\x00"):
        kind = "xz"
    elif first.startswith((b"\x28\xb5\x2f\xfd", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"!<arch>\n")):
        raise UnsupportedFailure(f"Unsupported nested archive; path SHA-256: {path_hash(name)}")
    elif len(first) >= 262 and first[257:262] == b"ustar":
        kind = "tar"
    elif name.lower().endswith((".zip", ".jar", ".whl", ".tar", ".tgz", ".tar.gz", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".deb", ".rpm")):
        raise UnsupportedFailure(f"Unsupported or malformed archive; path SHA-256: {path_hash(name)}")

    if kind:
        if depth >= MAX_DEPTH:
            raise LimitFailure("Nested archive depth limit exceeded")
        if size > MAX_ARCHIVE_BYTES:
            raise LimitFailure(f"Archive size limit exceeded; path SHA-256: {path_hash(name)}")
        with tempfile.SpooledTemporaryFile(max_size=4 * 1024**2) as stored:
            label = finding(first)
            if label:
                raise MatchFailure(f"Possible {label} in archive; path SHA-256: {path_hash(name)}")
            stored.write(first)
            tail = first[-OVERLAP:]
            total = len(first)
            while chunk := source.read(CHUNK):
                budget.tick(len(chunk))
                label = finding(tail + chunk)
                if label:
                    raise MatchFailure(f"Possible {label} in archive; path SHA-256: {path_hash(name)}")
                tail = chunk[-OVERLAP:]
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise LimitFailure("Compressed archive size limit exceeded")
                stored.write(chunk)
            stored.seek(0)
            inspect_archive(stored, kind, name, budget, depth + 1)
        return

    if name.endswith("botocore/data/iam/2010-05-08/examples-1.json") and size <= CHUNK:
        data = first + source.read(CHUNK)
        budget.tick(len(data) - len(first))
        label = finding(strip_verified_public_example(name, data))
        if label:
            raise MatchFailure(f"Possible {label}; path SHA-256: {path_hash(name)}")
        return
    tail = b""
    chunk = first
    while chunk:
        data = tail + chunk
        label = finding(data)
        if label:
            raise MatchFailure(f"Possible {label}; path SHA-256: {path_hash(name)}")
        tail = data[-OVERLAP:]
        chunk = source.read(CHUNK)
        budget.tick(len(chunk))


def inspect_archive(stored, kind: str, name: str, budget: Budget, depth: int) -> None:
    if kind == "zip":
        with zipfile.ZipFile(stored) as archive:
            if finding(archive.comment):
                raise MatchFailure("Possible secret in archive metadata")
            entries = archive.infolist()
            if len(entries) > MAX_MEMBERS - budget.entries:
                raise LimitFailure("Archive member limit exceeded")
            seen = set()
            for entry in entries:
                budget.tick(entry=True)
                if entry.filename in seen or entry.flag_bits & 1:
                    raise UnsupportedFailure("Duplicate or encrypted archive member")
                if finding(entry.extra + entry.comment):
                    raise MatchFailure("Possible secret in archive metadata")
                seen.add(entry.filename)
                if check_path(name + "/" + entry.filename):
                    raise PathFailure("Unsafe archive member path")
                member_type = (entry.external_attr >> 16) & 0o170000
                if member_type not in (0, 0o100000, 0o040000):
                    raise UnsupportedFailure("Unsupported archive member type")
                if entry.is_dir():
                    continue
                if entry.file_size > MAX_TOTAL_BYTES - budget.bytes:
                    raise LimitFailure("Expanded byte limit exceeded")
                with archive.open(entry) as source:
                    inspect_content(source, name + "/" + entry.filename, entry.file_size, budget, depth)
    elif kind == "tar":
        with tarfile.open(fileobj=stored, mode="r|") as archive:
            check_layer(archive, budget, depth, name)
    else:
        opener = gzip.GzipFile(fileobj=stored, mode="rb") if kind == "gzip" else (
            bz2.BZ2File(stored, mode="rb") if kind == "bzip2" else lzma.LZMAFile(stored, mode="rb")
        )
        with opener as source, tempfile.SpooledTemporaryFile(max_size=4 * 1024**2) as expanded:
            total = 0
            while chunk := source.read(CHUNK):
                total += len(chunk)
                budget.tick(len(chunk))
                if total > MAX_ARCHIVE_BYTES:
                    raise LimitFailure("Expanded archive size limit exceeded")
                expanded.write(chunk)
            expanded.seek(0)
            clean_name = re.sub(r"\.(?:gz|bz2|xz)$", "", name, flags=re.I)
            inspect_content(expanded, clean_name, total, budget, depth)


def check_layer(layer: tarfile.TarFile, budget: Budget | None = None, depth: int = 0, prefix: str = "") -> None:
    budget = budget or Budget()
    for entry in layer:
        budget.tick(entry=True)
        name = prefix + "/" + entry.name if prefix else entry.name
        reason = check_path(name)
        if reason:
            raise PathFailure(f"{reason}; path SHA-256: {path_hash(name)}")
        for key, value in entry.pax_headers.items():
            if finding((str(key) + "=" + str(value)).encode("utf-8", "surrogateescape")):
                raise MatchFailure(f"Possible secret in archive metadata; path SHA-256: {path_hash(name)}")
            if any(ord(c) < 32 and c not in "\t\n" for c in str(key) + str(value)):
                raise MetadataFailure(f"Unsafe archive metadata; path SHA-256: {path_hash(name)}")
        if entry.issym() or entry.islnk():
            target = entry.linkname
            if finding(target.encode("utf-8", "surrogateescape")):
                raise MatchFailure("Possible secret in archive link target")
            if any(ord(c) < 32 or ord(c) == 127 for c in target) or "\\" in target:
                raise PathFailure("Unsafe archive link target")
            # Resolve the link inside a virtual image root; never follow it.
            base = [] if target.startswith("/") or entry.islnk() else name.split("/")[:-1]
            for part in target.split("/"):
                if part in ("", "."):
                    continue
                if part == "..":
                    if not base:
                        raise PathFailure("Archive link escapes image root")
                    base.pop()
                else:
                    base.append(part)
            if check_path("/".join(base)):
                raise PathFailure("Sensitive archive link target")
            continue
        if entry.isdir():
            continue
        if not entry.isfile():
            raise UnsupportedFailure("Unsupported archive member type")
        source = layer.extractfile(entry)
        if source is None:
            raise AuditFailure("Unable to inspect image layer")
        inspect_content(source, name, entry.size, budget, depth)


def audit_metadata(path: str) -> dict:
    with open(path, "rb") as metadata:
        data = metadata.read(10 * 1024 * 1024 + 1)
    if len(data) > 10 * 1024 * 1024:
        raise LimitFailure("Image metadata exceeds size limit")
    label = finding(data)
    if label:
        raise MatchFailure(f"Possible {label} in image metadata")
    metadata = json.loads(data)
    if not isinstance(metadata, list) or len(metadata) != 1 or not isinstance(metadata[0], dict):
        raise MetadataFailure("Invalid image inspection metadata")
    return metadata[0]


def manifest_layers(path: str) -> tuple[str, list[str]]:
    manifest = None
    budget = Budget()
    with tarfile.open(path, mode="r|gz") as archive:
        for entry in archive:
            budget.tick(entry.size, entry=True)
            if entry.name != "manifest.json":
                continue
            if manifest is not None or not entry.isfile() or entry.size > 1024 * 1024:
                raise MetadataFailure("Invalid image manifest")
            source = archive.extractfile(entry)
            if source is None:
                raise MetadataFailure("Missing image manifest")
            manifest_data = source.read()
            if finding(manifest_data):
                raise MatchFailure("Possible secret in image manifest")
            manifest = json.loads(manifest_data)
    if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
        raise MetadataFailure("Expected exactly one image in docker-save manifest")
    config = manifest[0].get("Config")
    if not isinstance(config, str) or not re.fullmatch(r"(?:blobs/sha256/[0-9a-f]{64}|[0-9a-f]{64}\.json)", config):
        raise UnsupportedFailure("Unsupported image config path")
    layers = manifest[0].get("Layers")
    if not isinstance(layers, list) or not layers or not all(isinstance(x, str) for x in layers):
        raise MetadataFailure("Invalid image layer list")
    if any(not re.fullmatch(r"(?:blobs/sha256/[0-9a-f]{64}|[0-9a-f]{64}/layer\.tar)", x) for x in layers):
        raise UnsupportedFailure("Unsupported image layer path")
    if len(set(layers)) != len(layers):
        raise UnsupportedFailure("Repeated image layers are not supported")
    return config, layers


def image_config(path: str, config_name: str, layers: list[str], inspected: dict | None) -> dict:
    config_data = None
    budget = Budget()
    seen: set[str] = set()
    with tarfile.open(path, mode="r|gz") as archive:
        for entry in archive:
            budget.tick(entry.size, entry=True)
            if check_path(entry.name):
                raise PathFailure("Unsafe image archive entry")
            if entry.name in seen:
                raise AuditFailure("Duplicate image archive entry")
            seen.add(entry.name)
            if entry.isdir():
                continue
            if not entry.isfile():
                raise UnsupportedFailure("Unsupported image archive entry")
            if entry.name in layers:
                continue
            if entry.name == config_name:
                if config_data is not None or entry.size > 10 * 1024 * 1024:
                    raise MetadataFailure("Invalid image config")
                source = archive.extractfile(entry)
                if source is None:
                    raise MetadataFailure("Missing image config")
                config_data = source.read()
                continue
            # OCI metadata may contain extra manifest/index descriptors. Inspect
            # each small JSON descriptor; reject all other unreferenced data.
            descriptor_blob = re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", entry.name)
            if entry.name not in {"manifest.json", "repositories", "index.json", "oci-layout"} and not descriptor_blob:
                raise UnsupportedFailure("Unreferenced image archive content")
            if entry.size > 2 * 1024 * 1024:
                raise LimitFailure("Image descriptor exceeds size limit")
            source = archive.extractfile(entry)
            if source is None:
                raise AuditFailure("Missing image descriptor")
            data = source.read()
            if finding(data):
                raise MatchFailure("Possible secret in image descriptor")
            if descriptor_blob and hashlib.sha256(data).hexdigest() != entry.name.rsplit("/", 1)[-1]:
                raise MetadataFailure("Image descriptor digest mismatch")
            json.loads(data)
    if config_data is None:
        raise MetadataFailure("Missing image config")
    if finding(config_data):
        raise MatchFailure("Possible secret in image config")
    config_digest = hashlib.sha256(config_data).hexdigest()
    named_digest = config_name.rsplit("/", 1)[-1].removesuffix(".json")
    if config_digest != named_digest:
        raise MetadataFailure("Image config digest mismatch")
    if inspected is not None and inspected.get("Id") != "sha256:" + config_digest:
        raise MetadataFailure("Inspected image ID does not match archive config")
    config = json.loads(config_data)
    if not isinstance(config, dict):
        raise MetadataFailure("Invalid image config")
    diffids = config.get("rootfs", {}).get("diff_ids")
    if not isinstance(diffids, list) or not all(isinstance(x, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in diffids):
        raise MetadataFailure("Invalid image diff IDs")
    return config


class DigestReader:
    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        data = self.source.read(size)
        self.digest.update(data)
        return data


class PrefixReader:
    def __init__(self, prefix, source):
        self.prefix = prefix
        self.source = source

    def read(self, size=-1):
        if size < 0:
            result, self.prefix = self.prefix, b""
            return result + self.source.read()
        result, self.prefix = self.prefix[:size], self.prefix[size:]
        return result + self.source.read(size - len(result)) if len(result) < size else result


def classify_layers(target: dict, reference: str, expected_id: str) -> tuple[int, int]:
    # The caller must establish the reference's provenance independently. A
    # local RepoDigest comparison binds the comparison to exact content, not a
    # filename, mutable tag, or inferred history. This never skips inspection.
    if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", reference):
        raise AuditFailure("An exact base repository digest is required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_id):
        raise AuditFailure("An exact base image ID is required")
    try:
        result = subprocess.run(["docker", "image", "inspect", reference], capture_output=True, check=True, timeout=10)
        base = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise AuditFailure("Unable to verify base image identity") from None
    if not isinstance(base, list) or len(base) != 1:
        raise AuditFailure("Invalid base image identity")
    base = base[0]
    if base.get("Id") != expected_id or reference not in (base.get("RepoDigests") or []):
        raise AuditFailure("Base image identity does not match trusted inputs")
    target_layers = target.get("RootFS", {}).get("Layers")
    base_layers = base.get("RootFS", {}).get("Layers")
    if not isinstance(base_layers, list) or not base_layers or not isinstance(target_layers, list) or target_layers[:len(base_layers)] != base_layers:
        raise AuditFailure("Image does not descend from the specified base")
    return len(base_layers), len(target_layers) - len(base_layers)


def audit(path: str, inspected: dict | None = None) -> int:
    PROGRESS.update(completed=0, total=0)
    config_name, layers = manifest_layers(path)
    PROGRESS["total"] = len(layers)
    config = image_config(path, config_name, layers, inspected)
    diffids = config["rootfs"]["diff_ids"]
    if len(diffids) != len(layers):
        raise MetadataFailure("Image layer and diff ID counts differ")
    if inspected is not None and inspected.get("RootFS", {}).get("Layers") != diffids:
        raise MetadataFailure("Inspected image layers do not match archive config")
    expected = dict(zip(layers, diffids, strict=True))
    inspected_layers: set[str] = set()
    budget = Budget()
    with tarfile.open(path, mode="r|gz") as archive:
        for entry in archive:
            budget.tick(entry=True)
            if entry.name not in expected:
                continue
            if entry.name in inspected_layers or not entry.isfile():
                raise AuditFailure("Duplicate or invalid image layer")
            file = archive.extractfile(entry)
            if file is None:
                raise AuditFailure("Unable to inspect layer archive")
            compressed = DigestReader(file)
            head = compressed.read(6)
            stream = PrefixReader(head, compressed)
            if head.startswith(b"\x1f\x8b"):
                expanded = gzip.GzipFile(fileobj=stream)
            elif head.startswith(b"BZh"):
                expanded = bz2.BZ2File(stream)
            elif head.startswith(b"\xfd7zXZ\x00"):
                expanded = lzma.LZMAFile(stream)
            elif head.startswith(b"\x28\xb5\x2f\xfd"):
                raise UnsupportedFailure("Unsupported image layer compression")
            else:
                expanded = stream
            uncompressed = DigestReader(expanded)
            with tarfile.open(fileobj=uncompressed, mode="r|") as layer:
                check_layer(layer, budget)
            while uncompressed.read(CHUNK):
                budget.tick()
            while compressed.read(CHUNK):
                budget.tick()
            if entry.name.startswith("blobs/sha256/") and compressed.digest.hexdigest() != entry.name.rsplit("/", 1)[-1]:
                raise MetadataFailure("Image layer digest mismatch")
            if "sha256:" + uncompressed.digest.hexdigest() != expected[entry.name]:
                raise MetadataFailure("Image layer order or diff ID mismatch")
            inspected_layers.add(entry.name)
            PROGRESS["completed"] = len(inspected_layers)
    if inspected_layers != set(layers):
        raise AuditFailure("Missing or uninspected image layers")
    return len(inspected_layers)


def main(arguments: list[str]) -> int:
    machine = bool(arguments and arguments[-1] == "--machine")
    args = arguments[:-1] if machine else arguments
    PROGRESS.update(completed=0, total=0)
    code = "ERROR"
    count = 0

    def timeout_handler(_signal, _frame):
        raise LimitFailure("Inspection time limit exceeded")

    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, MAX_SECONDS)
        # Bound parser allocations before malformed metadata can be processed.
        for limit, ceiling in ((resource.RLIMIT_AS, 1024**3), (resource.RLIMIT_FSIZE, MAX_ARCHIVE_BYTES)):
            soft, hard = resource.getrlimit(limit)
            if soft == resource.RLIM_INFINITY or soft > ceiling:
                resource.setrlimit(limit, (min(ceiling, hard) if hard != resource.RLIM_INFINITY else ceiling, hard))
        if not (len(args) in (2, 3) or (len(args) == 5 and args[2] == "--base")):
            raise AuditFailure("Invalid arguments")
        inspected = audit_metadata(args[1])
        if len(args) == 3:
            with open(args[2], "rb") as history:
                data = history.read(10 * 1024 * 1024 + 1)
                if len(data) > 10 * 1024 * 1024:
                    raise LimitFailure("Image history exceeds size limit")
                if finding(data):
                    raise MatchFailure("Possible secret in image history")
        if not machine and len(args) != 5:
            print("Layer provenance unverified; inspecting every layer without exemptions.", flush=True)
        count = audit(args[0], inspected)
        if len(args) == 5:
            matched, added = classify_layers(inspected, args[3], args[4])
            if not machine:
                print(f"Digest-matched base layers: {matched}; subsequent layers: {added}. All were inspected.")
        code = "PASS"
    except BaseException as error:
        # The machine protocol emits fixed enum values, never exception text.
        if isinstance(error, PathFailure):
            code = "PATH"
        elif isinstance(error, MetadataFailure):
            code = "METADATA"
        elif isinstance(error, MatchFailure):
            code = "MATCH"
        elif isinstance(error, UnsupportedFailure):
            code = "UNSUPPORTED"
        elif isinstance(error, LimitFailure):
            code = "LIMIT"
        else:
            code = "ERROR"
        if not machine:
            print(f"INCOMPLETE: fully inspected layers {PROGRESS['completed']}/{PROGRESS['total']}", file=sys.stderr)
            if isinstance(error, AuditFailure):
                print(f"Image audit failed: {error}", file=sys.stderr)
            else:
                print("Image audit failed: unreadable or malformed image archive or metadata", file=sys.stderr)
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except BaseException:
            code = "ERROR"

    if machine:
        completed, total = PROGRESS.get("completed"), PROGRESS.get("total")
        if not (type(completed) is int and type(total) is int and 0 <= completed <= total <= MAX_MEMBERS):
            code, completed, total = "ERROR", 0, 0
        elif code == "PASS" and (total == 0 or completed != total or count != total):
            code, completed, total = "ERROR", 0, 0
        print(f"AUDIT_STATUS {code} {completed} {total}")
    elif code == "PASS":
        print(f"Inspected {count} image layers; no configured high-confidence findings. This is not proof that secrets are absent.")
    return 0 if code == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
