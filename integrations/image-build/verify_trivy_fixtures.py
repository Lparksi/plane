# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Allow only exact, independently documented public happy-dom test material.

No report contents, file names or matched values are printed. Run in an isolated,
resource-limited, networkless container with read-only mounts.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import signal
import sys
import tarfile
from pathlib import Path

SRC = "/app/node_modules/.pnpm/happy-dom@21.0.4/node_modules/happy-dom/src/fetch/certificate/FetchHTTPSCertificate.ts"
LIB = "/app/node_modules/.pnpm/happy-dom@21.0.4/node_modules/happy-dom/lib/fetch/certificate/FetchHTTPSCertificate.js"
BUNDLE = "/app/apps/space/build/server/index.js"
FILE_HASHES = {
    SRC: "fb5b45345ead4b7cc6d42f18397cc2ca872e6131113c8ab45ed243402062387a",
    LIB: "0beb738f269d902037f790d6227a629121cfd2280b0bb96b44abc4e363ce4d6a",
}
BLOCK_HASH = "7f7f8c83ded111336dca167452776b8b6c35e4223882103df5edeb55875a2d41"
LOCK_RESOLUTION = (b"  happy-dom@21.0.4:\n    resolution: {integrity: "
                   b"sha512-tFm+GaLBgo6o0awHnvHaNoraVo27qJ+2tZEtZ+cIa08hXbeitrxAJajLI05hsUy/2/YTKcUjQYzHe5mCcraLBw==}")
PEM = re.compile(rb"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----", re.S)
MAX_FILE = 32 * 1024 * 1024


class Rejected(Exception):
    pass


class HashReader:
    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        data = self.source.read(size)
        self.digest.update(data)
        return data


class PrefixReader:
    def __init__(self, prefix, source):
        self.prefix, self.source = prefix, source

    def read(self, size=-1):
        if size < 0:
            result, self.prefix = self.prefix, b""
            return result + self.source.read()
        result, self.prefix = self.prefix[:size], self.prefix[size:]
        return result + self.source.read(size - len(result)) if len(result) < size else result


def archive_json(path: str, name: str, limit: int = 10 * 1024 * 1024) -> bytes:
    found = None
    with tarfile.open(path, "r|gz") as archive:
        for entry in archive:
            if entry.name == name:
                if found is not None or not entry.isfile() or entry.size > limit:
                    raise Rejected()
                source = archive.extractfile(entry)
                if source is None:
                    raise Rejected()
                found = source.read(limit + 1)
    if found is None or len(found) > limit:
        raise Rejected()
    return found


def check_block(data: bytes, findings: list[dict]) -> None:
    matches = list(PEM.finditer(data))
    if len(matches) != 1:
        raise Rejected()
    match = matches[0]
    block = match.group().replace(b"\\n", b"\n").replace(b"\\r", b"\r")
    if hashlib.sha256(block).hexdigest() != BLOCK_HASH:
        raise Rejected()
    start = data.count(b"\n", 0, match.start()) + 1
    end = data.count(b"\n", 0, match.end()) + 1
    if len(findings) != 1:
        raise Rejected()
    f = findings[0]
    if not (type(f.get("StartLine")) is int and type(f.get("EndLine")) is int
            and start <= f["StartLine"] <= f["EndLine"] <= end + 1):
        raise Rejected()


def verify(report_path: str, image_path: str, lock_path: str, image_id: str, scanner_exit: int) -> None:
    report_file = Path(report_path)
    if report_file.stat().st_size > 64 * 1024 * 1024:
        raise Rejected()
    report_raw = report_file.read_bytes()
    report = json.loads(report_raw)
    if (report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image"
            or not isinstance(report.get("Metadata"), dict) or report["Metadata"].get("ImageID") != image_id
            or not isinstance(report.get("Results"), list)):
        raise Rejected()
    wanted: dict[tuple[str, str], list[dict]] = {}
    allowed = {SRC, LIB, BUNDLE}
    for section in report["Results"]:
        if not isinstance(section, dict) or not isinstance(section.get("Secrets", []), list):
            raise Rejected()
        for f in section.get("Secrets", []):
            if not isinstance(f, dict) or f.get("RuleID") != "private-key" or section.get("Target") not in allowed:
                raise Rejected()
            target = section["Target"]
            diff = (f.get("Layer") or {}).get("DiffID")
            if not isinstance(diff, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", diff):
                raise Rejected()
            wanted.setdefault((diff, target), []).append(f)
    count = sum(map(len, wanted.values()))
    if count == 0:
        if scanner_exit != 0:
            raise Rejected()
        return
    if scanner_exit != 1 or any(len(fs) != 1 for fs in wanted.values()):
        raise Rejected()
    lock_file = Path(lock_path)
    if lock_file.stat().st_size > 10 * 1024 * 1024:
        raise Rejected()
    lock = lock_file.read_bytes()
    if lock.count(LOCK_RESOLUTION) != 1:
        raise Rejected()
    manifest = json.loads(archive_json(image_path, "manifest.json", 1024 * 1024))
    if not isinstance(manifest, list) or len(manifest) != 1:
        raise Rejected()
    config_name, layers = manifest[0].get("Config"), manifest[0].get("Layers")
    if not isinstance(config_name, str) or not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", config_name):
        raise Rejected()
    if (not isinstance(layers, list) or len(set(layers)) != len(layers)
            or not all(isinstance(x, str) and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", x) for x in layers)):
        raise Rejected()
    config_raw = archive_json(image_path, config_name)
    digest = hashlib.sha256(config_raw).hexdigest()
    if image_id != "sha256:" + digest or not config_name.endswith(digest):
        raise Rejected()
    config = json.loads(config_raw)
    ids = config.get("rootfs", {}).get("diff_ids")
    if not isinstance(ids, list) or len(ids) != len(layers) or len(set(ids)) != len(ids) or report["Metadata"].get("DiffIDs") != ids:
        raise Rejected()
    mapping = dict(zip(ids, layers, strict=True))
    if any(diff not in mapping for diff, _ in wanted):
        raise Rejected()
    # Source and lib must both be present and byte-identical to verified npm
    # files. The bundle may vary but must contain only the exact public block.
    proofs = {SRC, LIB} | {target for _, target in wanted}
    seen: dict[str, tuple[str, bytes]] = {}
    target_layers = set(mapping.values())
    inspected_layers: set[str] = set()
    with tarfile.open(image_path, "r|gz") as outer:
        for entry in outer:
            if entry.name not in target_layers:
                continue
            if entry.name in inspected_layers or not entry.isfile():
                raise Rejected()
            inspected_layers.add(entry.name)
            raw = outer.extractfile(entry)
            if raw is None:
                raise Rejected()
            compressed = HashReader(raw)
            head = compressed.read(6)
            stream = PrefixReader(head, compressed)
            expanded = gzip.GzipFile(fileobj=stream) if head.startswith(b"\x1f\x8b") else stream
            if head.startswith((b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd")):
                raise Rejected()
            plain = HashReader(expanded)
            layer_diff = ids[layers.index(entry.name)]
            layer_paths = []
            with tarfile.open(fileobj=plain, mode="r|") as layer:
                for member in layer:
                    target = "/" + member.name.removeprefix("./")
                    if target not in proofs:
                        continue
                    if target in seen or not member.isfile() or member.size > MAX_FILE:
                        raise Rejected()
                    f = layer.extractfile(member)
                    if f is None:
                        raise Rejected()
                    data = f.read(MAX_FILE + 1)
                    if len(data) > MAX_FILE:
                        raise Rejected()
                    seen[target] = (layer_diff, data)
                    layer_paths.append(target)
            while plain.read(1024 * 1024):
                pass
            while compressed.read(1024 * 1024):
                pass
            if (compressed.digest.hexdigest() != entry.name.rsplit("/", 1)[-1]
                    or "sha256:" + plain.digest.hexdigest() != layer_diff):
                raise Rejected()
    if inspected_layers != target_layers or set(seen) != proofs:
        raise Rejected()
    for target, expected in FILE_HASHES.items():
        if hashlib.sha256(seen[target][1]).hexdigest() != expected:
            raise Rejected()
    for (diff, target), findings in wanted.items():
        if seen[target][0] != diff:
            raise Rejected()
        check_block(seen[target][1], findings)


def main() -> int:
    def timed_out(_signal, _frame):
        raise Rejected()
    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(240)
    try:
        if len(sys.argv) != 6 or not re.fullmatch(r"sha256:[0-9a-f]{64}", sys.argv[4]):
            raise Rejected()
        verify(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
    except BaseException:
        print("SECRET_GATE BLOCKED")
        return 1
    finally:
        signal.alarm(0)
    print("SECRET_GATE PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
