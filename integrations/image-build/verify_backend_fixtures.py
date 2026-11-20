# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Verify only two pinned public backend examples; reject every unknown finding.

Run with immutable, same-scan image/report inputs in a networkless restricted
container. Never emit findings or their values.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import signal
import sys
import tarfile
import tomllib
from pathlib import Path

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



AWS_PATH = '/code/plane/api/views/issue.py'
JWT_PATH = '/usr/local/lib/python3.12/site-packages/pyjwt-2.15.1.dist-info/METADATA'
MAX_FILE = 32 * 1024 * 1024
SPECS = {
    AWS_PATH: {
        'rule': 'aws-access-key-id',
        'file': '8454d4227edc7e5043e9a48ccc1eb9b9880d8af8352077338a1677b97fc6e5f5',
        'match': '1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3',
        'pattern': re.compile(rb'(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])'),
    },
    JWT_PATH: {
        'rule': 'jwt-token',
        'file': '1ea0c9f139b8c928276b3628af165955f6f764491448a6ad8f103cdcbb382da3',
        'match': 'bf145d9380bbe05bdc1a72525796b224f8a8c93ae0e9e102eafbc255ac1af9e8',
        'pattern': re.compile(rb'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    },
}
PYJWT_WHEEL = 'sha256:42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193'


def check_finding(data: bytes, spec: dict, finding: dict) -> None:
    if hashlib.sha256(data).hexdigest() != spec['file']:
        raise Rejected()
    matches = list(spec['pattern'].finditer(data))
    if len(matches) != 1 or hashlib.sha256(matches[0].group()).hexdigest() != spec['match']:
        raise Rejected()
    line = data.count(b'\n', 0, matches[0].start()) + 1
    if type(finding.get('StartLine')) is not int or type(finding.get('EndLine')) is not int:
        raise Rejected()
    if finding['StartLine'] != line or finding['EndLine'] != line:
        raise Rejected()


def verify(report_path: str, image_path: str, lock_path: str, image_id: str, scanner_exit: int) -> None:
    report_file = Path(report_path)
    if report_file.stat().st_size > 64 * 1024 * 1024:
        raise Rejected()
    report = json.loads(report_file.read_bytes())
    if (scanner_exit != 1 or report.get('SchemaVersion') != 2 or report.get('ArtifactType') != 'container_image'
            or not isinstance(report.get('Metadata'), dict) or report['Metadata'].get('ImageID') != image_id
            or not isinstance(report.get('Results'), list)):
        raise Rejected()
    wanted = {}
    for section in report['Results']:
        if not isinstance(section, dict) or not isinstance(section.get('Secrets', []), list):
            raise Rejected()
        for finding in section.get('Secrets', []):
            if not isinstance(finding, dict):
                raise Rejected()
            target = section.get('Target')
            if target not in SPECS or finding.get('RuleID') != SPECS[target]['rule']:
                raise Rejected()
            layer = finding.get('Layer')
            diff = layer.get('DiffID') if isinstance(layer, dict) else None
            if not isinstance(diff, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', diff) or target in wanted:
                raise Rejected()
            wanted[target] = (diff, finding)
    if not wanted:
        raise Rejected()
    lock_file = Path(lock_path)
    if lock_file.stat().st_size > 10 * 1024 * 1024:
        raise Rejected()
    lock = tomllib.loads(lock_file.read_text())
    matches = [p for p in lock.get('package', []) if p.get('name') == 'pyjwt' and p.get('version') == '2.15.1']
    if len(matches) != 1 or sum(w.get('hash') == PYJWT_WHEEL for w in matches[0].get('wheels', [])) != 1:
        raise Rejected()
    manifest = json.loads(archive_json(image_path, 'manifest.json', 1024 * 1024))
    if not isinstance(manifest, list) or len(manifest) != 1:
        raise Rejected()
    config_name, layers = manifest[0].get('Config'), manifest[0].get('Layers')
    if not isinstance(config_name, str) or not re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', config_name):
        raise Rejected()
    if (not isinstance(layers, list) or len(set(layers)) != len(layers)
            or not all(isinstance(x, str) and re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', x) for x in layers)):
        raise Rejected()
    raw_config = archive_json(image_path, config_name)
    digest = hashlib.sha256(raw_config).hexdigest()
    if image_id != 'sha256:' + digest or not config_name.endswith(digest):
        raise Rejected()
    config = json.loads(raw_config)
    ids = config.get('rootfs', {}).get('diff_ids')
    if not isinstance(ids, list) or len(ids) != len(layers) or len(set(ids)) != len(ids) or report['Metadata'].get('DiffIDs') != ids:
        raise Rejected()
    mapping = dict(zip(ids, layers, strict=True))
    if any(diff not in mapping for diff, _ in wanted.values()):
        raise Rejected()
    seen = set()
    target_layers = set(layers)
    inspected = set()
    with tarfile.open(image_path, 'r|gz') as outer:
        for entry in outer:
            if entry.name not in target_layers:
                continue
            if entry.name in inspected or not entry.isfile():
                raise Rejected()
            inspected.add(entry.name)
            raw = outer.extractfile(entry)
            if raw is None:
                raise Rejected()
            compressed = HashReader(raw)
            head = compressed.read(6)
            stream = PrefixReader(head, compressed)
            if head.startswith((b'BZh', b'\xfd7zXZ\x00', b'\x28\xb5\x2f\xfd')):
                raise Rejected()
            plain = HashReader(gzip.GzipFile(fileobj=stream) if head.startswith(b'\x1f\x8b') else stream)
            layer_diff = ids[layers.index(entry.name)]
            layer_seen = set()
            with tarfile.open(fileobj=plain, mode='r|') as layer:
                for member in layer:
                    target = '/' + member.name.removeprefix('./')
                    if target not in wanted:
                        continue
                    if target in layer_seen or not member.isfile() or member.size > MAX_FILE:
                        raise Rejected()
                    layer_seen.add(target)
                    f = layer.extractfile(member)
                    if f is None:
                        raise Rejected()
                    data = f.read(MAX_FILE + 1)
                    if len(data) > MAX_FILE or hashlib.sha256(data).hexdigest() != SPECS[target]['file']:
                        raise Rejected()
                    if layer_diff == wanted[target][0]:
                        check_finding(data, SPECS[target], wanted[target][1])
                        seen.add(target)
            while plain.read(1024 * 1024):
                pass
            while compressed.read(1024 * 1024):
                pass
            if compressed.digest.hexdigest() != entry.name.rsplit('/', 1)[-1] or 'sha256:' + plain.digest.hexdigest() != layer_diff:
                raise Rejected()
    if inspected != target_layers or seen != set(wanted):
        raise Rejected()


def main() -> int:
    def timed_out(_signal, _frame):
        raise Rejected()
    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(240)
    try:
        if len(sys.argv) != 6 or not re.fullmatch(r'sha256:[0-9a-f]{64}', sys.argv[4]):
            raise Rejected()
        verify(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
    except BaseException:
        print('SECRET_GATE BLOCKED')
        return 1
    finally:
        signal.alarm(0)
    print('SECRET_GATE PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
