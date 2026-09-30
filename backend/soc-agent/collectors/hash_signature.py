"""Event-driven file hash and platform trust inspection with metadata caching."""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import threading
from collections import OrderedDict
from datetime import datetime, timezone


class HashSignatureEngine:
    """Hash unchanged files once; SHA-256 is always the primary identity."""

    def __init__(self, max_entries=10_000):
        self._max_entries = max(100, int(max_entries))
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _metadata(path):
        stat = os.stat(path, follow_symlinks=False)
        return (int(stat.st_size), int(stat.st_mtime_ns), int(getattr(stat, 'st_ino', 0)))

    def inspect(self, path, include_sha1=False, include_md5=False, signature=True):
        if not path or not os.path.isfile(path) or os.path.islink(path):
            return {}
        try:
            metadata = self._metadata(path)
        except OSError:
            return {}
        normalized = os.path.normcase(os.path.abspath(path))
        cache_key = (normalized, metadata, bool(include_sha1), bool(include_md5), bool(signature))
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._cache.move_to_end(cache_key)
                return {**cached, 'hashCached': True}

        algorithms = {'sha256': hashlib.sha256()}
        if include_sha1:
            algorithms['sha1'] = hashlib.sha1()  # compatibility only
        if include_md5:
            algorithms['md5'] = hashlib.md5()  # compatibility only
        try:
            with open(path, 'rb') as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    for digest in algorithms.values():
                        digest.update(chunk)
            if self._metadata(path) != metadata:  # do not publish a torn read
                return {}
        except (OSError, PermissionError):
            return {}

        result = {name: digest.hexdigest() for name, digest in algorithms.items()}
        result.update({'fileSize': metadata[0], 'fileMtimeNs': metadata[1], 'hashAlgorithm': 'sha256', 'hashCached': False})
        if signature:
            if platform.system() == 'Windows':
                result.update(self._windows_authenticode(path))
            elif platform.system() == 'Linux':
                result.update(self._linux_package_status(path))
            elif platform.system() == 'Darwin':
                result.update(self._macos_codesign_status(path))

        with self._lock:
            for key in [key for key in self._cache if key[0] == normalized and key != cache_key]:
                self._cache.pop(key, None)
            self._cache[cache_key] = dict(result)
            while len(self._cache) > self._max_entries:
                self._cache.popitem(last=False)
        return result

    @staticmethod
    def _windows_authenticode(path):
        escaped = path.replace("'", "''")
        script = (
            "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "';$c=$s.SignerCertificate;"
            "[pscustomobject]@{Status=[string]$s.Status;StatusMessage=$s.StatusMessage;"
            "Publisher=if($c){$c.GetNameInfo('SimpleName',$false)}else{''};Subject=if($c){$c.Subject}else{''};"
            "Issuer=if($c){$c.Issuer}else{''};Serial=if($c){$c.SerialNumber}else{''};"
            "Thumbprint=if($c){$c.Thumbprint}else{''};ValidFrom=if($c){$c.NotBefore.ToUniversalTime().ToString('o')}else{$null};"
            "ValidUntil=if($c){$c.NotAfter.ToUniversalTime().ToString('o')}else{$null}}|ConvertTo-Json -Compress"
        )
        try:
            completed = subprocess.run(
                ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                capture_output=True, text=True, timeout=8, check=False,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            data = json.loads(completed.stdout.strip() or '{}')
        except (OSError, subprocess.SubprocessError, ValueError):
            return {'signatureStatus': 'UNKNOWN', 'trustStatus': 'UNKNOWN'}
        native = str(data.get('Status') or 'UnknownError')
        status = {'Valid': 'VALID', 'NotSigned': 'UNSIGNED', 'HashMismatch': 'INVALID', 'NotTrusted': 'UNTRUSTED_PUBLISHER', 'UnknownError': 'UNKNOWN'}.get(native, 'UNKNOWN')
        valid_until = data.get('ValidUntil')
        if status == 'VALID' and valid_until:
            try:
                if datetime.fromisoformat(str(valid_until).replace('Z', '+00:00')) < datetime.now(timezone.utc):
                    status = 'EXPIRED'
            except ValueError:
                pass
        return {
            'signatureStatus': status, 'signatureNativeStatus': native,
            'signatureMessage': str(data.get('StatusMessage') or '')[:500],
            'publisher': data.get('Publisher') or '', 'certificateSubject': data.get('Subject') or '',
            'certificateIssuer': data.get('Issuer') or '', 'certificateSerial': data.get('Serial') or '',
            'certificateThumbprint': data.get('Thumbprint') or '', 'certificateValidFrom': data.get('ValidFrom'),
            'certificateValidUntil': valid_until, 'trustStatus': 'TRUSTED' if status == 'VALID' else status,
        }

    @staticmethod
    def _linux_package_status(path):
        # Linux package verification is deliberately distinct from Authenticode.
        owner, verification = '', 'NOT_PACKAGE_MANAGED'
        try:
            if shutil.which('dpkg-query'):
                found = subprocess.run(['dpkg-query', '-S', path], capture_output=True, text=True, timeout=3, check=False)
                if found.returncode == 0:
                    owner = found.stdout.split(':', 1)[0].strip()
                    # `dpkg --verify <package>` scans every file in a package and
                    # can flag an unrelated changed config file. Compare only the
                    # executable's own recorded digest when dpkg provides one.
                    package_base = owner.split(':', 1)[0]
                    sums_path = f'/var/lib/dpkg/info/{package_base}.md5sums'
                    expected_md5 = ''
                    try:
                        relative = os.path.abspath(path).lstrip('/')
                        with open(sums_path, 'r', encoding='utf-8', errors='replace') as sums:
                            for line in sums:
                                digest, _, listed_path = line.strip().partition('  ')
                                if listed_path == relative:
                                    expected_md5 = digest.lower()
                                    break
                    except OSError:
                        pass
                    if expected_md5:
                        digest = hashlib.md5()  # package metadata compatibility
                        with open(path, 'rb') as handle:
                            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                                digest.update(chunk)
                        verification = 'VERIFIED' if digest.hexdigest().lower() == expected_md5 else 'MODIFIED'
                    else:
                        verification = 'PACKAGE_OWNED_UNVERIFIED'
            elif shutil.which('rpm'):
                found = subprocess.run(['rpm', '-qf', path], capture_output=True, text=True, timeout=3, check=False)
                if found.returncode == 0:
                    owner = found.stdout.strip().splitlines()[0]
                    verified = subprocess.run(['rpm', '-V', owner], capture_output=True, text=True, timeout=8, check=False)
                    verification = 'VERIFIED' if verified.returncode == 0 and not verified.stdout.strip() else 'MODIFIED'
        except (OSError, subprocess.SubprocessError):
            verification = 'UNKNOWN'
        return {'signatureStatus': 'UNKNOWN', 'trustStatus': 'PACKAGE_VERIFICATION', 'packageOwner': owner, 'packageVerificationStatus': verification}

    @staticmethod
    def _macos_codesign_status(path):
        """Validate the exact executable with Apple's native code-signing tool."""
        try:
            verified = subprocess.run(
                ['codesign', '--verify', '--strict', '--verbose=2', path],
                capture_output=True, text=True, timeout=8, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return {'signatureStatus': 'UNKNOWN', 'trustStatus': 'UNKNOWN'}

        diagnostic = f'{verified.stdout}\n{verified.stderr}'.strip()
        if verified.returncode == 0:
            status = 'VALID'
        elif 'not signed at all' in diagnostic.lower():
            status = 'UNSIGNED'
        else:
            status = 'INVALID'

        publisher = ''
        team_id = ''
        try:
            details = subprocess.run(
                ['codesign', '--display', '--verbose=4', path],
                capture_output=True, text=True, timeout=8, check=False,
            )
            detail_text = f'{details.stdout}\n{details.stderr}'
            authorities = [
                line.split('=', 1)[1].strip()
                for line in detail_text.splitlines()
                if line.startswith('Authority=')
            ]
            publisher = authorities[0] if authorities else ''
            team_line = next((line for line in detail_text.splitlines() if line.startswith('TeamIdentifier=')), '')
            team_id = team_line.split('=', 1)[1].strip() if '=' in team_line else ''
        except (OSError, subprocess.SubprocessError):
            pass
        return {
            'signatureStatus': status,
            'trustStatus': 'TRUSTED' if status == 'VALID' else status,
            'signatureMessage': diagnostic[:500],
            'publisher': publisher,
            'teamIdentifier': team_id,
        }


ENGINE = HashSignatureEngine()
