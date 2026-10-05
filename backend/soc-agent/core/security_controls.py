"""Runtime evidence for server-managed controls; no claims of kernel immunity."""
import ctypes
import sys
from urllib.parse import urlparse
from .file_open_protection import FileOpenProtection

CONTROL_KEYS = {
    'selfProtection': 'self_protection', 'tamperProtection': 'tamper_protection',
    'antiDebugging': 'anti_debugging', 'antiReverseEngineering': 'anti_reverse_engineering',
    'antiDumpProtection': 'anti_dump_protection', 'integrityVerification': 'integrity_verification',
    'secureCommunication': 'secure_communication', 'configurationEncryption': 'configuration_encryption',
    'certificateValidation': 'certificate_validation', 'codeIntegrityMonitoring': 'code_integrity_monitoring',
    'lockdownMode': 'lockdown_mode', 'maintenanceMode': 'maintenance_mode',
}
REQUIRED = {'secure_communication', 'configuration_encryption', 'certificate_validation'}


def normalize_policy(policy):
    if not isinstance(policy, dict):
        raise ValueError('Security policy must be an object')
    version = policy.get('policy_version')
    if type(version) is not int or version < 1:
        raise ValueError('Invalid security policy version')
    for wire in CONTROL_KEYS.values():
        if type(policy.get(wire)) is not bool:
            raise ValueError('Missing or invalid security control: ' + wire)
    if any(policy[wire] is False for wire in REQUIRED):
        raise ValueError('Transport, configuration encryption and certificate verification are mandatory')
    erase = policy.get('erase_code_on_open', False)
    if type(erase) is not bool:
        raise ValueError('Invalid file-open response policy')
    return {**{wire: policy[wire] for wire in CONTROL_KEYS.values()}, 'policy_version': version, 'erase_code_on_open': erase}


class RuntimeSecurity:
    def __init__(self):
        self._core_limit = None
        self._dumpable = None
        self.file_open = FileOpenProtection()
        self.dump_status = {'state': 'unsupported', 'detail': 'Anti-dump hardening has not been applied.'}

    def apply(self, config):
        self.file_open.apply(config)
        enabled = config.get('self_protection', True) and config.get('anti_dump_protection', True)
        if sys.platform == 'win32':
            self.dump_status = {'state': 'unsupported', 'detail': 'This Python Windows agent has no protected-process driver; memory dump prevention is unavailable.'}
            return
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
            if enabled:
                if self._core_limit is None:
                    self._core_limit = soft
                resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
                if sys.platform.startswith('linux'):
                    libc = ctypes.CDLL(None, use_errno=True)
                    if self._dumpable is None:
                        self._dumpable = libc.prctl(3, 0, 0, 0, 0)  # PR_GET_DUMPABLE
                    if self._dumpable < 0 or libc.prctl(4, 0, 0, 0, 0) != 0:
                        raise OSError(ctypes.get_errno(), 'PR_SET_DUMPABLE failed')
                    self.dump_status = {'state': 'enforced', 'detail': 'Linux process dumpability and core dumps disabled; privileged administrators retain access.'}
                else:
                    self.dump_status = {'state': 'monitoring', 'detail': 'Core dumps disabled; this platform has no process-memory access restriction in this agent.'}
            else:
                if self._core_limit is not None:
                    resource.setrlimit(resource.RLIMIT_CORE, (self._core_limit, hard))
                    self._core_limit = None
                if self._dumpable is not None:
                    if ctypes.CDLL(None, use_errno=True).prctl(4, self._dumpable, 0, 0, 0) != 0:
                        raise OSError('Could not restore process dumpability')
                    self._dumpable = None
                self.dump_status = {'state': 'disabled', 'detail': 'Anti-dump hardening disabled by policy.'}
        except Exception as error:
            self.dump_status = {'state': 'error', 'detail': str(error)[:300]}

    def report(self, config, integrity, transport, lockdown, maintenance):
        controls = {}
        master = config.get('self_protection', True)
        for key, wire in CONTROL_KEYS.items():
            enabled = True if wire in REQUIRED else config.get(wire, key != 'maintenanceMode') is True
            controls[key] = {'enabled': enabled, 'state': 'disabled', 'detail': 'Disabled by policy.'}
        def set_status(key, state, detail):
            controls[key].update(state=state, detail=detail)
        if master:
            set_status('selfProtection', 'monitoring', 'Agent integrity and analysis checks are running; lockdown protects command execution.')
            if config.get('tamper_protection', True):
                set_status('tamperProtection', 'monitoring' if config.get('integrity_verification', True) else 'disabled', 'Checks package code, symlinks and writable permissions; privileged OS administrators retain access.' if config.get('integrity_verification', True) else 'Requires Integrity Verification.')
            if config.get('anti_debugging', True):
                set_status('antiDebugging', 'monitoring', 'Detects attached Python and OS debuggers; does not terminate debugging tools.')
            if config.get('anti_reverse_engineering', True):
                set_status('antiReverseEngineering', 'monitoring', 'Detects known analysis tool processes. Python source extraction is not prevented.')
            if config.get('anti_dump_protection', True):
                set_status('antiDumpProtection', **self.dump_status)
            if config.get('integrity_verification', True):
                set_status('integrityVerification', 'enforced' if integrity.get('integrityStatus') == 'verified' else 'error', 'SHA-256 package manifest verification: ' + str(integrity.get('integrityStatus', 'unknown')))
            if config.get('code_integrity_monitoring', True):
                set_status('codeIntegrityMonitoring', 'monitoring' if config.get('integrity_verification', True) else 'disabled', 'Periodic package code verification on heartbeats.' if config.get('integrity_verification', True) else 'Requires Integrity Verification.')
        else:
            for key in controls:
                if CONTROL_KEYS[key] not in REQUIRED and key not in ('lockdownMode', 'maintenanceMode'):
                    set_status(key, 'disabled', 'Self Protection is disabled.')
        set_status('secureCommunication', 'enforced', 'AES-256-GCM authenticated API payloads with HMAC signed requests; plaintext API responses are rejected.')
        set_status('configurationEncryption', 'enforced' if transport.get('configuration_encrypted') else 'error', 'Installed enrollment configuration uses AES-256-GCM with a separate protected key.' if transport.get('configuration_encrypted') else 'Encrypted configuration could not be verified on disk.')
        tls = urlparse(str(config.get('server_url', ''))).scheme == 'https'
        set_status('certificateValidation', 'enforced' if tls else 'not_applicable', 'TLS server certificate chain and hostname are verified.' if tls else 'Current connection uses HTTP with encrypted payloads. TLS certificates require HTTPS.')
        if config.get('lockdown_mode', True):
            set_status('lockdownMode', 'enforced', 'Automatic safe lockdown enabled. Current containment: ' + ('active' if lockdown else 'inactive'))
        if maintenance:
            set_status('maintenanceMode', 'enforced', 'Passive mode: ordinary telemetry and response commands paused; security heartbeat remains active.')
        controls['selfProtection']['fileOpen'] = self.file_open.report(config)
        return controls
