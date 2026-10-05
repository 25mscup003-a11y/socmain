#!/usr/bin/env python3
"""
SOC Agent v0.1.13 — main entry point.
Usage:
  python3 agent.py test       # connectivity test (NO root needed)
  python3 agent.py run        # run in foreground
  sudo python3 agent.py install    # install as system service
  sudo python3 agent.py uninstall  # remove service
  sudo python3 agent.py start / stop / status
"""

import os
import sys
import time
import logging
import platform
import argparse
import uuid
from pathlib import Path

SYSTEM = platform.system()

# Windows PowerShell 5 can expose a legacy code page when stdout/stderr are
# redirected by an installer. Keep diagnostic output from crashing on Unicode
# status symbols; the installer enables UTF-8, while other hosts degrade safely.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors='replace')
    except (AttributeError, OSError):
        pass

# ── Logging: endpoint OS data directories only (never the source tree) ───────
def _setup_logging():
    windows_data_dir = Path(os.environ.get('AJNAT_DATA_DIR', 'C:/ProgramData/AJNAT'))
    candidates = {
        'Linux':   [Path('/var/log/soc-agent'), Path.home() / '.soc-agent' / 'logs'],
        'Darwin':  [Path('/Library/Logs/SOCAgent'), Path.home() / 'Library' / 'Logs' / 'SOCAgent'],
        'Windows': [windows_data_dir / 'logs', Path('C:/ProgramData/SOCAgent/logs')],
    }.get(SYSTEM, [])

    log_dir = None
    for d in candidates:
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / '.probe'
            probe.write_text('x')
            probe.unlink()
            log_dir = d
            break
        except (PermissionError, OSError):
            continue

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        # A disk handler is installed only after the authenticated backend has
        # issued the in-memory AES key. This prevents plaintext runtime logs.
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    return log_dir


LOG_DIR = _setup_logging()
logger  = logging.getLogger('soc-agent')


def _enable_encrypted_file_logging(encryption_key: str) -> None:
    if not LOG_DIR:
        return
    from core.encrypted_logging import EncryptedRotatingFileHandler
    root = logging.getLogger()
    target = str(LOG_DIR / 'agent.log')
    if any(getattr(handler, 'baseFilename', None) == target for handler in root.handlers):
        return
    handler = EncryptedRotatingFileHandler(
        target,
        encryption_key=encryption_key,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
    root.addHandler(handler)

# ── Ensure agent root is on sys.path ─────────────────────────────────────────
AGENT_ROOT = Path(__file__).resolve().parent
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from core.security import signed_headers


def _is_elevated() -> bool:
    """Return whether the agent has the OS identity required for enforcement."""
    if SYSTEM in ('Linux', 'Darwin'):
        return hasattr(os, 'geteuid') and os.geteuid() == 0
    if SYSTEM == 'Windows':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return False


def _require_elevated(command: str) -> None:
    """Fail closed: an unprivileged agent must never pretend IPS is active."""
    if _is_elevated():
        return
    label = 'Administrator/LocalSystem' if SYSTEM == 'Windows' else 'root'
    raise SystemExit(
        f'ERROR: AJNAT {command} requires {label} privileges. '
        'Install and run it as the operating-system service.'
    )


def _import_class(module_path, *class_suffixes):
    """
    Import a module by dotted path and return the first class whose name
    ends with one of class_suffixes.  Returns None on any failure.
    """
    try:
        import importlib
        mod = importlib.import_module(module_path)
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if isinstance(obj, type) and any(attr.endswith(s) for s in class_suffixes):
                return obj
        logger.warning(f'{module_path}: no class ending with {class_suffixes}')
        return None
    except ImportError as e:
        logger.warning(f'{module_path} not available: {e}')
        return None
    except Exception as e:
        logger.error(f'{module_path} import error: {e}')
        return None


def _start(klass, name, **kwargs):
    """Instantiate and start a service class. Returns instance or None."""
    if klass is None:
        return None
    try:
        svc = klass(**kwargs)
        svc.start()
        logger.info(f'{name} started')
        return svc
    except Exception as e:
        logger.warning(f'{name} failed to start: {e}')
        return None


def _fetch_storage_key_with_retry(config, fetcher=None, sleeper=time.sleep, max_attempts=None):
    """Wait for the mandatory server-issued spool key without exiting."""
    if fetcher is None:
        from core.storage_key import fetch_storage_key as fetcher
    attempt = 0
    delay = 5
    while True:
        attempt += 1
        try:
            return fetcher(config)
        except Exception as exc:
            if max_attempts is not None and attempt >= max_attempts:
                raise
            logger.warning(
                'Storage key unavailable (%s); secure startup will retry in %ss',
                exc,
                delay,
            )
            sleeper(delay)
            delay = min(delay * 2, 60)


def _prepare_device_mtls(config):
    """Create and enroll the endpoint certificate when HTTPS mTLS is enabled."""
    if not str(config.get('server_url', '') or '').lower().startswith('https://'):
        return False
    if not config.get('mtls_auto_enroll', True):
        return False
    from core.device_identity import enroll_device_certificate, ensure_device_identity
    ensure_device_identity(config)
    enroll_device_certificate(config)
    return True


# ── Startup event ────────────────────────────────────────────────────────────
def _send_startup_event(sender, config):
    """Send an AGENT_START alert as the first event on boot.
    This logs install data (version, system name, server URL) to the backend
    so the SOC dashboard shows when each agent started.
    """
    import socket
    hostname = ''
    try:
        hostname = socket.gethostname()
    except Exception:
        pass

    info_lines = [
        f'  System   : {config.get("system_name", "?")}',
        f'  Company  : {config.get("company_name", "?")}',
        f'  Server   : {config.get("server_url", "?")}',
        f'  Agent v  : {config.get("agent_version", "0.1.13")}',
        f'  Hostname : {hostname}',
        f'  Platform : {platform.system()} {platform.release()}',
        f'  Log dir  : {LOG_DIR}',
    ]
    logger.info('── AGENT STARTED ──────────────────────────────')
    for line in info_lines:
        logger.info(line)
    logger.info('───────────────────────────────────────────────')

    from datetime import datetime, timezone
    sender.enqueue({
        'rule_id':     'AGENT_START',
        'category':    'system',
        'severity':    'low',
        'description': (
            f'Agent v{config.get("agent_version","0.1.13")} started — system={config.get("system_name","?")} '
            f'v={config.get("agent_version","0.1.13")} '
            f'host={hostname}'
        ),
        'source':      'agent',
        'raw_log':     '\n'.join(info_lines),
        'timestamp':   datetime.now(timezone.utc).isoformat(),
    })


def _detect_host_role():
    """Best-effort role detection to stop server packages on endpoints and vice versa."""
    system = platform.system().lower()
    if system == 'windows':
      try:
          edition = getattr(platform, 'win32_edition', lambda: '')() or ''
          if 'server' in edition.lower():
              return 'server'
      except Exception:
          pass
      return 'system'

    if system == 'linux':
        server_chassis = {'11', '12', '17', '23', '28', '29', '30', '31', '32'}
        try:
            chassis = Path('/sys/class/dmi/id/chassis_type').read_text().strip()
            if chassis in server_chassis:
                return 'server'
        except Exception:
            pass
        try:
            import subprocess
            target = subprocess.run(
                ['systemctl', 'get-default'],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            ).stdout.strip()
            if target == 'multi-user.target':
                return 'server'
        except Exception:
            pass
        display_markers = [
            '/usr/bin/gnome-shell',
            '/usr/bin/startplasma-x11',
            '/usr/bin/startxfce4',
            '/usr/bin/lightdm',
            '/usr/sbin/gdm3',
        ]
        if not any(Path(p).exists() for p in display_markers):
            return 'server'
        return 'system'

    if system in ('darwin',):
        return 'system'
    return 'system'


def _enforce_device_role(config):
    expected = str(config.get('expected_device_role') or config.get('agent_type') or 'system').lower()
    if expected not in ('system', 'server'):
        return

    actual = _detect_host_role()
    if actual != expected:
        logger.critical(
            'Device role mismatch: this config/package is for %s, but this machine looks like %s. '
            'Download the correct agent from SOC Dashboard.',
            expected,
            actual,
        )
        raise SystemExit(2)


# ── Main run loop ─────────────────────────────────────────────────────────────
def build_and_run():
    logger.info('=' * 55)
    logger.info('SOC Agent starting…')
    if LOG_DIR:
        logger.info(f'Logs → {LOG_DIR / "agent.log"}')

    from core.config    import AgentConfig
    from core.state     import StateManager
    from core.sender    import AlertSender
    from core.heartbeat import HeartbeatService

    config = AgentConfig()
    _enforce_device_role(config)
    try:
        if _prepare_device_mtls(config):
            logger.info('AJNAT unique client certificate enrolled for mTLS')
    except Exception as exc:
        if config.get('mtls_required', False):
            raise RuntimeError(f'Mandatory AJNAT mTLS enrollment failed: {exc}') from exc
        logger.warning('Optional AJNAT mTLS enrollment deferred: %s', exc)
    # AES material is server-derived, held only in process memory, and never
    # persisted into company_config.json or another local key file.
    storage_key = _fetch_storage_key_with_retry(config)
    config.update_runtime({'storage_encryption_key': storage_key}, persist=False)
    _enable_encrypted_file_logging(storage_key)
    state  = StateManager(encryption_key=storage_key)
    sender = AlertSender(config, state)
    hb     = HeartbeatService(config)

    sender.start()

    # Send startup event immediately so dashboard logs it
    _send_startup_event(sender, config)

    # Native device GPS collector.  The thread is always present so a company
    # policy delivered by heartbeat can enable it without reinstall/restart.
    GPSCollector = _import_class('core.gps_location', 'GPSLocationCollector')
    if GPSCollector:
        try:
            import threading as _gps_threading
            gps_collector = GPSCollector(config, state=state)

            def _run_gps_location():
                while True:
                    try:
                        if gps_collector.enabled:
                            gps_collector.run_and_report(sender=sender)
                            time.sleep(gps_collector.interval_seconds)
                        else:
                            time.sleep(15)
                    except Exception as gps_error:
                        logger.warning(f'[GPSLocation] collection error: {gps_error}')
                        time.sleep(max(15, int(config.get('memory_scanner_interval_seconds', 60) or 60)))

            _gps_threading.Thread(target=_run_gps_location, daemon=True, name='gps-location').start()
            logger.info('GPS location collector ready (policy-gated)')
        except Exception as gps_error:
            logger.warning(f'GPS location collector failed to start: {gps_error}')

    # Optional VirusTotal scanner (shared by multiple modules)
    vt = None
    vt_key = config.get('virustotal_api_key', '')
    if vt_key:
        VTScanner = _import_class('detectors.virustotal', 'Scanner')
        if VTScanner:
            try:
                vt = VTScanner(vt_key, encryption_key=storage_key)
                logger.info('VirusTotal enrichment active')
            except Exception as e:
                logger.warning(f'VT init: {e}')

    # ── Malware Responder — auto-quarantine detected malware ─────────────
    responder = None
    if config.get('response_enabled', True):
        MalwareResponder = _import_class('core.malware_responder', 'Responder')
        if MalwareResponder:
            try:
                responder = MalwareResponder(sender=sender, config=config)
                responder.start()
                logger.info('Malware responder started (auto-response enabled)')
            except Exception as e:
                logger.warning(f'Malware responder failed: {e}')

    # Rule detector (wraps every log line)
    detector = None
    RuleDetector = _import_class('detectors.rules', 'Detector')
    if RuleDetector:
        try:
            detector = RuleDetector(sender, responder=responder, config=config)
            logger.info('Rule detector active')
        except Exception as e:
            logger.warning(f'Rule detector: {e}')

    def on_log_line(line, source):
        if detector and line.strip():
            try:
                detector.analyze(line, source)
            except Exception:
                pass

    # Collectors
    LogCollector  = _import_class('collectors.logs',        'Collector')
    NetCollector  = _import_class('collectors.network',     'Collector')
    ProcCollector = _import_class('collectors.processes',   'Collector', 'Monitor')
    USBCollector  = _import_class('collectors.usb',         'Collector')
    FileCollector = _import_class('collectors.file_monitor','Collector', 'Monitor')
    BrowserCollector = _import_class('collectors.browser_activity', 'Collector')
    EmailThreatCollector = _import_class('collectors.email_threat', 'Collector')
    LateralMovementCollector = _import_class('collectors.lateral_movement', 'Collector')
    CredentialSecurityCollector = _import_class('collectors.credential_security', 'Collector')
    DataSecurityCollector = _import_class('collectors.data_security', 'Collector')
    InputBehaviorCollector = _import_class('collectors.input_behavior', 'Collector')
    ProcessAssetCollector = _import_class('collectors.process_assets', 'Collector')
    PatchInventoryCollector = _import_class('collectors.patch_inventory', 'Collector')
    WindowsProcessEventCollector = _import_class('collectors.windows_process_events', 'Collector')
    WorkloadActivityCollector = _import_class('collectors.workload_activity', 'Collector')
    KernelMonitorCollector = _import_class('collectors.kernel_monitor', 'Collector')

    _start(LogCollector,  'Log collector',     state=state, on_line=on_log_line)
    network_collector = _start(
        NetCollector, 'Network monitor', sender=sender, vt_scanner=vt, config=config
    ) if config.get('network_monitor_enabled', True) else None
    if config.get('process_monitor_enabled', True):
        _start(ProcCollector, 'Process monitor', sender=sender, config=config)
        if config.get('advanced_process_monitor_enabled', True):
            _start(ProcessAssetCollector, 'Process asset/workload monitor', sender=sender, config=config)
            if config.get('workload_activity_monitor_enabled', True):
                _start(WorkloadActivityCollector, 'Application/database activity monitor', sender=sender, config=config)
            if SYSTEM == 'Windows':
                _start(
                    WindowsProcessEventCollector,
                    'Windows kernel-backed process telemetry',
                    sender=sender,
                    state=state,
                    config=config,
                    on_dns_query=network_collector.observe_dns_query if network_collector else None,
                    on_network_connection=network_collector.observe_network_connection if network_collector else None,
                )
    if config.get('kernel_monitoring_enabled', True):
        _start(KernelMonitorCollector, 'Kernel/driver monitor', sender=sender, config=config)
    if config.get('patch_inventory_enabled', True):
        _start(PatchInventoryCollector, 'Patch/software inventory monitor', sender=sender, config=config)
    if config.get('usb_monitor_enabled', True):
        _start(USBCollector, 'USB monitor', sender=sender)
    else:
        logger.info('USB monitor disabled by agent configuration')
    _start(FileCollector, 'File monitor', sender=sender, config=config)
    _start(BrowserCollector, 'Browser login/MFA monitor', sender=sender)
    if config.get('lateral_movement_monitoring_enabled', True):
        _start(LateralMovementCollector, 'Lateral movement monitor', sender=sender, config=config)
    # Keep the lightweight worker alive so heartbeat policy changes can enable
    # or disable this module without requiring an agent restart.
    _start(CredentialSecurityCollector, 'Credential security monitor', sender=sender, config=config)
    # Complements FIM/USB/network telemetry with bounded process-side DLP
    # context. Policy can be changed by heartbeat without reinstalling.
    _start(DataSecurityCollector, 'Data security monitor', sender=sender, config=config)
    _start(InputBehaviorCollector, 'Privacy-safe mouse/keyboard behavior monitor', sender=sender, config=config, state=state)
    if config.get('email_threat_monitoring_enabled', True):
        _start(EmailThreatCollector, 'Email threat monitor', sender=sender, config=config)

    # YARA scanner
    if config.get('yara_enabled', True):
        YaraScanner = _import_class('detectors.yara_scanner', 'Scanner')
        _start(YaraScanner, 'YARA scanner', sender=sender, vt_scanner=vt, config=config)

    # Anomaly detector
    AnomalyDetector = _import_class('detectors.anomaly', 'Detector')
    _start(AnomalyDetector, 'Anomaly detector', sender=sender, config=config)

    # ── LOLBins Detector — living-off-the-land binary abuse ─────────────────
    if config.get('lolbins_enabled', True):
        LOLBinsDetector = _import_class('detectors.lolbins', 'Detector')
        if LOLBinsDetector:
            try:
                lolbins = LOLBinsDetector(sender=sender, config=config)
                lolbins.start()
                logger.info('LOLBins detector started (T1059/T1218/T1105)')
            except Exception as e:
                logger.warning(f'LOLBins detector failed to start: {e}')
        else:
            logger.info('LOLBins: module not found — skipped')

    # ── Ransomware & Encryption Detector ─────────────────────────────────────
    # Keep the lightweight detector lifecycle active even when policy disables
    # alerting, so a later heartbeat can enable it without reinstall/restart.
    RansomwareDetector = _import_class('detectors.ransomware', 'Detector', 'Monitor')
    if RansomwareDetector:
        try:
            ransom = RansomwareDetector(sender=sender, config=config)
            ransom.start()
            logger.info('Ransomware/Encryption detector started (T1486/T1490; policy=%s)',
                        'enabled' if config.get('ransomware_enabled', True) else 'disabled')
        except Exception as e:
            logger.warning(f'Ransomware detector failed to start: {e}')
    else:
        logger.info('Ransomware: module not found — skipped')

    # ── EDR — process monitoring, kill malicious processes ───────────────────
    edr = None
    if config.get('edr_enabled', True):
        EDRModule = _import_class('core.edr', 'Module')
        if EDRModule:
            try:
                edr = EDRModule(sender=sender)
                edr.start()
                logger.info('EDR module started')
            except Exception as e:
                logger.warning(f'EDR failed to start: {e}')
        else:
            logger.info('EDR: module not found — skipped')

    # ── IDS — intrusion detection (C2 ports, port scans, brute-force) ───────
    ids = None
    if config.get('ids_enabled', True):
        IDSModule = _import_class('core.ids', 'Module')
        if IDSModule:
            try:
                ids = IDSModule(sender=sender, config=config)
                logger.info('IDS module ready')
            except Exception as e:
                logger.warning(f'IDS failed to start: {e}')
        else:
            logger.info('IDS: module not found — skipped')

    # ── Firewall Control — apply rules from dashboard ───────────────────────
    firewall = None
    if config.get('firewall_enabled', True):
        FirewallModule = _import_class('core.firewall', 'Module')
        if FirewallModule:
            try:
                firewall = FirewallModule(sender=sender, config=config)
                logger.info('Firewall control module ready')
            except Exception as e:
                logger.warning(f'Firewall module failed to init: {e}')
        else:
            logger.info('Firewall: module not found — skipped')
    if network_collector is not None:
        network_collector.set_firewall(firewall)

    # ── IPS — auto-block malicious IPs via host firewall ─────────────────────
    ips = None
    if config.get('ips_enabled', True):
        IPSModule = _import_class('core.ips', 'Module')
        if IPSModule:
            try:
                ips = IPSModule(sender=sender, config=config)
                logger.info('IPS module ready')
            except Exception as e:
                logger.warning(f'IPS failed to init: {e}')
        else:
            logger.info('IPS: module not found — skipped')

    if ids:
        ids.set_ips(ips)
        ids.start()
        logger.info('IDS module started')

    # Auto-response depends on the firewall and IPS instances above.
    auto_response = None
    if config.get('auto_response_enabled', True):
        AutoResponseEngine = _import_class('core.auto_response', 'Engine')
        if AutoResponseEngine:
            try:
                auto_response = AutoResponseEngine(sender=sender, config=config,
                                                    ips=ips, firewall=firewall)
                auto_response.start()
                hb.set_response_handler(auto_response)
                logger.info('Auto-response engine started')
            except Exception as e:
                logger.warning(f'Auto-response engine failed: {e}')

    # Start heartbeat only after its response handler is ready.  Otherwise the
    # initial heartbeat can claim and clear queued firewall commands before the
    # firewall/IPS modules have finished initializing.
    hb.start()

    # ── WAF v2.0 — Smart Web Application Firewall ─────────────────────────────
    # Auto-detects ALL running web services, starts proxy WAF per port.
    # Detection mode by default; optional transparent nftables REDIRECT via
    # config waf_intercept. Blocks attacker IPs on the local host firewall.
    # No config needed — port detection is automatic.
    WAFModule = _import_class('core.waf', 'Module') if config.get('waf_enabled', True) else None
    if WAFModule:
        try:
            waf = WAFModule(sender=sender, ips=ips, config=config)
            waf.start()
            logger.info('WAF v2.0 started — auto-detecting web service ports')
        except Exception as e:
            logger.warning(f'WAF failed to start: {e}')
    elif config.get('waf_enabled', True):
        logger.info('WAF: module not found — skipped')
    else:
        logger.info('WAF disabled by agent configuration')

    # ── Suricata / Zeek IDS parser ────────────────────────────────────────────
    if config.get('ids_enabled', True):
        SuricataParser = _import_class('core.suricata_parser', 'Parser')
        if SuricataParser:
            try:
                # Pass the IPS instance so Suricata alerts can be enforced by
                # the local firewall when ips_auto_block is enabled.
                sur = SuricataParser(sender=sender, config=config, ips=ips)
                sur.start()
                logger.info('Suricata/Zeek parser started')
            except Exception as e:
                logger.warning(f'Suricata/Zeek parser failed: {e}')
        else:
            logger.info('Suricata/Zeek parser: module not found — skipped')

    # ── Memory Scanner — process injection, shellcode, LSASS access ─────────
    if config.get('memory_scanner_enabled', True):
        MemScanner = _import_class('core.memory_scanner', 'Scanner')
        if MemScanner:
            try:
                import threading
                def _run_mem_scanner():
                    import time
                    ms = MemScanner(config=config)
                    while True:
                        try:
                            findings = ms.run_and_report(sender=sender)
                            if findings:
                                logger.warning(f'[MemScanner] {len(findings)} suspicious memory regions found')
                        except Exception as e:
                            logger.warning(f'[MemScanner] scan error: {e}')
                        time.sleep(60)
                threading.Thread(target=_run_mem_scanner, daemon=True, name='memory-scanner').start()
                logger.info('Memory scanner started (T1055/T1003/T1190)')
            except Exception as e:
                logger.warning(f'Memory scanner failed: {e}')

    # ── Registry Monitor — Windows persistence key polling ───────────────────
    if SYSTEM == 'Windows' and config.get('registry_monitor_enabled', True):
        RegMonitor = _import_class('core.registry_monitor', 'RegistryMonitor', 'Monitor')
        if RegMonitor:
            try:
                import threading as _t_reg, time as _time_reg
                def _run_reg_monitor():
                    interval = max(15, int(config.get('registry_monitor_interval_seconds', 60) or 60))
                    rm = RegMonitor(config=config, poll_interval=interval)
                    while True:
                        try:
                            rm.run_and_report(sender=sender)
                        except Exception as e:
                            logger.warning(f'[RegMonitor] error: {e}')
                        _time_reg.sleep(interval)
                threading.Thread(target=_run_reg_monitor, daemon=True, name='registry-monitor').start()
                logger.info('Registry monitor started (T1547.001)')
            except Exception as e:
                logger.warning(f'Registry monitor failed: {e}')

    # ── Geo Enrichment — impossible travel + IP geo enrichment ─────────────
    if config.get('geo_enrichment_enabled', True):
        GeoEnricher = _import_class('core.geo_enrichment', 'Enrichment', 'Enricher')
        if GeoEnricher:
            try:
                import threading as _t, time as _time
                _ge_inst = GeoEnricher(config=config)
                def _run_geo():
                    while True:
                        try:
                            if hasattr(_ge_inst, 'run_and_report'):
                                _ge_inst.run_and_report([], sender=sender)
                        except Exception as _e:
                            logger.warning(f'[GeoEnrich] {_e}')
                        _time.sleep(300)
                _t.Thread(target=_run_geo, daemon=True, name='geo-enrichment').start()
                logger.info('Geo enrichment started (impossible travel detection active)')
            except Exception as e:
                logger.warning(f'Geo enrichment failed: {e}')

    # ── DNS Cache Poison Detector — DNS resolution baseline + change alert ───
    # Always load the manager so a policy disabled at startup can be enabled
    # remotely without reinstalling or restarting the endpoint agent.
    cache_poison_detector = None
    CPDetector = _import_class('core.cache_poison_detector', 'PoisonDetector', 'Detector')
    if CPDetector:
        try:
            import threading as _t, time as _time
            cache_poison_detector = CPDetector(config=config)
            hb.set_cache_poison_detector(cache_poison_detector)
            def _run_cpd():
                while True:
                    try:
                        findings = cache_poison_detector.run_and_report(sender=sender)
                        if findings:
                            logger.warning(f'[CachePoison] {len(findings)} DNS anomalies detected')
                    except Exception as _e:
                        logger.warning(f'[CachePoison] {_e}')
                    _time.sleep(cache_poison_detector.scan_interval_seconds)
            _t.Thread(target=_run_cpd, daemon=True, name='cache-poison-detector').start()
            logger.info('DNS cache poison detector ready (T1557.003)')
        except Exception as e:
            logger.warning(f'DNS cache poison detector failed: {e}')

    # ── Memory Overflow Detector — SIGSEGV / heap spray / stack smash ────────
    if config.get('memory_overflow_enabled', True):
        MemOverflow = _import_class('core.memory_overflow', 'OverflowDetector', 'Detector')
        if MemOverflow:
            try:
                import threading as _t, time as _time
                _mo_inst = MemOverflow(config=config)
                def _run_overflow():
                    while True:
                        try:
                            findings = _mo_inst.run_and_report(sender=sender)
                            if findings:
                                logger.warning(f'[MemOverflow] {len(findings)} overflow events detected')
                        except Exception as _e:
                            logger.warning(f'[MemOverflow] {_e}')
                        _time.sleep(_mo_inst.collection_interval_seconds)
                _t.Thread(target=_run_overflow, daemon=True, name='memory-overflow').start()
                logger.info('Memory overflow detector started (T1203/T1190)')
            except Exception as e:
                logger.warning(f'Memory overflow detector failed: {e}')

    # ── DNS Sinkhole — always load its manager so the dashboard can enable it
    # at runtime even when the persisted policy currently has enabled=false.
    dns_sinkhole = None
    DNSSinkhole = _import_class('core.dns_sinkhole', 'Sinkhole')
    if DNSSinkhole:
        try:
            dns_sinkhole = DNSSinkhole(config=config)
            hb.set_dns_sinkhole(dns_sinkhole)
            sinkholed = dns_sinkhole.list_sinkholed() if hasattr(dns_sinkhole, 'list_sinkholed') else []
            state = 'enabled' if dns_sinkhole.enabled else 'disabled'
            logger.info(f'DNS sinkhole ready ({state}) — {len(sinkholed)} domains currently sinkholed (T1071.004)')
            import threading as _t, time as _time
            def _run_dns_sinkhole():
                while True:
                    try:
                        if dns_sinkhole.enabled and dns_sinkhole.telemetry_enabled:
                            dns_sinkhole.run_and_report(sender=sender)
                    except Exception as _e:
                        logger.warning(f'[DNSSinkhole] telemetry error: {_e}')
                    interval = max(60, min(3600, int(dns_sinkhole.report_interval_seconds)))
                    _time.sleep(interval)
            _t.Thread(target=_run_dns_sinkhole, daemon=True, name='dns-sinkhole-telemetry').start()
        except Exception as e:
            logger.warning(f'DNS sinkhole failed: {e}')

    # Command listener (receives block_ip / isolate / quarantine / open_port commands from dashboard)
    CmdListener = _import_class('core.command_listener', 'Listener')
    _start(CmdListener, 'Command listener', config=config, sender=sender, ips=ips, firewall=firewall,
           auto_response=auto_response if 'auto_response' in dir() else None,
           dns_sinkhole=dns_sinkhole, cache_poison_detector=cache_poison_detector)

    logger.info('SOC Agent running — Ctrl+C to stop')
    try:
        while True:
            time.sleep(60)
            # Check subscription stop flag every minute
            if hb.is_monitoring_stopped() if hasattr(hb, 'is_monitoring_stopped') else False:
                logger.warning('🔴 Subscription expired — agent entering passive mode (no monitoring)')
                # Stay alive but in passive mode — wake up when subscription renewed
                while True:
                    time.sleep(300)
                    # Re-check: heartbeat will clear the flag if reactivated
                    try:
                        from core.heartbeat import is_monitoring_stopped
                        if not is_monitoring_stopped():
                            logger.info('✅ Subscription reactivated. Restarting agent...')
                            import subprocess, sys, os
                            os.execv(sys.executable, [sys.executable] + sys.argv)
                    except Exception:
                        pass
    except KeyboardInterrupt:
        logger.info('SOC Agent stopped.')


# ── Connectivity test ─────────────────────────────────────────────────────────
def test_connection():
    """Run without root and return whether mandatory agent services work."""
    healthy = True
    storage_key = ''
    try:
        import requests
    except ImportError:
        print('\n❌  requests not installed.')
        print('    Fix: pip3 install -r requirements.txt\n')
        return False

    import socket
    from core.config import AgentConfig
    from core.secure_transport import secure_request
    config = AgentConfig()
    try:
        if _prepare_device_mtls(config):
            print('  ✅  Unique client certificate enrolled')
    except Exception as e:
        print(f'  ❌  mTLS enrollment failed: {e}')
        if config.get('mtls_required', False):
            return False

    server_url = config.get('server_url') or \
        'http://{}:{}'.format(
            config.get('server_ip', 'localhost'),
            config.get('server_port', 5000),
        )
    agent_key = config.get('agent_key', '')
    secret    = config.get('integration_secret', '')

    print('\n╔══ SOC Agent Connectivity Test ══╗')
    print(f'  Server   : {server_url}')
    print(f'  Company  : {config.get("company_name", "?")}')
    print(f'  System   : {config.get("system_name", "?")}')
    print(f'  AgentKey : {"set ✓" if agent_key else "MISSING ✗"}')
    print()

    if not agent_key:
        print('  ⚠️   No agent_key in config.')
        print('      Download your config from Dashboard → Systems → ↓ Download Agent\n')
        healthy = False

    # 1 — Server health
    try:
        r = secure_request(config, 'GET', f'{server_url}/health', timeout=5)
        if 200 <= r.status_code < 300:
            print(f'  ✅  Server reachable  (HTTP {r.status_code})')
        else:
            print(f'  ❌  Server health failed (HTTP {r.status_code})')
            healthy = False
    except requests.exceptions.ConnectionError:
        print(f'  ❌  Server not reachable at {server_url}')
        print(f'      Is the backend running?  cd backend && npm run dev\n')
        return False
    except Exception as e:
        print(f'  ❌  Server error: {e}\n')
        return False

    # 2 — Heartbeat
    try:
        payload = {'agentKey': agent_key, 'hostname': socket.gethostname()}
        r = secure_request(
            config,
            'POST',
            f'{server_url}/api/system/heartbeat',
            json=payload,
            headers=signed_headers(config, payload),
            timeout=5,
        )
        if r.status_code in (200, 201):
            print(f'  ✅  Heartbeat accepted')
        else:
            body = r.json() if r.headers.get('content-type','').startswith('application/json') else r.text
            msg  = body.get('message', body) if isinstance(body, dict) else body
            print(f'  ⚠️   Heartbeat {r.status_code}: {str(msg)[:100]}')
            healthy = False
    except Exception as e:
        print(f'  ❌  Heartbeat failed: {e}')
        healthy = False

    # 3 — Mandatory durable-spool encryption key
    try:
        from core.storage_key import fetch_storage_key
        storage_key = fetch_storage_key(config)
        print('  ✅  Secure storage key issued')
    except Exception as e:
        print(f'  ❌  Secure storage key failed: {e}')
        healthy = False

    # 4 — Test alert
    try:
        payload = {
            # Broker ingestion requires every alert to carry an idempotency key.
            # The connectivity probe is a real alert, so give it the same
            # durable identity as alerts sent through AlertSender.
            'event_id':      uuid.uuid4().hex,
            'agent_key':     agent_key,
            'company_id':    config.get('company_id'),
            'department_id': config.get('department_id'),
            'system_id':     config.get('system_id'),
            'rule_id':       'AGENT_TEST',
            'category':      'system',
            'severity':      'low',
            'description':   'SOC Agent connectivity test — safe to ignore',
            'raw_log':       'agent.py test',
        }
        r = secure_request(
            config,
            'POST',
            f'{server_url}/api/alerts',
            json=payload,
            headers=signed_headers(config, payload),
            timeout=5,
        )
        if 200 <= r.status_code < 300:
            print(f'  ✅  Test alert sent   → check dashboard!')
        else:
            body = r.json() if r.headers.get('content-type','').startswith('application/json') else r.text
            msg  = body.get('message', body) if isinstance(body, dict) else body
            print(f'  ⚠️   Alert {r.status_code}: {str(msg)[:150]}')
            healthy = False
    except Exception as e:
        print(f'  ❌  Alert send failed: {e}')
        healthy = False

    # 5 — VirusTotal (optional)
    vt_key = config.get('virustotal_api_key', '')
    if vt_key:
        try:
            VTScanner = _import_class('detectors.virustotal', 'Scanner')
            if VTScanner:
                vt = VTScanner(vt_key, encryption_key=storage_key)
                # EICAR hash — safe test file, always detected
                eicar = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
                result = vt.scan_hash(eicar)
                if result:
                    print(f'  ✅  VirusTotal active — EICAR: {result.get("detection_ratio")} ({result.get("verdict")})')
                else:
                    print(f'  ⚠️   VirusTotal returned no result (wrong key?)')
        except Exception as e:
            print(f'  ❌  VirusTotal: {e}')
    else:
        print(f'  ℹ️   VirusTotal not configured (no virustotal_api_key in config)')

    print()
    return healthy


# ── Service management ────────────────────────────────────────────────────────
def install_service():
    script = str(Path(__file__).resolve())
    python = sys.executable
    cwd    = str(AGENT_ROOT)

    if SYSTEM == 'Linux':
        unit = (
            '[Unit]\nDescription=SOC Security Agent\nAfter=network.target\n\n'
            '[Service]\nType=simple\nWorkingDirectory={cwd}\n'
            'ExecStart={py} {sc} run\nRestart=always\nRestartSec=10\n\n'
            '[Install]\nWantedBy=multi-user.target\n'
        ).format(cwd=cwd, py=python, sc=script)
        Path('/etc/systemd/system/soc-agent.service').write_text(unit)
        import subprocess
        subprocess.run(['systemctl', 'daemon-reload'])
        subprocess.run(['systemctl', 'enable', 'soc-agent'])
        subprocess.run(['systemctl', 'start',  'soc-agent'])
        print('✅  Service installed and started.')
        print('    Status:  systemctl status soc-agent')
        print('    Logs:    journalctl -u soc-agent -f')

    elif SYSTEM == 'Darwin':
        plist = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            '  <key>Label</key><string>com.soc.agent</string>\n'
            '  <key>ProgramArguments</key>\n'
            '  <array><string>{py}</string><string>{sc}</string><string>run</string></array>\n'
            '  <key>WorkingDirectory</key><string>{cwd}</string>\n'
            '  <key>RunAtLoad</key><true/>\n'
            '  <key>KeepAlive</key><true/>\n'
            '</dict></plist>'
        ).format(py=python, sc=script, cwd=cwd)
        pl = Path('/Library/LaunchDaemons/com.soc.agent.plist')
        pl.write_text(plist)
        import subprocess
        subprocess.run(['launchctl', 'bootout', 'system/com.soc.agent'], check=False)
        started = subprocess.run(['launchctl', 'bootstrap', 'system', str(pl)], check=False)
        if started.returncode != 0:
            subprocess.run(['launchctl', 'load', str(pl)], check=True)
        subprocess.run(['launchctl', 'enable', 'system/com.soc.agent'], check=False)
        subprocess.run(['launchctl', 'kickstart', '-k', 'system/com.soc.agent'], check=False)
        print('✅  Service installed and started.')

    elif SYSTEM == 'Windows':
        import subprocess
        wrapper = str(Path(cwd) / 'windows_service.py')
        subprocess.run([python, wrapper, '--startup', 'auto', 'install'], check=True)
        subprocess.run(['sc.exe', 'config', 'SOCAgent', 'start=', 'delayed-auto'], check=True)
        subprocess.run([
            'sc.exe', 'failure', 'SOCAgent', 'reset=', '86400',
            'actions=', 'restart/5000/restart/15000/restart/60000',
        ], check=True)
        subprocess.run(['sc.exe', 'start', 'SOCAgent'], check=True)
        print('✅  Installed native Windows service.')

    # ── Report install to server (registers installDate + increments installCount) ──
    _report_install()


def _report_install():
    """POST heartbeat immediately after install to register the agent with the server."""
    try:
        import socket
        from core.config import AgentConfig
        from core.secure_transport import secure_request
        config    = AgentConfig()
        _prepare_device_mtls(config)
        agent_key = config.get('agent_key', '')
        if not agent_key:
            return
        server_url = config.get('server_url') or \
            'http://{}:{}'.format(config.get('server_ip', 'localhost'),
                                  config.get('server_port', 5000))

        # Collect identity info
        hostname = socket.gethostname()
        os_type  = SYSTEM
        os_ver   = __import__('platform').version()[:80]
        arch     = __import__('platform').machine()

        # IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80)); ip = s.getsockname()[0]; s.close()
        except Exception:
            ip = socket.gethostbyname(hostname) if hostname else ''

        # Use the same stable primary-interface selection as recurring heartbeats.
        from core.heartbeat import _get_mac_address
        mac = _get_mac_address()

        payload = {
            'agentKey':    agent_key,
            'hostname':    hostname,
            'os':          os_type,
            'osVersion':   os_ver,
            'arch':        arch,
            'ip':          ip,
            'macAddress':  mac,
            'agentVersion': config.get('agent_version', '0.1.13'),
        }
        resp = secure_request(
            config,
            'POST',
            f'{server_url.rstrip("/")}/api/system/heartbeat',
            json=payload,
            headers=signed_headers(config, payload),
            timeout=10,
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            print(f'✅  Agent registered with server (systemId: {data.get("systemId","?")})')
        else:
            print(f'⚠️   Server registration: HTTP {resp.status_code}')
    except ImportError:
        pass   # requests not yet installed — install.sh will handle it
    except Exception as e:
        print(f'⚠️   Could not reach server during install: {e}')


def uninstall_service():
    import subprocess
    if SYSTEM == 'Linux':
        subprocess.run(['systemctl', 'stop',    'soc-agent'], check=False)
        subprocess.run(['systemctl', 'disable', 'soc-agent'], check=False)
        Path('/etc/systemd/system/soc-agent.service').unlink(missing_ok=True)
        subprocess.run(['systemctl', 'daemon-reload'])
        print('✅  Service removed.')
    elif SYSTEM == 'Darwin':
        pl = '/Library/LaunchDaemons/com.soc.agent.plist'
        stopped = subprocess.run(['launchctl', 'bootout', 'system/com.soc.agent'], check=False)
        if stopped.returncode != 0:
            subprocess.run(['launchctl', 'unload', pl], check=False)
        Path(pl).unlink(missing_ok=True)
        print('✅  Service removed.')
    elif SYSTEM == 'Windows':
        subprocess.run(['sc.exe', 'stop', 'SOCAgent'], check=False)
        subprocess.run(['sc.exe', 'delete', 'SOCAgent'], check=False)
        print('✅  Service removed.')


def service_ctrl(action):
    import subprocess
    if SYSTEM == 'Linux':
        subprocess.run(['systemctl', action, 'soc-agent'])
    elif SYSTEM == 'Darwin':
        pl = '/Library/LaunchDaemons/com.soc.agent.plist'
        if action == 'status':
            subprocess.run(['launchctl', 'print', 'system/com.soc.agent'])
        elif action == 'start':
            started = subprocess.run(['launchctl', 'bootstrap', 'system', pl], check=False)
            if started.returncode != 0:
                subprocess.run(['launchctl', 'kickstart', '-k', 'system/com.soc.agent'])
        else:
            stopped = subprocess.run(['launchctl', 'bootout', 'system/com.soc.agent'], check=False)
            if stopped.returncode != 0:
                subprocess.run(['launchctl', 'unload', pl], check=False)
    elif SYSTEM == 'Windows':
        command = 'query' if action == 'status' else action
        subprocess.run(['sc.exe', command, 'SOCAgent'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SOC Agent')
    parser.add_argument('command',
        choices=['run', 'test', 'install', 'uninstall', 'start', 'stop', 'status'])
    parser.add_argument('--config', help='Explicit company_config.json path')
    args = parser.parse_args()

    if args.config:
        os.environ['SOC_AGENT_CONFIG'] = str(Path(args.config).resolve())

    if args.command in {'run', 'install', 'uninstall', 'start', 'stop'}:
        _require_elevated(args.command)

    result = {
        'run':       build_and_run,
        'test':      test_connection,
        'install':   install_service,
        'uninstall': uninstall_service,
        'start':     lambda: service_ctrl('start'),
        'stop':      lambda: service_ctrl('stop'),
        'status':    lambda: service_ctrl('status'),
    }[args.command]()
    if args.command == 'test':
        raise SystemExit(0 if result else 1)
