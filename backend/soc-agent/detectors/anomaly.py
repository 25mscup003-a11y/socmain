"""
Anomaly detector — baselines CPU/memory/connections and alerts on 3x spikes.
"""
import time, logging, threading, statistics
from datetime import datetime, timezone
from collections import deque

try:
    import psutil
except ImportError:  # Optional on constrained agent builds.
    psutil = None

logger = logging.getLogger('soc-agent.detector.anomaly')
POLL_INTERVAL = 60
BASELINE_SAMPLES = 20

class AnomalyDetector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._cpu = deque(maxlen=BASELINE_SAMPLES)
        self._mem = deque(maxlen=BASELINE_SAMPLES)
        self._conns = deque(maxlen=BASELINE_SAMPLES)
        self._thread = threading.Thread(target=self._loop, daemon=True, name='anomaly')

    def start(self):
        self._thread.start()

    def _loop(self):
        logger.info('Anomaly detector started')
        while True:
            try:
                self._check()
            except Exception as e:
                logger.debug(f'Anomaly check: {e}')
            interval = max(15, min(3600, int(self._config.get('ueba_monitor_interval_seconds', POLL_INTERVAL))))
            time.sleep(interval)

    def _check(self):
        if self._config.get('ueba_monitoring_enabled', True) is False:
            return
        if psutil is None:
            return
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent
            conns = len(psutil.net_connections())
            for metric, history, value, name in [
                (cpu, self._cpu, cpu, 'CPU'),
                (mem, self._mem, mem, 'Memory'),
                (conns, self._conns, conns, 'Network connections'),
            ]:
                if len(history) >= 10:
                    avg = statistics.mean(history)
                    multiplier = max(1.5, min(10.0, float(self._config.get('ueba_anomaly_multiplier', 3.0))))
                    if avg > 0 and value > avg * multiplier:
                        deviation = value / avg
                        risk_score = min(100, round(60 + min(40, (deviation - multiplier) * 12)))
                        self._sender.enqueue({
                            'rule_id': f'ANOMALY_{name.upper().replace(" ", "_")}',
                            'capabilityId': 11,
                            'capabilityIds': [11],
                            'category': 'system',
                            'subCategory': 'ueba',
                            'source': 'anomaly',
                            'event_type': 'behavioral_anomaly',
                            'behavior_category': 'Endpoint Behavior' if name != 'Network connections' else 'Network Behavior',
                            'entity_type': 'endpoint',
                            'entity_id': self._config.get('system_name') or self._config.get('hostname'),
                            'risk_score': risk_score,
                            'behavior_score': risk_score,
                            'baseline_score': min(100, round(avg, 2)),
                            'peer_deviation_score': min(100, round(deviation * 20)),
                            'ueba_confidence': min(100, 50 + len(history) * 2),
                            'ueba_risk_factors': [f'{name.lower().replace(" ", "_")}_baseline_deviation'],
                            'baseline_window_days': 30,
                            'severity': 'high',
                            'description': f'{name} anomaly: {value:.1f} (baseline {avg:.1f}, {deviation:.1f}x deviation)',
                            'raw_log': f'ANOMALY:{name}:{value:.1f}:baseline:{avg:.1f}',
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                        })
                history.append(value)
        except (OSError, RuntimeError) as exc:
            logger.debug('UEBA system metric collection failed: %s', exc)
