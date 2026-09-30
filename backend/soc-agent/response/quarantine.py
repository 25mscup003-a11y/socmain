"""Move files to quarantine."""
import os, shutil, hashlib, platform, logging
from pathlib import Path
logger = logging.getLogger('soc-agent.response.quarantine')

QUARANTINE_DIR = {
    'Linux': Path('/var/quarantine/soc-agent'),
    'Darwin': Path('/Library/SOCAgent/quarantine'),
    'Windows': Path('C:/ProgramData/SOCAgent/quarantine'),
}.get(platform.system(), Path('/tmp/soc-quarantine'))

PROTECTED_PATHS = [
    Path('/home/chaudahry/Desktop/soc4'),
    Path(__file__).resolve().parents[3],
]

def _is_protected_path(path: Path) -> bool:
    try:
      resolved = path.resolve()
      extra = os.getenv('SOC_AGENT_QUARANTINE_EXCLUDE', '')
      protected = PROTECTED_PATHS + [Path(p).expanduser() for p in extra.split(os.pathsep) if p.strip()]
      return any(resolved == base.resolve() or base.resolve() in resolved.parents for base in protected)
    except Exception:
      return False

def quarantine(file_path: str) -> str:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(file_path)
    if _is_protected_path(src):
        msg = f'quarantine skipped for protected development path: {src}'
        logger.warning(msg)
        return msg
    sha256 = hashlib.sha256(src.read_bytes()).hexdigest()
    dest = QUARANTINE_DIR / f'{sha256}_{src.name}'
    shutil.move(str(src), str(dest))
    logger.warning(f'Quarantined: {file_path} -> {dest}')
    return str(dest)
