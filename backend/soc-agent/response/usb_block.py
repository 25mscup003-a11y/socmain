"""Block/unblock USB storage."""
import subprocess, platform, logging
logger = logging.getLogger('soc-agent.response.usb_block')
SYSTEM = platform.system()

def block():
    if SYSTEM == 'Linux':
        return subprocess.run(['modprobe', '-r', 'usb_storage'], check=False).returncode == 0
    elif SYSTEM == 'Windows':
        return subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR', '/v', 'Start', '/t', 'REG_DWORD', '/d', '4', '/f'], check=False).returncode == 0
    return False

def unblock():
    if SYSTEM == 'Linux':
        return subprocess.run(['modprobe', 'usb_storage'], check=False).returncode == 0
    elif SYSTEM == 'Windows':
        return subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR', '/v', 'Start', '/t', 'REG_DWORD', '/d', '3', '/f'], check=False).returncode == 0
    return False
