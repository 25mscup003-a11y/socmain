"""Native Windows Service host for the AJNAT/SOC Python agent.

Used by Windows installers when NSSM is unavailable. Requires pywin32, which
the installer provisions before registering this service.
"""

import os
import subprocess
import sys
from pathlib import Path

import servicemanager
import win32event
import win32service
import win32serviceutil


class SocAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SOCAgent"
    _svc_display_name_ = "SOC Security Agent"
    _svc_description_ = "AJNAT endpoint security monitoring and response agent"

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.process = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        if self.process and self.process.poll() is None:
            self.process.terminate()

    def SvcShutdown(self):
        self.SvcStop()

    def SvcDoRun(self):
        module_root = Path(__file__).resolve().parent
        executable = Path(sys.executable).resolve()
        # pythonservice.exe imports a copy of this module from site-packages.
        # Walk upwards from the private runtime instead of assuming one exact
        # venv/standalone layout, and select the first directory containing the
        # packaged agent entry point.
        root_candidates = [module_root, *module_root.parents, *executable.parents]
        root = next((item for item in root_candidates if (item / "agent.py").is_file()), module_root)
        agent = root / "agent.py"
        data_root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AJNAT"
        log_dir = data_root / "logs"
        config_path = data_root / "config" / "company_config.json"
        legacy_config = root / "config" / "company_config.json"
        if not config_path.is_file() and legacy_config.is_file():
            config_path = legacy_config
        log_dir.mkdir(parents=True, exist_ok=True)
        if not agent.is_file():
            raise FileNotFoundError(f"Agent entry point is missing: {agent}")
        if not config_path.is_file():
            raise FileNotFoundError(f"Agent configuration is missing: {config_path}")
        child_env = os.environ.copy()
        child_env["AJNAT_DATA_DIR"] = str(data_root)
        child_env["SOC_AGENT_CONFIG"] = str(config_path)
        child_env["PYTHONUTF8"] = "1"
        child_env["PYTHONIOENCODING"] = "utf-8"
        # Under the SCM host, sys.executable can be pythonservice.exe. Launching
        # agent.py with that binary starts another service host instead of the
        # normal Python interpreter.
        python_candidates = (
            Path(sys.exec_prefix) / "python.exe",
            Path(sys.exec_prefix) / "Scripts" / "python.exe",
            root / "runtime" / "python" / "python.exe",
            root / "runtime" / "python" / "Scripts" / "python.exe",
            Path(sys.executable),
        )
        python_executable = next((item for item in python_candidates if item.is_file()), None)
        if python_executable is None:
            raise FileNotFoundError("AJNAT Python runtime is missing")
        servicemanager.LogInfoMsg("SOCAgent service starting")
        self.process = subprocess.Popen(
            [str(python_executable), str(agent), "run"],
            cwd=str(root),
            env=child_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        while self.process.poll() is None:
            if win32event.WaitForSingleObject(self.stop_event, 1000) == win32event.WAIT_OBJECT_0:
                break
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
        servicemanager.LogInfoMsg("SOCAgent service stopped")


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parent)
    win32serviceutil.HandleCommandLine(SocAgentService)
