import pathlib
import sys
import unittest

AGENT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from collectors.process_assets import container_risks, kubernetes_pod_risks, workload_role
from collectors.windows_process_events import classify_windows_event, parse_event_xml


def sysmon_xml(event_id, record_id, **data):
    values = ''.join(f'<Data Name="{key}">{value}</Data>' for key, value in data.items())
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>{event_id}</EventID>
      <EventRecordID>{record_id}</EventRecordID><TimeCreated SystemTime="2026-08-29T10:00:00Z"/>
      <Computer>win-test</Computer></System><EventData>{values}</EventData></Event>'''


class WindowsProcessEventTests(unittest.TestCase):
    def test_sysmon_network_connect_is_exactly_attributed(self):
        event = parse_event_xml(sysmon_xml(
            3, 53, Image=r'C:\Program Files\AJNAT\agent.exe', ProcessId='321',
            DestinationIp='203.0.113.10', DestinationPort='443', Protocol='tcp',
            SourceIp='10.0.0.25', SourcePort='51000',
        ))
        finding = classify_windows_event('Microsoft-Windows-Sysmon/Operational', event)[0]
        self.assertEqual(finding['rule_id'], 'PROC_NETWORK_CONNECTION')
        self.assertEqual(finding['pid'], 321)
        self.assertEqual(finding['dest_ip'], '203.0.113.10')
        self.assertEqual(finding['dst_port'], 443)
        self.assertEqual(finding['attribution_confidence'], 'exact')
        self.assertEqual(finding['evidence_type'], 'sysmon_network_connect')

    def test_sysmon_process_termination_is_kernel_backed(self):
        event = parse_event_xml(sysmon_xml(
            5, 54, Image=r'C:\Windows\System32\cmd.exe', ProcessId='654',
        ))
        finding = classify_windows_event('Microsoft-Windows-Sysmon/Operational', event)[0]
        self.assertEqual(finding['rule_id'], 'PROC_KERNEL_TERMINATED')
        self.assertEqual(finding['pid'], 654)
        self.assertEqual(finding['eventType'], 'Process Terminate')
        self.assertEqual(finding['evidence_type'], 'sysmon_process_terminate')

    def test_sysmon_remote_thread_maps_to_dll_injection(self):
        event = parse_event_xml(sysmon_xml(
            8, 55, SourceImage=r'C:\Temp\injector.exe', SourceProcessId='100',
            TargetImage=r'C:\Windows\System32\notepad.exe', TargetProcessId='200',
            StartModule=r'C:\Temp\payload.dll',
        ))
        findings = classify_windows_event('Microsoft-Windows-Sysmon/Operational', event)
        self.assertEqual(findings[0]['rule_id'], 'PROC_DLL_INJECTION')
        self.assertEqual(findings[0]['target_pid'], 200)
        self.assertEqual(findings[0]['evidence_type'], 'sysmon_create_remote_thread')

    def test_sysmon_process_tampering_maps_to_hollowing(self):
        event = parse_event_xml(sysmon_xml(25, 56, Image=r'C:\Temp\victim.exe', ProcessId='300', Type='Image is replaced'))
        finding = classify_windows_event('Microsoft-Windows-Sysmon/Operational', event)[0]
        self.assertEqual(finding['rule_id'], 'PROC_HOLLOWING')
        self.assertEqual(finding['mitre_id'], 'T1055.012')

    def test_sysmon_dns_is_exactly_attributed(self):
        event = parse_event_xml(sysmon_xml(22, 57, Image=r'C:\Browser\browser.exe', ProcessId='400', QueryName='example.test'))
        finding = classify_windows_event('Microsoft-Windows-Sysmon/Operational', event)[0]
        self.assertEqual(finding['rule_id'], 'PROC_DNS_QUERY')
        self.assertEqual(finding['domain'], 'example.test')
        self.assertEqual(finding['attribution_confidence'], 'exact')

    def test_native_task_event_is_preserved(self):
        event = parse_event_xml(sysmon_xml(4698, 58, TaskName=r'\AJNAT\Daily'))
        finding = classify_windows_event('Security', event)[0]
        self.assertEqual(finding['inventory_type'], 'scheduled_task')
        self.assertEqual(finding['change_type'], 'created')


class CrossPlatformInventoryTests(unittest.TestCase):
    def test_workloads_have_dedicated_roles(self):
        self.assertEqual(workload_role('nginx', 'nginx: worker'), 'nginx')
        self.assertEqual(workload_role('java', 'org.apache.catalina.startup.Bootstrap'), 'tomcat')
        self.assertEqual(workload_role('postgres.exe', ''), 'postgresql')

    def test_container_risks_are_evidence_based(self):
        risks = container_risks({
            'Config': {'User': '0'},
            'HostConfig': {'Privileged': True, 'NetworkMode': 'host', 'PidMode': 'host',
                           'CapAdd': ['SYS_ADMIN'], 'Binds': ['/var/run/docker.sock:/sock']},
        })
        for risk in ['privileged', 'host_network', 'host_pid', 'cap_sys_admin', 'sensitive_host_mount', 'runs_as_root']:
            self.assertIn(risk, risks)

    def test_kubernetes_privilege_risks(self):
        risks = kubernetes_pod_risks({'spec': {
            'hostPID': True,
            'volumes': [{'hostPath': {'path': '/'}}],
            'containers': [{'securityContext': {'privileged': True, 'allowPrivilegeEscalation': True}}],
        }})
        self.assertEqual(risks, ['host_path_mount', 'host_pid', 'privilege_escalation_allowed', 'privileged'])


if __name__ == '__main__':
    unittest.main()
