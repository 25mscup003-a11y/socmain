const REGISTRY_TEXT_PATTERN = /(?:windows\s+registry|registry\s+(?:key|value|change|modified|monitor|persistence)|regedit|hklm|hkcu|hkcr|hku|hkey(?:_|\b)|runonce?\s+key)/i;
const CONFIG_PATH_PATTERN = /(?:^|\/)etc\/(?:passwd|shadow|group|gshadow|sudoers(?:\.d)?(?:\/|$)|ssh(?:\/|$)|cron(?:\.d|\.daily|\.hourly|\.weekly|\.monthly)?(?:\/|$)|systemd(?:\/|$)|security(?:\/|$)|pam\.d(?:\/|$)|fstab$|hosts$|resolv\.conf$|sysctl(?:\.conf|\.d(?:\/|$))|audit(?:\/|$))/i;

function registryMonitoringFilter() {
  return {
    $or: [
      { eventCategory: 'registry' },
      { source: 'registry_monitor' },
      { registryKey: REGISTRY_TEXT_PATTERN },
      { keyPath: REGISTRY_TEXT_PATTERN },
      { ruleId: REGISTRY_TEXT_PATTERN },
      { type: REGISTRY_TEXT_PATTERN },
      { description: REGISTRY_TEXT_PATTERN },
      { 'rawEvent.message': REGISTRY_TEXT_PATTERN },
      { 'rawEvent.key': REGISTRY_TEXT_PATTERN },
      { registryKey: CONFIG_PATH_PATTERN },
      { keyPath: CONFIG_PATH_PATTERN },
      { filePath: CONFIG_PATH_PATTERN },
      { sourcePath: CONFIG_PATH_PATTERN },
      { 'rawEvent.file_path': CONFIG_PATH_PATTERN },
      { 'rawEvent.filePath': CONFIG_PATH_PATTERN },
    ],
  };
}

module.exports = { registryMonitoringFilter };
