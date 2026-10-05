const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const tls = require('node:tls');
const os = require('node:os');
const {
  linuxPreInstallScript,
  getAgentIntegrityManifest,
  windowsPasswordVerifySnippet,
  prepareWindowsTlsPackage,
  prepareAndroidTlsPackage,
  loadWindowsPublisherCertificate,
  buildUniversal,
} = require('../src/services/packageBuilder.service');

test('Windows downloads embed and configure the AJNAT server CA bundle', () => {
  const caPem = tls.rootCertificates.find(pem => new crypto.X509Certificate(pem).ca);
  assert.ok(caPem, 'Node must provide at least one trusted CA test fixture');
  const prepared = prepareWindowsTlsPackage(
    { server_url: 'https://soc.example.test', require_tls: false },
    { AGENT_SERVER_CA_BUNDLE_PEM: caPem, AGENT_SERVER_CERT_SHA256: 'ab:'.repeat(31) + 'ab' },
  );
  assert.equal(prepared.config.require_tls, true);
  assert.equal(prepared.config.tls_ca_bundle, String.raw`C:\ProgramData\AJNAT\certs\server-ca-bundle.pem`);
  assert.equal(prepared.config.tls_server_sha256, 'ab'.repeat(32));
  assert.match(prepared.caBundle.content.toString('utf8'), /BEGIN CERTIFICATE/);
  assert.match(prepared.caBundle.sha256, /^[a-f0-9]{64}$/);

  assert.throws(
    () => prepareWindowsTlsPackage(
      { server_url: 'http://soc.example.test' },
      { AGENT_SERVER_CA_BUNDLE_PEM: caPem },
    ),
    /requires an HTTPS server_url/,
  );
});

test('local-test Windows downloads carry only the public publisher certificate', () => {
  // This loader reads public X.509 metadata; it does not sign an installer.
  // Avoid depending on a developer's private signing setup or missing .cer file.
  const publicPem = tls.rootCertificates.find(pem => {
    const certificate = new crypto.X509Certificate(pem);
    return certificate.subject === certificate.issuer;
  });
  assert.ok(publicPem);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ajnat-public-cert-test-'));
  try {
    const certificatePath = path.join(directory, 'publisher.cer');
    fs.writeFileSync(certificatePath, new crypto.X509Certificate(publicPem).raw);
    const publisher = loadWindowsPublisherCertificate({
      WINDOWS_CODE_SIGN_MODE: 'local-test',
      WINDOWS_CODE_SIGN_PUBLIC_CERT: certificatePath,
    });
    assert.match(publisher.thumbprint, /^[A-F0-9]{40}$/);
    assert.match(publisher.sha256, /^[a-f0-9]{64}$/);
    assert.doesNotMatch(publisher.content.toString('utf8'), /PRIVATE KEY/);
    assert.equal(loadWindowsPublisherCertificate({ WINDOWS_CODE_SIGN_MODE: 'production' }), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Android downloads embed an app-private AJNAT server CA asset configuration', () => {
  const caPem = tls.rootCertificates.find(pem => new crypto.X509Certificate(pem).ca);
  const prepared = prepareAndroidTlsPackage(
    { server_url: 'https://soc.example.test', require_tls: false, integration_secret: 'must-not-ship' },
    { AGENT_SERVER_CA_BUNDLE_PEM: caPem },
  );
  assert.equal(prepared.config.require_tls, true);
  assert.equal(prepared.config.integration_secret, undefined);
  assert.equal(prepared.config.tls_ca_bundle_asset, 'server-ca-bundle.pem');
  assert.equal(prepared.config.tls_ca_bundle, undefined);
  assert.match(prepared.caBundle.content.toString('utf8'), /BEGIN CERTIFICATE/);
  const localTest = prepareAndroidTlsPackage(
    { server_url: 'http://localhost:3000', integration_secret: 'must-not-ship' },
    {},
  );
  assert.equal(localTest.config.require_tls, false);
  assert.equal(localTest.config.allow_cleartext_test, true);
  assert.equal(localTest.config.integration_secret, undefined);
  const lanTest = prepareAndroidTlsPackage({ server_url: 'http://10.126.148.104:5000' }, {});
  assert.equal(lanTest.config.require_tls, false);
  assert.equal(lanTest.config.allow_cleartext_test, true);
  assert.throws(() => prepareAndroidTlsPackage(
    { server_url: 'http://10.126.148.104:5000' },
    { NODE_ENV: 'production' },
  ), /require an HTTPS server_url/);
  assert.throws(() => prepareAndroidTlsPackage({ server_url: 'http://soc.example.test' }, {}),
    /require an HTTPS server_url/);
});

test('agent packages include a non-empty SHA-256 integrity inventory', () => {
  const manifest = getAgentIntegrityManifest();
  assert.equal(manifest.algorithm, 'sha256');
  assert.match(manifest.fleetSha256, /^[a-f0-9]{64}$/);
  assert.ok(Object.keys(manifest.files).length > 20);
  assert.match(manifest.files['core/heartbeat.py'], /^[a-f0-9]{64}$/);
  assert.match(manifest.files['core/self_protection.py'], /^[a-f0-9]{64}$/);
  assert.match(manifest.files['core/file_open_protection.py'], /^[a-f0-9]{64}$/);
  assert.match(manifest.files['core/gps_location.py'], /^[a-f0-9]{64}$/);
  assert.match(manifest.files['core/time_anomaly.py'], /^[a-f0-9]{64}$/);
  assert.match(manifest.files['collectors/kernel_monitor.py'], /^[a-f0-9]{64}$/);
  assert.match(manifest.files['collectors/input_behavior.py'], /^[a-f0-9]{64}$/);
  const builder = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  assert.match(builder, /SKIP_DIRS[^\n]+['"]venv['"][^\n]+['"]\.venv['"]/);
  assert.match(routes, /SKIP_DIRS[^\n]+['"]venv['"][^\n]+['"]\.venv['"]/);
  assert.match(routes, /X-AJNAT-Build-Mode', 'just-in-time'/);
  assert.match(routes, /Cache-Control', 'no-store, no-cache, must-revalidate, private'/);
});

test('desktop agent release version is aligned across package and update paths', () => {
  const expected = '0.1.13';
  const files = [
    'src/routes/agent.routes.js',
    'src/routes/superadmin.routes.js',
    'src/services/prebuild.service.js',
    'src/server.js',
  ];
  for (const relative of files) {
    const source = fs.readFileSync(path.join(__dirname, '..', relative), 'utf8');
    assert.ok(source.split('\n').some(line => line.includes('AGENT_VERSION') && line.includes(expected)), relative);
  }
});

test('UEBA input activity uses a live one-minute reporting cadence', () => {
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  const collector = fs.readFileSync(path.join(__dirname, '../soc-agent/collectors/input_behavior.py'), 'utf8');
  assert.match(routes, /input_behavior_report_interval_seconds: Math\.min\(3600, Math\.max\(60,[^\n]+\|\| 60\)\)/);
  assert.match(collector, /while True:[\s\S]+report_interval = 60[\s\S]+if now - report_started >= report_interval/);
});

test('bundled AJNAT desktop agent defaults report the current release', () => {
  const expected = '0.1.13';
  for (const relative of [
    'soc-agent/core/config.py',
    'soc-agent/agent.py',
    'soc-agent/core/heartbeat.py',
    'soc-agent/README.txt',
    'soc-agent/INSTALL.txt',
  ]) {
    const source = fs.readFileSync(path.join(__dirname, '..', relative), 'utf8');
    assert.ok(source.includes(expected), relative);
  }
});

test('fresh and update packages fail closed and include the complete 0.1.13 runtime', () => {
  const AdmZip = require('adm-zip');
  const builder = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  assert.match(builder, /const DEFAULT_AGENT_VERSION = '0\.1\.13'/);
  assert.match(builder, /function requireAgentDir\(\)/);
  assert.match(builder, /refusing to build an empty installer/);
  assert.match(builder, /SOC Agent source is incomplete/);
  assert.match(builder, /VENV_DIR="\$INSTALL_DIR\/\.venv"/);
  assert.match(builder, /All required Python dependencies installed and verified/);
  assert.match(builder, /service did not remain active after installation/);

  const payload = buildUniversal(
    { name: 'release-smoke', agentType: 'system' },
    { name: 'AJNAT', _id: 'release-smoke' },
    {
      agent_version: '0.1.13',
      agent_key: 'release-smoke',
      system_id: 'release-smoke',
      expected_device_role: 'system',
      server_url: 'https://soc.example.test',
    },
  );
  const archive = new AdmZip(payload);
  const entries = archive.getEntries().map(entry => entry.entryName);
  for (const relative of [
    'agent.py', 'requirements.txt', 'integrity_manifest.json',
    'core/heartbeat.py', 'core/secure_transport.py', 'core/config_protection.py',
    'core/file_open_protection.py', 'core/security_controls.py',
    'core/device_identity.py', 'collectors/processes.py',
    'install.sh', 'install.ps1',
  ]) {
    assert.ok(entries.some(entry => entry.endsWith(`/${relative}`)), relative);
  }
  const configEntry = archive.getEntries().find(entry => entry.entryName.endsWith('/config/company_config.json'));
  assert.equal(JSON.parse(configEntry.getData().toString('utf8')).agent_version, '0.1.13');
});

test('Debian preinst lets legacy in-service OTA survive the old prerm stop', () => {
  const script = linuxPreInstallScript();
  assert.match(script, /ACTION=/);
  assert.match(script, /\[ "\$ACTION" = "upgrade" \]/);
  assert.match(script, /set-property --runtime soc-agent\.service KillMode=process/);
  assert.match(script, /postinst restores control-group mode/);
});

test('Linux packages require Suricata NFQUEUE inline IPS setup', () => {
  const builder = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  const sensorInstaller = fs.readFileSync(path.join(__dirname, '../soc-agent/install-ids-sensors.sh'), 'utf8');
  const processTelemetryInstaller = fs.readFileSync(path.join(__dirname, '../soc-agent/install-linux-advanced-telemetry.sh'), 'utf8');
  assert.match(builder, /SOC_SURICATA_MODE=ips bash "\$IDS_INSTALLER"/);
  assert.doesNotMatch(builder, /Sensor setup did not complete; agent installation will continue/);
  assert.match(sensorInstaller, /SOC_SURICATA_MODE:-ips/);
  assert.match(sensorInstaller, /systemctl show suricata -p ExecStart/);
  assert.match(sensorInstaller, /nft list table inet soc_suricata_ips/);
  assert.match(sensorInstaller, /soc-suricata-nfqueue\.service/);
  assert.match(sensorInstaller, /Before=suricata\.service/);
  assert.match(sensorInstaller, /suricata-nfqueue-inline/);
  assert.match(builder, /install-linux-advanced-telemetry\.sh/);
  assert.match(processTelemetryInstaller, /process_vm_writev/);
  assert.match(processTelemetryInstaller, /ajnat_process_injection/);
});

test('Linux installers provision the policy-gated native location stack', () => {
  const builder = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  const installer = fs.readFileSync(path.join(__dirname, '../soc-agent/install-linux-location-provider.sh'), 'utf8');
  assert.match(builder, /install-linux-location-provider\.sh/);
  assert.match(installer, /geoclue-2\.0 geoclue-2-demo/);
  assert.match(installer, /modemmanager gpsd gpsd-clients/);
  assert.match(installer, /org\.gnome\.system\.location enabled true/);
  assert.match(installer, /coordinates are sent only when GPS policy is enabled/);
  assert.doesNotMatch(installer, /gps_tracking_enabled[^\n]*true/);
});

test('Windows and macOS installers provision native OS location providers', () => {
  const builder = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  const requirements = fs.readFileSync(path.join(__dirname, '../soc-agent/requirements.txt'), 'utf8');
  assert.match(builder, /Get-Service -Name 'lfsvc'/);
  assert.match(builder, /ConsentStore\\\\location/);
  assert.match(builder, /disabled by Group Policy[\s\S]+will not bypass the policy/);
  assert.match(builder, /import CoreLocation, objc/);
  assert.match(requirements, /pyobjc-framework-CoreLocation[^\n]+sys_platform == 'darwin'/);
});

test('Android agent requests precise GPS permission and applies heartbeat policy', () => {
  const manifest = fs.readFileSync(path.join(__dirname, '../android-agent/app/src/main/AndroidManifest.xml'), 'utf8');
  const collector = fs.readFileSync(path.join(__dirname, '../android-agent/app/src/main/java/com/soc/agent/GpsLocationCollector.java'), 'utf8');
  const service = fs.readFileSync(path.join(__dirname, '../android-agent/app/src/main/java/com/soc/agent/AgentService.java'), 'utf8');
  assert.match(manifest, /android\.permission\.ACCESS_FINE_LOCATION/);
  assert.match(manifest, /android\.permission\.ACCESS_BACKGROUND_LOCATION/);
  assert.match(collector, /gps_tracking_enabled/);
  assert.match(collector, /gps_required_accuracy_meters", 50\.0/);
  assert.match(collector, /GPS_LOCATION_TELEMETRY/);
  assert.match(service, /applyHeartbeatPolicy\(json\)/);
});

test('Windows packages use a real service wrapper and safe native-firewall fallback', () => {
  const builder = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  const wrapper = fs.readFileSync(path.join(__dirname, '../soc-agent/windows_service.py'), 'utf8');
  const agent = fs.readFileSync(path.join(__dirname, '../soc-agent/agent.py'), 'utf8');
  const windowsIds = fs.readFileSync(path.join(__dirname, '../soc-agent/install-windows-ids.ps1'), 'utf8');
  const windowsProcessTelemetry = fs.readFileSync(path.join(__dirname, '../soc-agent/install-windows-advanced-telemetry.ps1'), 'utf8');

  assert.doesNotMatch(builder, /sc\.exe create \$ServiceName/);
  assert.match(builder, /windows_service\.py/);
  assert.match(builder, /Get-Service \$ServiceName -ErrorAction Stop/);
  assert.match(builder, /ExecWait 'powershell\.exe -NoProfile -STA[^\n]+install\.ps1/);
  assert.match(builder, /RequestExecutionLevel admin/);
  assert.match(builder, /IfSilent silent_agent_update interactive_install/);
  assert.match(builder, /GetTempFileName \$3 "\$TEMP"[\s\S]+AJNAT-agent-stage/);
  assert.doesNotMatch(builder, /GetTempFileName \$3 "\$COMMONAPPDATA/);
  assert.match(builder, /stage_path_failure/);
  assert.match(builder, /IfSilent silent_prepare_stage interactive_prepare_stage/);
  assert.match(builder, /options\.isAgentUpdate \? '' : `Function \.onInit/);
  assert.match(builder, /silent_prepare_stage:[\s\S]+CreateDirectory "\$3"[\s\S]+Goto stage_payload/);
  assert.match(builder, /IfSilent silent_preflight_failure interactive_preflight_failure/);
  assert.match(builder, /silent_preflight_failure:[\s\S]+SetErrorLevel \$0[\s\S]+Abort/);
  assert.match(builder, /silent_agent_update:[\s\S]+Exec 'powershell\.exe[^\n]+install-update\.ps1[^\n]+'/);
  assert.match(builder, /silent_agent_update:[\s\S]+Exec 'powershell\.exe[^\n]+install-update\.ps1[^\n]+'[\s\S]+Quit/);
  const silentInstallerBranch = builder.slice(
    builder.indexOf('silent_agent_update:'),
    builder.indexOf('interactive_install:', builder.indexOf('silent_agent_update:'))
  );
  assert.doesNotMatch(silentInstallerBranch, /^\s*ExecWait/m);
  assert.match(builder, /\$4 != "detached"[\s\S]+RMDir \/r "\$3"/);
  assert.match(builder, /if \(\$IsUpdate\) \{ \$sensorArguments \+= '-SkipRuleUpdate' \}/);
  assert.match(windowsIds, /\[switch\]\$SkipRuleUpdate/);
  assert.match(windowsIds, /WaitForExit\(60000\)/);
  assert.match(windowsProcessTelemetry, /download\.sysinternals\.com\/files\/Sysmon\.zip/);
  assert.match(windowsProcessTelemetry, /Get-AuthenticodeSignature/);
  assert.match(windowsProcessTelemetry, /SignerCertificate\.Subject -match 'Microsoft'/);
  assert.match(windowsProcessTelemetry, /sysmonConfigApplied/);
  assert.match(builder, /sourcePath\.Equals\(\$targetPath/);
  assert.match(builder, /Supported Python not found; downloading Python 3\.12/);
  assert.match(builder, /python-3\.12\.10-amd64\.exe/);
  assert.match(builder, /python-3\.12\.10-arm64\.exe/);
  assert.match(builder, /Join-Path \$InstallDir 'runtime\\\\python'/);
  assert.match(builder, /TargetDir="\{0\}"[^\n]+-f \$privatePythonRuntimeDir/);
  assert.doesNotMatch(builder, /Creating AJNAT runtime from existing Python/);
  assert.doesNotMatch(builder, /AJNAT private Python runtime creation/);
  assert.match(builder, /-replace '\^\\\\s\*-V:\[\^\\\\s\]\+\\\\s\*'/);
  assert.equal(
    (builder.match(/\$pythonCandidates = @\([\s\S]{0,500}Join-Path \$privatePythonRuntimeDir 'python\.exe'[\s\S]{0,500}\$env:ProgramFiles\\\\Python312\\\\python\.exe/g) || []).length,
    2,
    'EXE and MSI must prefer a full Python install and never create a service-host venv',
  );
  assert.match(builder, /Could not resolve the selected Python runtime directory/);
  assert.match(builder, /Join-Path \$InstallDir 'packages'/);
  assert.match(builder, /process\.platform === 'win32'/);
  assert.match(builder, /where\.exe/);
  assert.match(builder, /WiX Toolset v3/);
  assert.match(builder, /function signWindowsArtifact\(filePath\)/);
  assert.match(builder, /WINDOWS_CODE_SIGN_REQUIRED/);
  assert.match(builder, /localTestSigning/);
  assert.match(builder, /Production[\s\S]*signing remains fail-closed/);
  assert.match(builder, /const offlineArgs = args\.filter/);
  assert.equal((builder.match(/signWindowsArtifact\(outFile\);/g) || []).length, 2);
  assert.match(builder, /path\.win32\.normalize/);
  assert.match(builder, /\$RoleConfigPath/);
  assert.doesNotMatch(builder, /\$ConfigPath = Join-Path \$InstallDir/);
  assert.match(builder, /Start-BitsTransfer/);
  assert.match(builder, /Start-Transcript -Path \$InstallLog/);
  assert.match(builder, /powershell\.exe[^\n]+-NoExit/);
  assert.match(builder, /soc-agent-install-bootstrap\.log/);
  assert.doesNotMatch(builder, /nsExec::ExecToStack[^\n]+install\.ps1/);
  assert.ok(builder.includes('FileOpen $2 "$TEMP\\\\soc-agent-install-bootstrap.log"'));
  assert.doesNotMatch(builder, /run-install\.(?:cmd|ps1)/);
  assert.match(builder, /Join-Path \$env:TEMP "soc-agent-install-bootstrap\.log"/);
  assert.doesNotMatch(builder, /-LogPath "\$COMMONAPPDATA/);
  assert.doesNotMatch(builder, /\$PROGRAMDATA\\SOCAgent\\install\.log/);
  assert.doesNotMatch(builder, /-ExitCode \$0/);
  const exeBuilder = builder.slice(builder.indexOf('function buildExe('), builder.indexOf('function buildMsi('));
  assert.match(exeBuilder, /Keeping the existing Velociraptor and packet-sensor installation during agent update/);
  assert.match(exeBuilder, /if \(-not \$IsUpdate\) \{[\s\S]+windowsNetworkSensorInstallSnippet/);
  assert.match(exeBuilder, /Existing dependencies retained/);
  assert.match(exeBuilder, /\$requiredImportsReady/);
  assert.match(exeBuilder, /All required Python packages installed and verified/);
  assert.match(exeBuilder, /PIP_CACHE_DIR = Join-Path \$packageDir 'pip-cache'/);
  assert.match(exeBuilder, /bounded Windows OTA updater/);
  assert.match(exeBuilder, /robocopy\.exe/);
  assert.match(exeBuilder, /bounded OTA completed and service is running/);
  assert.match(exeBuilder, /SOC Agent OTA UPDATED to v\$\{VERSION\}/);
  assert.match(exeBuilder, /Add-Content -LiteralPath \$InstallLogPath/);
  assert.match(exeBuilder, /set-uninstall-password\.ps1/);
  assert.ok(
    exeBuilder.indexOf('${windowsProtectedAclSnippet()}') > exeBuilder.indexOf('VERIFIED: Service'),
    'EXE installer must harden ACLs only after the Windows service is running',
  );
  assert.doesNotMatch(exeBuilder, /Downloading NSSM/);
  assert.match(exeBuilder, /Native pywin32 Windows service/);
  assert.match(exeBuilder, /start=', 'delayed-auto/);
  assert.match(exeBuilder, /restart\/5000\/restart\/15000\/restart\/60000/);
  assert.doesNotMatch(exeBuilder, /Invoke-Sc -Arguments @\('delete', \$ServiceName\)/);
  assert.match(exeBuilder, /ERROR_SERVICE_MARKED_FOR_DELETE/);
  assert.match(exeBuilder, /\$serviceAction = if \(\$serviceExists\) \{ 'update' \} else \{ 'install' \}/);
  assert.match(exeBuilder, /pywin32_postinstall\.py/);
  assert.match(exeBuilder, /windowsPywin32ServiceHostSnippet\('Invoke-Native'\)/);
  assert.match(builder, /AJNAT Windows service host validation/);
  assert.match(builder, /Copy-Item -LiteralPath \$serviceWrapper -Destination \(Join-Path \$serviceSitePackages 'windows_service\.py'\)/);
  assert.match(builder, /Get-ChildItem -LiteralPath \$basePythonDir -Filter 'python\*\.dll'/);
  assert.match(exeBuilder, /operation=\$CurrentOperation/);
  assert.match(exeBuilder, /\$env:PYTHONUTF8 = "1"/);
  assert.match(exeBuilder, /Agent health check/);
  assert.match(exeBuilder, /AGENT_EMBED_WINDOWS_VELOCIRAPTOR/);
  assert.match(exeBuilder, /authenticated[\s\S]*AJNAT dependency endpoint/);
  assert.match(exeBuilder, /windowsVelociraptorInstallSnippet\(\)/);
  assert.match(builder, /function Install-AjnatVelociraptorClient/);
  assert.match(builder, /service install/);
  assert.match(builder, /enrollment starts on first server connection/);
  assert.match(exeBuilder, /exited during the post-install stability check/);
  assert.doesNotMatch(exeBuilder, /Add-Content -Path \$InstallLog -Value \$failure/);
  assert.match(exeBuilder, /WaitForStatus\('Stopped'.*30/);
  assert.match(exeBuilder, /function Repair-InstallerAccess/);
  assert.match(exeBuilder, /Test-Path -LiteralPath \$Path -ErrorAction Stop/);
  assert.match(exeBuilder, /New-Item -ItemType Directory -Path \$Path -Force -ErrorAction Stop/);
  assert.match(exeBuilder, /Add-Content -LiteralPath \$BootstrapLog -Value \$failure/);
  assert.match(exeBuilder, /takeown\.exe \/F \$Path \/A \/R/);
  assert.match(exeBuilder, /icacls\.exe \$Path \/reset \/T/);
  assert.match(exeBuilder, /icacls\.exe \$Path \/grant '\*S-1-5-18:F' '\*S-1-5-32-544:F' \/T/);
  assert.ok(
    exeBuilder.indexOf('$CurrentOperation = "stop-existing-service"') < exeBuilder.indexOf('$CurrentOperation = "backup-existing-install"'),
    'EXE updater must stop the existing service before backing up its files',
  );
  assert.ok(
    exeBuilder.indexOf('$CurrentOperation = "stop-existing-service"') < exeBuilder.indexOf('$CurrentOperation = "repair-existing-install-access"')
      && exeBuilder.indexOf('$CurrentOperation = "repair-existing-install-access"') < exeBuilder.indexOf('$CurrentOperation = "backup-existing-install"'),
    'EXE updater must repair protected child ACLs after stopping agent processes and before backup/replacement',
  );
  assert.match(exeBuilder, /\$BackupComplete = \$false/);
  assert.match(exeBuilder, /\$BackupComplete = \$true/);
  assert.match(exeBuilder, /\$IsUpdate -and \$BackupComplete -and/);
  assert.match(exeBuilder, /Before BackupComplete no installed file has been overwritten/);
  assert.match(exeBuilder, /AJNAT-backup-/);
  assert.match(exeBuilder, /rollback restored previous files\/config and running service/);
  assert.match(exeBuilder, /Matching enrollment retained and refreshed/);
  assert.match(exeBuilder, /replacing stale agent identity/);
  assert.match(exeBuilder, /\$sameCompany -and \$sameSystem -and \$sameAgentKey/);
  assert.match(exeBuilder, /\$configToInstall\.agent_version = \$Version/);
  assert.match(exeBuilder, /Could not install packaged enrollment configuration/);
  assert.doesNotMatch(exeBuilder, /Existing enrollment configuration preserved/);
  assert.doesNotMatch(exeBuilder, /urllib3<2/);
  assert.match(exeBuilder, /'requests', 'urllib3<3', 'psutil', 'watchdog', 'cryptography'/);
  assert.match(exeBuilder, /Required AJNAT Python dependencies installation/);
  assert.match(exeBuilder, /Required AJNAT Python dependencies validation/);
  assert.match(builder, /takeown\.exe \/F \$legacyPassFile \/A/);
  assert.match(builder, /repair the legacy uninstall password ACL/);
  assert.match(builder, /pbkdf2-sha256/);
  const generatedPasswordVerifier = windowsPasswordVerifySnippet();
  assert.ok(
    generatedPasswordVerifier.includes("^pbkdf2-sha256:(\\d+):([^:]+):([^:]+)$"),
    'generated PowerShell must retain the regex digit escape for PBKDF2 records',
  );
  assert.match(builder, /UseSystemPasswordChar = \$true/);
  assert.match(builder, /Uninstall cancelled or password verification failed/);
  assert.match(builder, /windowsPasswordInstallSnippet\(\{ resetExisting: true \}\)/);
  assert.match(builder, /path\.join\(payloadRoot, 'set-uninstall-password\.ps1'\)/);
  assert.match(exeBuilder, /preserve-uninstall-password/);
  assert.match(exeBuilder, /ProgramData "AJNAT"/);
  assert.match(exeBuilder, /certs\/server-ca-bundle\.pem/);
  assert.match(exeBuilder, /windowsCaProvisionSnippet\(tlsPackage\.caBundle\)/);
  assert.match(exeBuilder, /AJNAT-Local-Test-Publisher\.cer/);
  assert.match(exeBuilder, /windowsPublisherProvisionSnippet\(publisherCertificate\)/);
  assert.match(exeBuilder, /Get-WinEvent/);
  assert.match(exeBuilder, /Service Control Manager/);
  assert.match(builder, /Unable to read diagnostic log/);
  assert.match(builder, /Exec 'powershell\.exe -NoExit[^\n]+soc-agent-show-error\.ps1/);
  assert.match(builder, /IfSilent silent_install_failure interactive_install_failure/);
  const onInitStart = builder.indexOf('Function .onInit');
  const onInitEnd = builder.indexOf('FunctionEnd', onInitStart);
  const onInit = builder.slice(onInitStart, onInitEnd);
  assert.ok(onInit.includes('IfFileExists "$COMMONAPPDATA\\\\AJNAT\\\\uninstall.pass" silent_update_allowed 0'));
  assert.ok(onInit.includes('IfFileExists "$COMMONAPPDATA\\\\SOCAgent\\\\uninstall.pass" silent_update_allowed 0'));
  assert.ok(onInit.indexOf('Silent installation is disabled') < onInit.indexOf('silent_update_allowed:'));
  assert.match(onInit, /Silent installation is disabled[\s\S]*Abort/);
  assert.match(builder, /SetErrorLevel \$0/);
  assert.doesNotMatch(builder, /ExecShell "open" "powershell\.exe"[^\n]+soc-agent-show-error\.ps1/);
  assert.match(builder, /\*S-1-5-32-545:\(OI\)\(CI\)RX/);
  assert.match(builder, /Install file direct ACL update/);
  assert.match(builder, /Runtime log direct ACL update/);
  assert.doesNotMatch(exeBuilder, /Where-Object \{ \$_\.Name -like ['"]python/);
  assert.match(wrapper, /class SocAgentService\(win32serviceutil\.ServiceFramework\)/);
  assert.match(wrapper, /HandleCommandLine\(SocAgentService\)/);
  assert.match(wrapper, /def SvcShutdown/);
  assert.match(wrapper, /SOC_AGENT_CONFIG/);
  assert.match(wrapper, /ProgramData.*AJNAT/);
  assert.match(wrapper, /Path\(sys\.exec_prefix\) \/ "python\.exe"/);
  assert.match(wrapper, /root \/ "runtime" \/ "python" \/ "Scripts" \/ "python\.exe"/);
  assert.match(wrapper, /root_candidates = \[module_root, \*module_root\.parents, \*executable\.parents\]/);
  assert.match(wrapper, /child_env\["PYTHONUTF8"\] = "1"/);
  assert.match(agent, /reconfigure\(errors='replace'\)/);
  assert.match(agent, /Secure storage key issued/);
  assert.match(agent, /'event_id':\s+uuid\.uuid4\(\)\.hex/);
  assert.match(agent, /200 <= r\.status_code < 300/);
  assert.match(agent, /raise SystemExit\(0 if result else 1\)/);
  assert.match(agent, /--config/);
  assert.match(exeBuilder, /'test', '--config', \$configPath/);
  assert.match(exeBuilder, /windowsNetworkSensorInstallSnippet\(\)/);
  assert.match(exeBuilder, /windowsAdvancedProcessTelemetrySnippet\(\)/);
  assert.match(builder, /AJNAT_REQUIRE_WINDOWS_INLINE_IPS/);
  assert.match(builder, /\$sensorArguments \+= '-Optional'/);
  assert.match(builder, /install-windows-ids\.ps1/);
  assert.match(builder, /AJNAT_SURICATA_INSTALLER_URL/);
  assert.match(builder, /-SuricataInstallerSha256/);
  assert.match(windowsIds, /OISF\.Suricata/);
  assert.match(windowsIds, /--windivert/);
  assert.match(windowsIds, /WinDivert\.dll/);
  assert.match(windowsIds, /WinDivert enabled:\\s\+yes/);
  assert.match(windowsIds, /inline_packet_verdict = \$true/);
  assert.match(windowsIds, /Continuing with Windows Defender Firewall native IPS fallback/);
  assert.match(windowsIds, /network_ids_sensors_enabled = \$false/);
  assert.match(windowsIds, /--service-change-params/);
  assert.match(windowsIds, /suricata\\log/);
  assert.match(windowsIds, /suricata_eve_path/);
  assert.match(windowsProcessTelemetry, /ProcessCreationIncludeCmdLine_Enabled/);
  assert.match(windowsProcessTelemetry, /sysmon-ajnat\.xml/);
  assert.match(windowsProcessTelemetry, /Sysmon is not installed/);
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  assert.match(routes, /compareVersions\(version, targetVersion\) === 0/);
  assert.match(routes, /pendingUpdateCommand\.force !== true[\s\S]*matchingUpdateRequest[\s\S]*!\['downloading', 'installing'\]\.includes\(reportedStatus\)/);
  assert.match(routes, /failedUpdateRequestConfirmed[\s\S]*reportedUpdateRequestId === String\(pendingUpdateCommand\.id\)/);
  assert.match(routes, /heartbeatWrite\.\$pull = pendingUpdateCommand[\s\S]*pendingCommands: \{ id: pendingUpdateCommand\.id \}/);
  assert.match(routes, /if \(command === 'update'\) continue/);
  assert.match(routes, /agentConfig\.update_request_id = updateRequestId/);
  assert.match(routes, /includeVelociraptor = \['exe', 'msi'\]\.includes\(buildFn\)/);
  assert.match(routes, /Cache-Control', 'no-store, no-cache, must-revalidate, private'/);
  assert.match(routes, /X-AJNAT-Artifact-SHA256/);
  assert.match(routes, /Content-Digest/);
  assert.match(routes, /agentPackageSha256\(payload\)/);
  assert.match(routes, /WINDOWS_CODE_SIGN_MODE[^\n]+local-test/);
  assert.match(routes, /WINDOWS_CODE_SIGN_PUBLIC_CERT/);
  assert.match(routes, /builders\[buildFn\]\(resolvedSystem, company, agentConfig, \{[\s\S]+includeVelociraptor/);
  assert.match(routes, /compareVersions\(system\.agentVersion, targetVersion\) >= 0/);
  assert.match(routes, /fromVersion: system\.agentVersion,[\s\S]*targetVersion/);
  assert.match(routes, /manual retry supersedes[\s\S]*\$pull: \{ pendingCommands: \{ command: 'update' \} \}/);
  assert.doesNotMatch(routes, /compareVersions\(agent_version, system\.updateTargetVersion\) >= 0/);
  const heartbeat = fs.readFileSync(path.join(__dirname, '../soc-agent/core/heartbeat.py'), 'utf8');
  assert.match(heartbeat, /params\['update_request_id'\] = update_request_id/);
  assert.match(heartbeat, /'update_request_id': \([\s\S]*self\._active_update_request_id[\s\S]*self\.config\.get\('update_request_id', ''\)/);
  assert.match(heartbeat, /if system == 'Windows':[\s\S]+subprocess\.Popen\(/);
  assert.doesNotMatch(heartbeat, /if system == 'Windows':[\s\S]{0,500}subprocess\.run\(cmd, check=True, timeout=600\)/);
  assert.match(heartbeat, /X-AJNAT-Artifact-SHA256/);
  assert.match(heartbeat, /hmac\.compare_digest\(actual_sha256, expected_sha256\)/);
  assert.match(heartbeat, /update package SHA-256 mismatch/);
  assert.match(exeBuilder, /Keep that copy in sync during bounded[\s\S]+Copy-Item -LiteralPath \(Join-Path \$InstallDir 'windows_service\.py'\)/);
  assert.match(builder, /Refresh on update too:[\s\S]+Copy-Item -LiteralPath \$packagedPythonServiceExe -Destination \$pythonServiceExe -Force/);
  assert.match(builder, /Base Python DLL is missing from \$basePythonDir/);
});

test('Android APK embeds configuration and starts protection automatically', () => {
  const builder = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  const gradle = fs.readFileSync(path.join(__dirname, '../android-agent/app/build.gradle'), 'utf8');
  const activity = fs.readFileSync(path.join(__dirname, '../android-agent/app/src/main/java/com/soc/agent/MainActivity.java'), 'utf8');
  const service = fs.readFileSync(path.join(__dirname, '../android-agent/app/src/main/java/com/soc/agent/AgentService.java'), 'utf8');
  const vpnFirewall = fs.readFileSync(path.join(__dirname, '../android-agent/app/src/main/java/com/soc/agent/LocalFirewallVpnService.java'), 'utf8');
  const manifest = fs.readFileSync(path.join(__dirname, '../android-agent/app/src/main/AndroidManifest.xml'), 'utf8');
  const networkSecurity = fs.readFileSync(path.join(__dirname, '../android-agent/app/src/main/res/xml/network_security_config.xml'), 'utf8');

  assert.match(gradle, /versionCode 17/);
  assert.match(gradle, /versionName "0\.1\.4"/);
  const blueprint = fs.readFileSync(path.join(__dirname, '../android-agent/Android.bp'), 'utf8');
  assert.match(blueprint, /--version-code", "17"/);
  assert.match(blueprint, /--version-name", "0\.1\.4"/);
  assert.match(routes, /ANDROID_AGENT_VERSION = process\.env\.ANDROID_AGENT_VERSION \|\| '0\.1\.4'/);

  assert.match(builder, /company_config\.json/);
  assert.match(activity, /startAgentService\(\);/);
  assert.match(service, /body\.put\("ip", (?:\(Object\))?localIp\)/);
  assert.match(service, /getLocalIpv4Address/);
  assert.match(service, /Math\.max\(30, Math\.min\(300, result\.intervalSeconds\)\)/);
  assert.match(service, /onTaskRemoved/);
  assert.match(service, /setAndAllowWhileIdle/);
  assert.match(service, /registerDefaultNetworkCallback/);
  assert.doesNotMatch(service, /if \(result\.stopMonitoring\) \{\s*stopSelf\(\)/);
  assert.match(service, /name\.startsWith\("wlan"\)/);
  assert.match(service, /initializeRootFirewall/);
  assert.doesNotMatch(service, /ProcessBuilder\("su"/);
  assert.doesNotMatch(service, /iptables -w -N SOC_AGENT/);
  assert.match(service, /LocalFirewallVpnService\.updateRule/);
  assert.match(service, /"block_ip"\.equals\(command\)/);
  assert.match(service, /"block_domain"\.equals\(command\)/);
  assert.match(service, /"ips_whitelist_add"\.equals\(command\)/);
  assert.match(service, /replaceWhitelist/);
  assert.match(routes, /ips_whitelist:/);
  assert.match(service, /body\.put\("idsEnabled", true\)/);
  assert.match(service, /syncFirewallPolicy\(json\.optJSONArray\("firewall_rules"\)\)/);
  assert.match(service, /performSelfUpdate\(commandId\)/);
  assert.match(service, /"update_request_id"/);
  assert.match(activity, /VpnService\.prepare/);
  assert.match(activity, /PBKDF2WithHmacSHA256/);
  assert.match(activity, /setUninstallBlocked\(adminComponent\(\), getPackageName\(\), true\)/);
  assert.match(activity, /showUninstallAuthorization/);
  assert.match(activity, /clearDeviceOwnerApp/);
  assert.match(manifest, /android\.permission\.BIND_DEVICE_ADMIN/);
  assert.match(manifest, /android\.app\.action\.DEVICE_ADMIN_ENABLED/);
  assert.match(vpnFirewall, /extends VpnService/);
  assert.match(vpnFirewall, /addRoute\(ip, ip\.contains\(":"\) \? 128 : 32\)/);
  assert.match(vpnFirewall, /addRoute\("::", 0\)/);
  assert.match(vpnFirewall, /whitelistMatches/);
  assert.match(vpnFirewall, /youtubei\.googleapis\.com/);
  assert.match(vpnFirewall, /replacePolicyRules/);
  assert.match(vpnFirewall, /reportBlockedAttempt/);
  assert.match(manifest, /android:networkSecurityConfig="@xml\/network_security_config"/);
  assert.match(networkSecurity, /base-config cleartextTrafficPermitted="true"/);
  assert.match(networkSecurity, />10\.0\.2\.2</);
  assert.match(manifest, /android\.intent\.action\.MY_PACKAGE_REPLACED/);
  assert.match(manifest, /FOREGROUND_SERVICE_SPECIAL_USE/);
  assert.match(manifest, /android\.permission\.BIND_VPN_SERVICE/);
});

test('Windows MSI auto-provisions supported Python and writes a failure log', () => {
  const builder = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  const wixBuilder = builder.slice(builder.indexOf('function buildMsiFromPayload('), builder.indexOf('// README helpers'));
  const msiBuilder = builder.slice(builder.indexOf('function buildMsi('), builder.indexOf('// macOS installer bundle'));

  assert.match(builder, /msi-install\.log/);
  assert.match(builder, /MSI INSTALL FAILED/);
  assert.match(builder, /python-3\.12\.10-arm64\.exe/);
  assert.match(builder, /Required AJNAT Python dependencies validation/);
  assert.match(msiBuilder, /Agent health check/);
  assert.match(msiBuilder, /'test', '--config', \$configPath/);
  assert.match(msiBuilder, /post-install stability check/);
  assert.doesNotMatch(msiBuilder, /copyVelociraptorBundle\(payloadRoot, 'winMsi'\)/);
  assert.match(msiBuilder, /windowsVelociraptorInstallSnippet\(\)/);
  assert.match(msiBuilder, /server-ca-bundle\.pem/);
  assert.match(msiBuilder, /windowsCaProvisionSnippet\(tlsPackage\.caBundle\)/);
  assert.match(msiBuilder, /AJNAT-Local-Test-Publisher\.cer/);
  assert.match(msiBuilder, /windowsPublisherProvisionSnippet\(publisherCertificate\)/);
  assert.match(builder, /X509BasicConstraintsExtension/);
  assert.match(builder, /X509Store\(\$storeName, 'LocalMachine'\)/);
  assert.match(builder, /Packaged AJNAT server CA bundle failed SHA-256 verification/);
  assert.match(builder, /@\('Root', 'TrustedPublisher'\)/);
  assert.match(builder, /AJNAT publisher certificate thumbprint mismatch/);
  assert.match(builder, /Downloading Velociraptor enrollment client from AJNAT server/);
  assert.match(builder, /self-update\/dependency\/velociraptor\/windows\?agent_key=\$agentKey/);
  assert.match(builder, /AJNAT dependency download failed after 3 attempts/);
  assert.match(builder, /X-AJNAT-Artifact-SHA256/);
  assert.match(builder, /failed SHA-256 verification/);
  assert.match(wixBuilder, /<Upgrade Id="\$\{upgradeCode\}">/);
  assert.match(wixBuilder, /const productCode = `\{\$\{crypto\.randomUUID\(\)\.toUpperCase\(\)\}\}`/);
  assert.match(wixBuilder, /<Product Id="\$\{productCode\}"/);
  assert.doesNotMatch(wixBuilder, /<Product Id="\*"/);
  assert.match(wixBuilder, /<UIRef Id="WixUI_Minimal"/);
  assert.match(wixBuilder, /must be installed interactively so an uninstall password can be configured/);
  assert.match(wixBuilder, /Installed OR AJNAT_RELATED_PRODUCTS OR UILevel &gt;= 4/);
  assert.match(wixBuilder, /InstallScope="perMachine" InstallPrivileges="elevated"/);
  assert.match(wixBuilder, /--ext', 'ui'/);
  assert.match(wixBuilder, /wixl 0\.106 emits InstallExecuteSequence references but silently drops/);
  assert.match(wixBuilder, /msibuild and msiinfo are required to finalize wixl MSI custom actions/);
  assert.match(wixBuilder, /MSI custom action was not compiled/);
  assert.match(wixBuilder, /<UpgradeVersion Minimum="0\.0\.0" IncludeMinimum="yes" Property="AJNAT_RELATED_PRODUCTS"/);
  assert.doesNotMatch(wixBuilder, /<UpgradeVersion[^>]+Maximum=/);
  assert.doesNotMatch(wixBuilder, /<MajorUpgrade/);
  assert.match(wixBuilder, /<RemoveExistingProducts Sequence="1450"/);
  assert.match(wixBuilder, /<Directory Id="ProgramFiles64Folder">/);
  assert.match(wixBuilder, /<Directory Id="INSTALLFOLDER" Name="AJNAT">/);
  assert.match(wixBuilder, /execFileSync\(wixl, \['--arch', 'x64'/);
  assert.match(wixBuilder, /ServiceControl[^>]+Name="SOCAgent"[^>]+Stop="both"[^>]+Remove="uninstall"/);
  assert.match(wixBuilder, /CustomAction Id="SetupUninstallPassword"[^>]+Return="check"/);
  assert.match(wixBuilder, /CustomAction Id="VerifyUninstallPassword"[^>]+Return="check"/);
  assert.match(wixBuilder, /REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE/);
  assert.match(wixBuilder, /CustomAction Id="RunUpgradeCleanup"[^>]+-PreserveData/);
  assert.match(wixBuilder, /Custom Action="RunUpgradeCleanup" Sequence="3420">REMOVE="ALL" AND UPGRADINGPRODUCTCODE/);
  assert.match(wixBuilder, /const setupPasswordCondition = isAgentUpdate[\s\S]*NOT \(REMOVE=&quot;ALL&quot;\) OR AJNAT_RELATED_PRODUCTS/);
  assert.match(wixBuilder, /SetupUninstallPassword" Sequence="4010">\$\{setupPasswordCondition\}/);
  assert.match(wixBuilder, /RunInstallPs1" Sequence="4020">NOT \(REMOVE=&quot;ALL&quot;\) OR AJNAT_RELATED_PRODUCTS/);
  assert.match(wixBuilder, /CustomAction Id="RunUninstallPs1"[^>]+Return="check"/);
  assert.match(wixBuilder, /CustomAction Id="RunUpgradeCleanup"[^>]+Return="check"/);
  assert.match(msiBuilder, /password-setup\.ps1/);
  assert.match(msiBuilder, /password-verify\.ps1/);
  assert.match(msiBuilder, /windowsMsiInteractiveActionPrelude\('Uninstall password setup'\)/);
  assert.match(builder, /ajnat-msi-password-action\.log/);
  assert.match(builder, /-Verb RunAs -Wait -PassThru/);
  assert.match(msiBuilder, /silent first-time installation is blocked/);
  assert.match(msiBuilder, /WaitForStatus\('Stopped'.*30/);
  assert.match(msiBuilder, /if \(-not \$PreserveData\)[\s\S]+Remove-Item C:\\\\ProgramData\\\\AJNAT/);
  assert.doesNotMatch(wixBuilder, /-InstallDir &quot;\[INSTALLFOLDER\]&quot;/);
  assert.match(msiBuilder, /function Repair-MsiInstallerAccess/);
  assert.match(msiBuilder, /Test-Path -LiteralPath \$Path -ErrorAction Stop/);
  assert.match(msiBuilder, /New-Item -ItemType Directory -Path \$Path -Force -ErrorAction Stop/);
  assert.match(msiBuilder, /Invoke-MsiNative/);
  assert.match(msiBuilder, /msi-service-install\.log/);
  assert.match(msiBuilder, /\$sameCompany -and \$sameSystem -and \$sameAgentKey/);
  assert.match(msiBuilder, /replacing stale agent identity/);
  assert.doesNotMatch(msiBuilder, /urllib3<2/);
  assert.match(msiBuilder, /'requests', 'urllib3<3', 'psutil', 'watchdog', 'cryptography'/);
  assert.match(msiBuilder, /Required AJNAT Python dependencies installation/);
  assert.match(msiBuilder, /windowsPywin32ServiceHostSnippet\('Invoke-MsiNative'\)/);
  assert.ok(
    msiBuilder.indexOf('${windowsProtectedAclSnippet()}') > msiBuilder.indexOf('SOC Agent service was created but did not reach Running state'),
    'MSI installer must harden ACLs only after its service is running',
  );
});

test('Windows MSI OTA packages allow silent execution without password prompts', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/services/packageBuilder.service.js'), 'utf8');
  assert.match(source, /const launchCondition = isAgentUpdate[\s\S]+\? '1'/);
  assert.match(source, /const setupPasswordCondition = isAgentUpdate[\s\S]+\? '0'/);
  assert.match(source, /buildMsiFromPayload\(payloadRoot, system, company, VERSION, options\)/);
  assert.match(source, /TrustPublisherRoot/);
  assert.match(source, /TrustPublisherCodeSigning/);
  assert.match(source, /certutil\.exe -f -addstore Root/);
  assert.match(source, /certutil\.exe -f -addstore TrustedPublisher/);
});

test('Windows download pages show direct EXE/MSI install, update, diagnostics, and uninstall steps', () => {
  for (const relativePath of [
    '../../company/src/pages/AgentDownloadPage.jsx',
    '../../superadmin/src/pages/AgentDownloadPage.jsx',
  ]) {
    const page = fs.readFileSync(path.join(__dirname, relativePath), 'utf8');
    assert.match(page, /Double-click the downloaded installer/);
    assert.match(page, /No PowerShell command is required/);
    assert.match(page, /automatically requests administrator access/);
    assert.match(page, /msiexec\.exe \/x .*\/L\*v/);
    assert.match(page, /stale enrollment is replaced automatically/);
    assert.match(page, /soc-agent-install-bootstrap\.log/);
    assert.doesNotMatch(page, /Extract the downloaded ZIP to C:\\\\SOCAgent/);
  }
});

test('update buttons are enabled only when the server release version increases', () => {
  for (const relativePath of [
    '../../company/src/pages/SystemsPage.jsx',
    '../../superadmin/src/pages/SystemsPage.jsx',
  ]) {
    const page = fs.readFileSync(path.join(__dirname, relativePath), 'utf8');
    const stateHelper = page.slice(
      page.indexOf('function agentUpdateButtonState'),
      page.indexOf('// ── Badge components'),
    );
    assert.ok(
      stateHelper.indexOf("['pending', 'downloading', 'installing']")
        < stateHelper.indexOf('isAgentUpdateAvailable(system.agentVersion, currentVersion)'),
      'an in-flight update must remain disabled until backend confirmation',
    );
    assert.match(page, /compareVersions\(installed, current\) < 0/);
    assert.match(stateHelper, /label: currentVersion \? 'Updated' : 'Version unavailable'/);
    assert.doesNotMatch(stateHelper, /Reinstall/);
    assert.doesNotMatch(page, /forceReinstall/);
    assert.match(page, /if \(sys\.updateStatus === 'success'\)/);
    assert.match(page, /currentVersion: st\.currentVersion/);
    assert.match(page, /targetAgentVersion\(system, currentAgentVersion\)/);
    assert.match(page, /soc-agent_v\$\{releaseVersion\}_/);
    assert.match(page, /No PowerShell command is required/);
  }
});

test('company update button gives an actionable recovery for Windows application-control blocks', () => {
  const page = fs.readFileSync(path.join(__dirname, '../../company/src/pages/SystemsPage.jsx'), 'utf8');
  assert.match(page, /isWindowsApplicationControlError/);
  assert.match(page, /winerror\\s\*4551/);
  assert.match(page, /Windows Policy Blocked the Update/);
  assert.match(page, /allow the AJNAT publisher/);
  assert.match(page, /Download Trust Certificate/);
  assert.match(page, /agent\/windows-signing-certificate/);
  assert.match(page, /AJNAT-Local-Test-Publisher\.cer/);
  assert.match(page, /Trusted Publishers/);
});

test('Windows updates preserve the original installer ownership', () => {
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  assert.match(routes, /downloadType: \{ \$in: \['exe', 'msi'\] \}/);
  assert.doesNotMatch(routes, /downloadType: \{ \$in: \['exe', 'msi', 'update-exe', 'update-msi'\] \}/);
  assert.doesNotMatch(routes, /applicationControlBlocked/);
  assert.doesNotMatch(routes, /type === 'exe'.+type = 'msi'/);
});

test('OTA progress and failure reports belong to the current update request', () => {
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  assert.match(routes, /else if \(failedUpdateRequestConfirmed\)/);
  assert.match(
    routes,
    /reportedUpdateRequestId === String\(pendingUpdateCommand\.id\)[\s\S]+\['downloading', 'installing'\]\.includes\(reportedStatus\)/,
  );
  assert.match(
    routes,
    /command\?\.command !== 'update'[\s\S]+!\['downloading', 'installing'\]\.includes\(responseUpdateStatus\)/,
  );
  assert.doesNotMatch(routes, /else if \(updateInProgress && reportedStatus === 'failed'\)/);
});
