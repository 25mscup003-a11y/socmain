/**
 * Package Builder Service  — v3 (fully updated)
 * Builds OS-specific installer packages that always include the LATEST agent files.
 *
 * All packages:
 *   • Full agent source code  (from fixed-agent-v2/ — latest fixes)
 *   • Pre-filled company_config.json  (agent_key, server_url, agent_version…)
 *   • OS-specific install / uninstall scripts with UPDATE support
 *
 *  buildDeb()  → .deb      (Debian / Ubuntu / Kali / Mint)
 *  buildRpm()  → .rpm      (RHEL / CentOS / Fedora / Rocky)
 *  buildExe()  → .exe      (Windows NSIS installer)
 *  buildMsi()  → .msi      (Windows Installer package)
 *  buildMacPkg() → .pkg    (macOS Installer package — LaunchDaemon)
 *  buildDmg()  → .dmg      (macOS disk image containing the .pkg)
 *  buildApk()  → .apk      (debug-signed Android app)
 *  buildSolaris() → .zip   (Solaris SMF service installer)
 *
 * UPDATE behaviour:
 *   Running install.sh on a system that already has the agent will:
 *   1. Stop the existing service
 *   2. Overwrite all agent code with the latest version
 *   3. Keep the existing config (unless a newer config is bundled)
 *   4. Restart the service
 */

const path = require('path');
const fs   = require('fs');
const os   = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const DEFAULT_AGENT_VERSION = '0.1.10';
const REQUIRED_AGENT_FILES = Object.freeze([
  'agent.py',
  'windows_service.py',
  'requirements.txt',
  'core/config.py',
  'core/config_protection.py',
  'core/device_identity.py',
  'core/heartbeat.py',
  'core/sender.py',
  'collectors/processes.py',
  'detectors/ransomware.py',
  'response/isolate.py',
]);

const WINDOWS_AGENT_CA_BUNDLE_PATH = String.raw`C:\ProgramData\AJNAT\certs\server-ca-bundle.pem`;

function loadAgentServerCaBundle(environment = process.env) {
  const inlinePem = String(environment.AGENT_SERVER_CA_BUNDLE_PEM || '').trim();
  const bundlePath = String(environment.AGENT_SERVER_CA_BUNDLE_FILE || '').trim();
  if (inlinePem && bundlePath) {
    throw new Error('Set only one of AGENT_SERVER_CA_BUNDLE_PEM or AGENT_SERVER_CA_BUNDLE_FILE');
  }
  if (!inlinePem && !bundlePath) return null;

  let pem = inlinePem;
  if (bundlePath) {
    const resolved = path.resolve(bundlePath);
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
      throw new Error(`AGENT_SERVER_CA_BUNDLE_FILE is not a readable file: ${resolved}`);
    }
    pem = fs.readFileSync(resolved, 'utf8').trim();
  }
  if (/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/.test(pem)) {
    throw new Error('AGENT server CA bundle must never contain a private key');
  }

  const certificates = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  if (!certificates.length) {
    throw new Error('AGENT server CA bundle does not contain a PEM certificate');
  }
  for (const certificatePem of certificates) {
    let certificate;
    try {
      certificate = new crypto.X509Certificate(certificatePem);
    } catch (err) {
      throw new Error(`AGENT server CA bundle contains an invalid certificate: ${err.message}`);
    }
    if (!certificate.ca) {
      throw new Error(`AGENT server CA bundle contains a non-CA certificate: ${certificate.subject}`);
    }
  }

  const content = Buffer.from(`${certificates.join('\n')}\n`, 'utf8');
  return {
    content,
    sha256: crypto.createHash('sha256').update(content).digest('hex'),
  };
}

function prepareWindowsTlsPackage(agentConfig, environment = process.env) {
  const config = { ...agentConfig };
  const caBundle = loadAgentServerCaBundle(environment);
  const pin = String(environment.AGENT_SERVER_CERT_SHA256 || config.tls_server_sha256 || '')
    .replace(/:/g, '')
    .trim()
    .toLowerCase();
  if (pin && !/^[a-f0-9]{64}$/.test(pin)) {
    throw new Error('AGENT_SERVER_CERT_SHA256 must be a SHA-256 certificate fingerprint');
  }
  if (pin) config.tls_server_sha256 = pin;

  if (caBundle) {
    let serverUrl;
    try {
      serverUrl = new URL(String(config.server_url || ''));
    } catch {
      throw new Error('A valid HTTPS server_url is required when an AGENT server CA bundle is configured');
    }
    if (serverUrl.protocol !== 'https:') {
      throw new Error('AGENT server CA provisioning requires an HTTPS server_url');
    }
    config.require_tls = true;
    config.tls_ca_bundle = WINDOWS_AGENT_CA_BUNDLE_PATH;
  } else if (config.tls_ca_bundle) {
    throw new Error('Windows agent config references tls_ca_bundle but no CA bundle is available to embed');
  }

  return { config, caBundle };
}

function prepareAndroidTlsPackage(agentConfig, environment = process.env) {
  const config = { ...agentConfig };
  // Android uses the per-system agent key for canonical HMAC authentication.
  // Never embed the fleet-wide legacy integration secret in a downloadable APK.
  delete config.integration_secret;
  const caBundle = loadAgentServerCaBundle(environment);
  const pin = String(environment.AGENT_SERVER_CERT_SHA256 || config.tls_server_sha256 || '')
    .replace(/:/g, '')
    .trim()
    .toLowerCase();
  if (pin && !/^[a-f0-9]{64}$/.test(pin)) {
    throw new Error('AGENT_SERVER_CERT_SHA256 must be a SHA-256 certificate fingerprint');
  }
  if (pin) config.tls_server_sha256 = pin;
  let serverUrl;
  try {
    serverUrl = new URL(String(config.server_url || ''));
  } catch {
    throw new Error('A valid server_url is required for Android agents');
  }
  const isPrivateTestHost = (hostname) => {
    if (['localhost', '127.0.0.1', '10.0.2.2'].includes(hostname)) return true;
    const octets = String(hostname).split('.').map(value => Number(value));
    if (octets.length !== 4 || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)) return false;
    return octets[0] === 10
      || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
      || (octets[0] === 192 && octets[1] === 168);
  };
  const testMode = String(environment.NODE_ENV || 'development').toLowerCase() !== 'production'
    || String(environment.ANDROID_AGENT_ALLOW_HTTP_TEST || '').toLowerCase() === 'true';
  const localHttpTest = serverUrl.protocol === 'http:' && testMode && isPrivateTestHost(serverUrl.hostname);
  if (serverUrl.protocol !== 'https:' && !localHttpTest) {
    throw new Error('Android agents require an HTTPS server_url');
  }
  config.require_tls = !localHttpTest;
  if (localHttpTest) config.allow_cleartext_test = true;
  else delete config.allow_cleartext_test;
  if (caBundle) {
    config.tls_ca_bundle_asset = 'server-ca-bundle.pem';
    delete config.tls_ca_bundle;
  } else {
    delete config.tls_ca_bundle;
    delete config.tls_ca_bundle_asset;
  }
  return { config, caBundle };
}

function loadWindowsPublisherCertificate(environment = process.env) {
  if (String(environment.WINDOWS_CODE_SIGN_MODE || '').trim().toLowerCase() !== 'local-test') {
    return null;
  }
  const certificatePath = String(environment.WINDOWS_CODE_SIGN_PUBLIC_CERT || '').trim();
  if (!certificatePath) {
    throw new Error('WINDOWS_CODE_SIGN_PUBLIC_CERT is required in local-test signing mode');
  }
  const resolved = path.resolve(certificatePath);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    throw new Error(`WINDOWS_CODE_SIGN_PUBLIC_CERT is not a readable file: ${resolved}`);
  }
  const content = fs.readFileSync(resolved);
  let certificate;
  try {
    certificate = new crypto.X509Certificate(content);
  } catch (err) {
    throw new Error(`WINDOWS_CODE_SIGN_PUBLIC_CERT is invalid: ${err.message}`);
  }
  if (certificate.subject !== certificate.issuer) {
    throw new Error('Local-test Windows publisher certificate must be self-signed');
  }
  return {
    content,
    sha256: crypto.createHash('sha256').update(content).digest('hex'),
    thumbprint: certificate.fingerprint.replace(/:/g, '').toUpperCase(),
  };
}

function windowsCaProvisionSnippet(caBundle) {
  if (!caBundle) return '';
  return `
# -- AJNAT server CA provisioning --
$CurrentOperation = "install-server-ca"
$packagedCaBundle = Join-Path $InstallDir 'certs\\server-ca-bundle.pem'
$installedCaDir = Join-Path $env:ProgramData 'AJNAT\\certs'
$installedCaBundle = Join-Path $installedCaDir 'server-ca-bundle.pem'
if (-not (Test-Path -LiteralPath $packagedCaBundle)) { throw 'Packaged AJNAT server CA bundle is missing' }
$actualCaSha256 = (Get-FileHash -LiteralPath $packagedCaBundle -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualCaSha256 -ne '${caBundle.sha256}') { throw 'Packaged AJNAT server CA bundle failed SHA-256 verification' }
New-Item -ItemType Directory -Path $installedCaDir -Force | Out-Null
Copy-Item -LiteralPath $packagedCaBundle -Destination $installedCaBundle -Force

$pem = Get-Content -LiteralPath $installedCaBundle -Raw
$pemCertificates = [regex]::Matches($pem, '-----BEGIN CERTIFICATE-----[\\s\\S]+?-----END CERTIFICATE-----')
if ($pemCertificates.Count -eq 0) { throw 'AJNAT server CA bundle contains no certificates' }
foreach ($pemCertificate in $pemCertificates) {
    $base64 = $pemCertificate.Value.Replace('-----BEGIN CERTIFICATE-----', '').Replace('-----END CERTIFICATE-----', '') -replace '\\s', ''
    $certificateBytes = [Convert]::FromBase64String($base64)
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$certificateBytes)
    $isCertificateAuthority = $false
    foreach ($extension in $certificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.19') {
            $basicConstraints = New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension
            $basicConstraints.CopyFrom($extension)
            $isCertificateAuthority = $basicConstraints.CertificateAuthority
        }
    }
    if (-not $isCertificateAuthority) { throw "Refusing to trust non-CA certificate $($certificate.Subject)" }
    $storeName = if ($certificate.Subject -eq $certificate.Issuer) { 'Root' } else { 'CA' }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $alreadyInstalled = @($store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint }).Count -gt 0
        if (-not $alreadyInstalled) { $store.Add($certificate) }
    } finally {
        $store.Close()
        $certificate.Dispose()
    }
}
& icacls.exe $installedCaBundle /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure AJNAT server CA bundle (exit code $LASTEXITCODE)" }
Write-Host "  OK: AJNAT server CA configured and trusted" -ForegroundColor Green
`;
}

function windowsPublisherProvisionSnippet(publisherCertificate) {
  if (!publisherCertificate) return '';
  return `
# -- Local-test AJNAT publisher trust provisioning --
$CurrentOperation = "install-ajnat-publisher-certificate"
$packagedPublisherCertificate = Join-Path $InstallDir 'certs\\AJNAT-Local-Test-Publisher.cer'
$installedCertificateDir = Join-Path $env:ProgramData 'AJNAT\\certs'
$installedPublisherCertificate = Join-Path $installedCertificateDir 'AJNAT-Local-Test-Publisher.cer'
if (-not (Test-Path -LiteralPath $packagedPublisherCertificate)) { throw 'Packaged AJNAT publisher certificate is missing' }
$actualPublisherSha256 = (Get-FileHash -LiteralPath $packagedPublisherCertificate -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualPublisherSha256 -ne '${publisherCertificate.sha256}') { throw 'Packaged AJNAT publisher certificate failed SHA-256 verification' }
New-Item -ItemType Directory -Path $installedCertificateDir -Force | Out-Null
Copy-Item -LiteralPath $packagedPublisherCertificate -Destination $installedPublisherCertificate -Force
$publisherCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $installedPublisherCertificate
if ($publisherCertificate.Thumbprint -ne '${publisherCertificate.thumbprint}') { throw 'AJNAT publisher certificate thumbprint mismatch' }
foreach ($publisherStoreName in @('Root', 'TrustedPublisher')) {
    $publisherStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($publisherStoreName, 'LocalMachine')
    try {
        $publisherStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $alreadyTrusted = @($publisherStore.Certificates | Where-Object { $_.Thumbprint -eq $publisherCertificate.Thumbprint }).Count -gt 0
        if (-not $alreadyTrusted) { $publisherStore.Add($publisherCertificate) }
    } finally {
        $publisherStore.Close()
    }
}
$publisherCertificate.Dispose()
& icacls.exe $installedPublisherCertificate /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure AJNAT publisher certificate (exit code $LASTEXITCODE)" }
Write-Host "  OK: AJNAT publisher certificate configured and trusted" -ForegroundColor Green
`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Find the bundled agent source directory (latest fixed version)
// ─────────────────────────────────────────────────────────────────────────────
function findAgentDir() {
  const candidates = [
    // ── Repo source first: every dashboard package must use the latest code ──
    path.resolve(__dirname, '..', 'soc-agent'),                // backend/soc-agent  ← latest source
    path.resolve(process.cwd(), 'soc-agent'),
    path.resolve(process.cwd(), '..', 'soc-agent'),
    path.resolve(__dirname, '..', '..', 'soc-agent'),          // alongside backend/
    // ── Custom agent folder (soc-Anant) ─────────────────────────────────────
    path.resolve(__dirname, '..', 'soc-Anant'),                // backend/soc-Anant  ← custom deployment
    path.resolve(__dirname, '..', '..', 'soc-Anant'),          // alongside backend/
    path.resolve(process.cwd(), 'soc-Anant'),
    path.resolve(process.cwd(), '..', 'soc-Anant'),
    path.resolve(require('os').homedir(), 'Downloads', 'soc4', 'soc-Anant'),
    path.resolve(require('os').homedir(), 'Downloads', 'soc-Anant'),
    // ── Standard agent folders ───────────────────────────────────────────────
    path.resolve(__dirname, '..', '..', 'fixed-agent-v2'),     // dev directory name
    path.resolve(process.cwd(), '..', 'fixed-agent-v2'),
    path.resolve(require('os').homedir(), 'Downloads', 'soc4', 'fixed-agent-v2'),
    path.resolve(require('os').homedir(), 'Downloads', 'soc-agent'),
    path.resolve(require('os').homedir(), 'Downloads', 'fixed-agent-v2'),
    '/opt/soc-Anant',
    '/opt/soc-agent',
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p) && fs.statSync(p).isDirectory()) return p;
    } catch { /* skip */ }
  }
  return null;
}

function requireAgentDir() {
  const agentDir = findAgentDir();
  if (!agentDir) {
    throw new Error('SOC Agent source directory was not found; refusing to build an empty installer');
  }
  const missing = REQUIRED_AGENT_FILES.filter(relative => {
    const candidate = path.join(agentDir, ...relative.split('/'));
    try {
      return !fs.statSync(candidate).isFile() || fs.statSync(candidate).size === 0;
    } catch {
      return true;
    }
  });
  if (missing.length) {
    throw new Error(`SOC Agent source is incomplete; missing required files: ${missing.join(', ')}`);
  }
  return agentDir;
}

// ─────────────────────────────────────────────────────────────────────────────
// Collect agent files recursively, skip runtime artifacts
// ─────────────────────────────────────────────────────────────────────────────
const SKIP_DIRS  = new Set(['__pycache__', '.git', '.DS_Store', 'node_modules', '.gitignore', 'venv', '.venv', 'tests']);
const SKIP_FILES = new Set(['agent_state.json', 'vt_cache.json', '.probe', 'integrity_manifest.json']);

function collectFiles(dir, prefix) {
  prefix = prefix || '';
  if (!dir || !fs.existsSync(dir)) return [];
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
    if (SKIP_FILES.has(entry.name)) continue;
    if (entry.name.endsWith('.pyc') || entry.name.endsWith('.pyo')) continue;
    const full = path.join(dir, entry.name);
    const rel  = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      results.push(...collectFiles(full, rel));
    } else {
      try {
        results.push({ full, rel, content: fs.readFileSync(full) });
      } catch { /* skip unreadable */ }
    }
  }
  return results;
}

function collectAgentFiles() {
  const agentDir = requireAgentDir();
  const files = collectFiles(agentDir);
  if (files.length < REQUIRED_AGENT_FILES.length) {
    throw new Error('SOC Agent source inventory is incomplete; installer build cancelled');
  }
  return files;
}

function createIntegrityManifest(files) {
  const protectedFiles = {};
  for (const file of files) {
    const relative = String(file.rel || '').replace(/\\/g, '/');
    if (!relative.endsWith('.py')) continue;
    protectedFiles[relative] = crypto.createHash('sha256').update(file.content).digest('hex');
  }
  const aggregate = crypto.createHash('sha256');
  for (const relative of Object.keys(protectedFiles).sort()) {
    aggregate.update(`${relative}\0${protectedFiles[relative]}\n`, 'utf8');
  }
  return {
    version: 1,
    algorithm: 'sha256',
    files: protectedFiles,
    fleetSha256: aggregate.digest('hex'),
  };
}

function integrityManifestBuffer(files) {
  return Buffer.from(`${JSON.stringify(createIntegrityManifest(files), null, 2)}\n`, 'utf8');
}

function getAgentIntegrityManifest() {
  return createIntegrityManifest(collectAgentFiles());
}

// ─────────────────────────────────────────────────────────────────────────────
// Add agent files to zip under zipRoot/ prefix
// ─────────────────────────────────────────────────────────────────────────────
function addAgentFiles(zip, files, zipRoot) {
  for (const f of files) {
    // Skip the config file — we inject a pre-filled one
    if (f.rel === 'config/company_config.json') continue;

    const relNorm  = f.rel.replace(/\\/g, '/');
    const dirPart  = relNorm.includes('/') ? relNorm.substring(0, relNorm.lastIndexOf('/')) : '';
    const fileName = path.basename(relNorm);

    const entryName = dirPart
      ? `${zipRoot}/${dirPart}/${fileName}`
      : `${zipRoot}/${fileName}`;

    zip.addFile(entryName, f.content);
  }
  zip.addFile(`${zipRoot}/integrity_manifest.json`, integrityManifestBuffer(files));
}

function writeAgentFilesToDir(targetDir, files) {
  for (const f of files) {
    if (f.rel === 'config/company_config.json') continue;
    const relNorm = f.rel.replace(/\\/g, '/');
    const dest = path.join(targetDir, relNorm);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, f.content);
  }
  fs.writeFileSync(path.join(targetDir, 'integrity_manifest.json'), integrityManifestBuffer(files));
}

function chmodPackageTree(rootDir) {
  if (!fs.existsSync(rootDir)) return;
  for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
    const full = path.join(rootDir, entry.name);
    if (entry.isDirectory()) chmodPackageTree(full);
    else fs.chmodSync(full, entry.name.endsWith('.sh') || entry.name.endsWith('.py') ? 0o755 : 0o644);
  }
}

function findVelociraptorBundle(type) {
  const baseCandidates = [
    process.env.VELOCIRAPTOR_CLIENT_BUNDLE_DIR,
    path.resolve(__dirname, '..', '..', '..', 'velociraptor', 'client_bundles'),
    path.resolve(process.cwd(), 'velociraptor', 'client_bundles'),
    path.resolve(process.cwd(), '..', 'velociraptor', 'client_bundles'),
    '/opt/velociraptor/client_bundles',
  ].filter(Boolean);

  const namesByType = {
    deb: ['linux/velociraptor_client_amd64.deb'],
    rpm: ['linux/velociraptor_client_amd64.rpm'],
    linuxBin: ['linux/velociraptor_client_amd64_repacked'],
    winExe: ['windows/velociraptor_client_repacked.exe'],
    winMsi: ['windows/velociraptor_client_repacked.msi'],
  };

  for (const base of baseCandidates) {
    for (const rel of namesByType[type] || []) {
      const candidate = path.join(base, rel);
      try {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          fs.accessSync(candidate, fs.constants.R_OK);
          return candidate;
        }
      } catch { /* skip unreadable bundle */ }
    }
  }
  return '';
}

function getWindowsVelociraptorBundle() {
  const exe = findVelociraptorBundle('winExe');
  if (exe) return { path: exe, extension: 'exe' };
  const msi = findVelociraptorBundle('winMsi');
  return msi ? { path: msi, extension: 'msi' } : null;
}

function copyVelociraptorBundle(targetDir, type) {
  const src = findVelociraptorBundle(type);
  if (!src) return false;
  const destDir = path.join(targetDir, 'velociraptor');
  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, path.join(destDir, path.basename(src)));
  return true;
}

function addVelociraptorBundleToZip(zip, zipRoot, type) {
  const src = findVelociraptorBundle(type);
  if (!src) return false;
  zip.addLocalFile(src, `${zipRoot}/velociraptor`);
  return true;
}

function packageVersion(version) {
  return String(version || DEFAULT_AGENT_VERSION)
    .replace(/^[^0-9]+/, '')
    .replace(/[^0-9A-Za-z.+~]/g, '.')
    || DEFAULT_AGENT_VERSION;
}

function shellSingleQuote(value) {
  return `'${String(value ?? '').replace(/'/g, `'\\''`)}'`;
}

function powershellSingleQuote(value) {
  return `'${String(value ?? '').replace(/'/g, "''")}'`;
}

function linuxRoleGuardSnippet() {
  return `
# ── Prevent system/server agent mismatch ─────────────────────────────────────
CONFIG_FILE="$INSTALL_DIR/config/company_config.json"
EXPECTED_ROLE="system"
if [ -f "$CONFIG_FILE" ]; then
  EXPECTED_ROLE="$(grep -o '"expected_device_role"[[:space:]]*:[[:space:]]*"[^"]*' "$CONFIG_FILE" | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]')"
  [ -n "$EXPECTED_ROLE" ] || EXPECTED_ROLE="$(grep -o '"agent_type"[[:space:]]*:[[:space:]]*"[^"]*' "$CONFIG_FILE" | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]')"
  [ -n "$EXPECTED_ROLE" ] || EXPECTED_ROLE="system"
fi
ACTUAL_ROLE="system"
if [ "$(uname -s)" = "Linux" ]; then
  CHASSIS="$(cat /sys/class/dmi/id/chassis_type 2>/dev/null || true)"
  TARGET="$(systemctl get-default 2>/dev/null || true)"
  if echo " 11 12 17 23 28 29 30 31 32 " | grep -q " $CHASSIS "; then
    ACTUAL_ROLE="server"
  elif [ "$TARGET" = "multi-user.target" ] && ! command -v gnome-shell >/dev/null 2>&1 && ! command -v startplasma-x11 >/dev/null 2>&1 && ! command -v startxfce4 >/dev/null 2>&1; then
    ACTUAL_ROLE="server"
  fi
fi
if [ "$EXPECTED_ROLE" = "server" ] || [ "$EXPECTED_ROLE" = "system" ]; then
  if [ "$EXPECTED_ROLE" != "$ACTUAL_ROLE" ]; then
    echo "ERROR: Agent type mismatch. This package is for $EXPECTED_ROLE, but this machine looks like $ACTUAL_ROLE." >&2
    echo "Download the correct agent from SOC Dashboard." >&2
    exit 1
  fi
fi
`;
}

function linuxVelociraptorInstallSnippet(pkgMgr = 'apt') {
  return `
# ── Velociraptor client auto-install/enroll ──────────────────────────────────
install_velociraptor_client() {
  if command -v velociraptor_client >/dev/null 2>&1 || command -v velociraptor >/dev/null 2>&1; then
    echo "Velociraptor client already installed"
    systemctl enable velociraptor_client >/dev/null 2>&1 || true
    systemctl restart velociraptor_client >/dev/null 2>&1 || true
    systemctl enable velociraptor >/dev/null 2>&1 || true
    systemctl restart velociraptor >/dev/null 2>&1 || true
    return 0
  fi

  BUNDLE_DIR="$INSTALL_DIR/velociraptor"
  if command -v dpkg >/dev/null 2>&1 && ls "$BUNDLE_DIR"/*.deb >/dev/null 2>&1; then
    echo "Installing bundled Velociraptor client (.deb)..."
    dpkg -i "$BUNDLE_DIR"/*.deb >/dev/null 2>&1 || {
      apt-get update -qq >/dev/null 2>&1 || true
      apt-get install -f -y >/dev/null 2>&1 || true
      dpkg -i "$BUNDLE_DIR"/*.deb >/dev/null 2>&1 || true
    }
  elif command -v rpm >/dev/null 2>&1 && ls "$BUNDLE_DIR"/*.rpm >/dev/null 2>&1; then
    echo "Installing bundled Velociraptor client (.rpm)..."
    rpm -Uvh --replacepkgs "$BUNDLE_DIR"/*.rpm >/dev/null 2>&1 || true
  elif ls "$BUNDLE_DIR"/velociraptor_client_* >/dev/null 2>&1; then
    echo "Installing bundled Velociraptor client binary..."
    install -m 755 "$(ls "$BUNDLE_DIR"/velociraptor_client_* | head -n1)" /usr/local/bin/velociraptor_client
  else
    echo "Velociraptor client bundle not found; skipping auto-install"
    return 0
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable velociraptor_client >/dev/null 2>&1 || true
  systemctl restart velociraptor_client >/dev/null 2>&1 || true
  systemctl enable velociraptor >/dev/null 2>&1 || true
  systemctl restart velociraptor >/dev/null 2>&1 || true
}
install_velociraptor_client || true
`;
}

function windowsVelociraptorInstallSnippet() {
  return `
# -- Velociraptor client auto-install/enroll --
function Install-AjnatVelociraptorClient {
    $velociraptorServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Velociraptor*' })
    if ($velociraptorServices.Count -gt 0) {
        foreach ($velociraptorService in $velociraptorServices) {
            & sc.exe config $velociraptorService.Name start= auto 2>&1 | Out-Null
            if ($velociraptorService.Status -ne 'Running') {
                Start-Service -Name $velociraptorService.Name -ErrorAction Stop
            }
        }
        Write-Host "  OK: Velociraptor client service is installed and running" -ForegroundColor Green
        return
    }

    $bundleDir = Join-Path $InstallDir 'velociraptor'
    $msiBundle = @(Get-ChildItem -LiteralPath $bundleDir -Filter '*.msi' -File -ErrorAction SilentlyContinue | Select-Object -First 1)
    $exeBundle = @(Get-ChildItem -LiteralPath $bundleDir -Filter '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($msiBundle.Count -eq 0 -and $exeBundle.Count -eq 0) {
        Write-Host "  Downloading Velociraptor enrollment client from AJNAT server ..." -ForegroundColor Yellow
        $agentConfigPath = Join-Path $env:ProgramData 'AJNAT\\config\\company_config.json'
        if (-not (Test-Path -LiteralPath $agentConfigPath)) { throw 'AJNAT enrollment configuration is missing' }
        $agentConfig = Get-Content -LiteralPath $agentConfigPath -Raw | ConvertFrom-Json
        $serverUrl = ([string]$agentConfig.server_url).TrimEnd('/')
        $agentKey = [Uri]::EscapeDataString([string]$agentConfig.agent_key)
        if (-not $serverUrl -or -not $agentKey) { throw 'AJNAT server URL or agent key is missing' }
        New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null
        $downloadedBundle = Join-Path $bundleDir 'velociraptor_client_repacked.exe'
        $dependencyUrl = "$serverUrl/api/agent/self-update/dependency/velociraptor/windows?agent_key=$agentKey"
        $headers = @{}
        if ($agentConfig.integration_secret) { $headers['x-integration-secret'] = [string]$agentConfig.integration_secret }
        $downloadResponse = $null
        $downloadError = $null
        # Retry transient AJNAT connectivity without ever accepting a partial file.
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Remove-Item -LiteralPath $downloadedBundle -Force -ErrorAction SilentlyContinue
                $downloadResponse = Invoke-WebRequest -Uri $dependencyUrl -Headers $headers -OutFile $downloadedBundle -UseBasicParsing -TimeoutSec 300
                $downloadError = $null
                break
            } catch {
                $downloadError = $_.Exception.Message
                if ($attempt -lt 3) { Start-Sleep -Seconds (5 * $attempt) }
            }
        }
        if ($downloadError) { throw "AJNAT dependency download failed after 3 attempts: $downloadError" }
        if (-not (Test-Path -LiteralPath $downloadedBundle) -or (Get-Item -LiteralPath $downloadedBundle).Length -lt 1MB) {
            throw 'Downloaded Velociraptor enrollment client is incomplete'
        }
        $expectedSha256 = [string]$downloadResponse.Headers['X-AJNAT-Artifact-SHA256']
        if ($expectedSha256) {
            $actualSha256 = (Get-FileHash -LiteralPath $downloadedBundle -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualSha256 -ne $expectedSha256.Trim().ToLowerInvariant()) {
                Remove-Item -LiteralPath $downloadedBundle -Force -ErrorAction SilentlyContinue
                throw 'Downloaded Velociraptor enrollment client failed SHA-256 verification'
            }
        }
        $exeBundle = @(Get-Item -LiteralPath $downloadedBundle)
    }
    if ($msiBundle.Count -gt 0) {
        Write-Host "  Installing bundled Velociraptor client (MSI) ..." -ForegroundColor Yellow
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $msiBundle[0].FullName, '/qn', '/norestart') -Wait -PassThru
        if (@(0, 1641, 3010) -notcontains $process.ExitCode) {
            throw "Velociraptor MSI installation failed with exit code $($process.ExitCode)"
        }
    } elseif ($exeBundle.Count -gt 0) {
        Write-Host "  Installing bundled Velociraptor client service ..." -ForegroundColor Yellow
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & $exeBundle[0].FullName service install 2>&1
            $code = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedPreference
        }
        if ($output) { $output | ForEach-Object { Write-Host "  $_" } }
        if ($code -ne 0) { throw "Velociraptor service installation failed with exit code $code" }
    } else { throw 'Velociraptor enrollment client is unavailable' }

    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Seconds 1
        $velociraptorServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Velociraptor*' })
    } while ($velociraptorServices.Count -eq 0 -and (Get-Date) -lt $deadline)
    if ($velociraptorServices.Count -eq 0) {
        throw 'Velociraptor installer completed but did not register a Windows service'
    }
    foreach ($velociraptorService in $velociraptorServices) {
        & sc.exe config $velociraptorService.Name start= auto 2>&1 | Out-Null
        if ($velociraptorService.Status -ne 'Running') {
            Start-Service -Name $velociraptorService.Name -ErrorAction Stop
        }
        (Get-Service -Name $velociraptorService.Name -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    Write-Host "  OK: Velociraptor client installed; enrollment starts on first server connection" -ForegroundColor Green
}
Install-AjnatVelociraptorClient
`;
}

function linuxNetworkSensorInstallSnippet() {
  return `
# ── Suricata NFQUEUE inline IPS + Zeek sensor install ────────────────────────────
install_network_sensors() {
  if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then
    echo "Suricata/Zeek auto-install is Linux-only; skipping"
    return 0
  fi
  if [ "\${SOC_INSTALL_NETWORK_SENSORS:-true}" = "false" ]; then
    echo "Suricata inline IPS/Zeek auto-install explicitly disabled"
    return 0
  fi
  IDS_INSTALLER="$INSTALL_DIR/install-ids-sensors.sh"
  if [ ! -f "$IDS_INSTALLER" ]; then
    echo "ERROR: Suricata inline IPS installer missing"
    return 1
  fi
  chmod +x "$IDS_INSTALLER" 2>/dev/null || true
  echo "Installing and configuring Suricata NFQUEUE inline IPS and Zeek..."
  SOC_SURICATA_MODE=ips bash "$IDS_INSTALLER"
}
install_network_sensors
`;
}

function linuxLocationProviderInstallSnippet() {
  return `
# ── Native device location provider (policy-gated at runtime) ────────────────
LOCATION_INSTALLER="$INSTALL_DIR/install-linux-location-provider.sh"
if [ ! -f "$LOCATION_INSTALLER" ]; then
  echo "ERROR: AJNAT Linux location-provider installer is missing" >&2
  exit 1
fi
chmod 700 "$LOCATION_INSTALLER"
"$LOCATION_INSTALLER"
`;
}

function windowsLocationProviderInstallSnippet() {
  return `
# -- Native Windows Location Services setup (telemetry remains policy-gated) --
$locationPolicyPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors'
$locationPolicyDisabled = $false
if (Test-Path -LiteralPath $locationPolicyPath) {
    $locationPolicy = Get-ItemProperty -LiteralPath $locationPolicyPath -ErrorAction SilentlyContinue
    $locationPolicyDisabled = $locationPolicy.DisableLocation -eq 1 -or $locationPolicy.DisableWindowsLocationProvider -eq 1
}
if ($locationPolicyDisabled) {
    Write-Warning 'Windows Location Services are disabled by Group Policy; AJNAT will report permission_denied and will not bypass the policy.'
} else {
    $locationService = Get-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
    if ($locationService) {
        try {
            Set-Service -Name 'lfsvc' -StartupType Manual
            Start-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Windows Location Service could not be started: $($_.Exception.Message)"
        }
    }
    $locationConsentPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location'
    New-Item -Path $locationConsentPath -Force | Out-Null
    New-ItemProperty -Path $locationConsentPath -Name 'Value' -Value 'Allow' -PropertyType String -Force | Out-Null
    Write-Host '  OK: Windows native Location Services are enabled; AJNAT transmission remains controlled by company GPS policy.' -ForegroundColor Green
}
`;
}

function macLocationProviderInstallSnippet() {
  return `
# ── Native macOS CoreLocation bridge (TCC permission remains OS-controlled) ──
if ! "$PYTHON" -c 'import CoreLocation, objc' >/dev/null 2>&1; then
  echo "ERROR: macOS CoreLocation Python bridge is unavailable" >&2
  exit 1
fi
echo "  OK: macOS CoreLocation provider installed"
echo "  INFO: macOS Location Services permission must allow AJNAT/Python; enterprise TCC policy is never bypassed"
`;
}

function windowsRoleGuardSnippet() {
  return `
# -- Prevent system/server agent mismatch --
$RoleConfigPath = @(
    (Join-Path $env:ProgramData "AJNAT\\config\\company_config.json"),
    (Join-Path $InstallDir "config\\company_config.json")
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$ExpectedRole = "system"
if ($RoleConfigPath) {
    try {
        $Cfg = Get-Content $RoleConfigPath -Raw | ConvertFrom-Json
        if ($Cfg.expected_device_role) { $ExpectedRole = [string]$Cfg.expected_device_role }
        elseif ($Cfg.agent_type) { $ExpectedRole = [string]$Cfg.agent_type }
        $ExpectedRole = $ExpectedRole.ToLowerInvariant()
    } catch {}
}
$ActualRole = "system"
try {
    $OsInfo = Get-CimInstance Win32_OperatingSystem
    if ($OsInfo.ProductType -ne 1) { $ActualRole = "server" }
} catch {
    try {
        $OsInfo = Get-WmiObject Win32_OperatingSystem
        if ($OsInfo.ProductType -ne 1) { $ActualRole = "server" }
    } catch {}
}
if (($ExpectedRole -eq "server" -or $ExpectedRole -eq "system") -and $ExpectedRole -ne $ActualRole) {
    Write-Host "ERROR: Agent type mismatch. This package is for $ExpectedRole, but this machine looks like $ActualRole." -ForegroundColor Red
    Write-Host "Download the correct agent from SOC Dashboard." -ForegroundColor Yellow
    exit 1
}
`;
}

function macRoleGuardSnippet() {
  return `
# ── Prevent system/server agent mismatch ─────────────────────────────────────
CONFIG_FILE="$INSTALL_DIR/config/company_config.json"
EXPECTED_ROLE="system"
if [ -f "$CONFIG_FILE" ]; then
  EXPECTED_ROLE="$(grep -o '"expected_device_role"[[:space:]]*:[[:space:]]*"[^"]*' "$CONFIG_FILE" | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]')"
  [ -n "$EXPECTED_ROLE" ] || EXPECTED_ROLE="$(grep -o '"agent_type"[[:space:]]*:[[:space:]]*"[^"]*' "$CONFIG_FILE" | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]')"
  [ -n "$EXPECTED_ROLE" ] || EXPECTED_ROLE="system"
fi
ACTUAL_ROLE="system"
if [ "$EXPECTED_ROLE" = "server" ]; then
  echo "ERROR: Server agent cannot be installed on macOS system package." >&2
  echo "Download the correct agent from SOC Dashboard." >&2
  exit 1
fi
if [ "$EXPECTED_ROLE" = "system" ] && [ "$ACTUAL_ROLE" != "system" ]; then
  echo "ERROR: Agent type mismatch. This package is for $EXPECTED_ROLE, but this machine looks like $ACTUAL_ROLE." >&2
  exit 1
fi
`;
}

function windowsNativeIpsBootstrapSnippet() {
  return `
# -- Native IPS firewall bootstrap --
# Windows Defender Firewall is the packet-enforcement backend for this agent.
# Enabling profiles preserves existing rules; SOC creates only its own
# per-indicator block rules when a validated IDS/IPS detection occurs.
Write-Host "Configuring native IPS firewall enforcement ..." -ForegroundColor Yellow
$profileState = & netsh.exe advfirewall show allprofiles state 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Windows Defender Firewall is unavailable; native IPS cannot enforce blocks."
}

if (($profileState | Out-String) -match "State[[:space:]]+OFF") {
    & netsh.exe advfirewall set allprofiles state on | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not enable Windows Defender Firewall profiles for native IPS."
    }
    $profileState = & netsh.exe advfirewall show allprofiles state 2>&1
}
New-Item -ItemType Directory -Path "$InstallDir\\state" -Force | Out-Null
@{
    platform = "Windows"
    backend = "windows-defender-firewall"
    mode = "native-ip-block-after-detection"
    inline_packet_verdict = $false
    configured_at = (Get-Date).ToUniversalTime().ToString("o")
    profiles = ($profileState | Out-String).Trim()
} | ConvertTo-Json | Set-Content -Path "$InstallDir\\state\\ips-enforcement.json" -Encoding UTF8
Write-Host "  OK: Windows Defender Firewall native IPS is ready" -ForegroundColor Green
`;
}

function windowsNetworkSensorInstallSnippet() {
  const rawSuricataInstallerUrl = String(process.env.AJNAT_SURICATA_INSTALLER_URL || '').trim();
  const rawSuricataInstallerSha256 = String(process.env.AJNAT_SURICATA_INSTALLER_SHA256 || '').trim();
  if (rawSuricataInstallerUrl && !/^[a-f0-9]{64}$/i.test(rawSuricataInstallerSha256)) {
    throw new Error('AJNAT_SURICATA_INSTALLER_SHA256 must be a 64-character SHA-256 when a custom Suricata installer URL is configured');
  }
  const suricataInstallerUrl = powershellSingleQuote(rawSuricataInstallerUrl);
  const suricataInstallerSha256 = powershellSingleQuote(rawSuricataInstallerSha256);
  const requireInlineIps = String(process.env.AJNAT_REQUIRE_WINDOWS_INLINE_IPS || '').toLowerCase() === 'true';
  return `
# -- Inline packet IPS bootstrap (Suricata + WinDivert) --
$sensorInstaller = Join-Path $InstallDir 'install-windows-ids.ps1'
if (-not (Test-Path -LiteralPath $sensorInstaller)) {
    throw 'Windows Suricata/WinDivert installer is missing from the agent package'
}
$suricataInstallerUrl = ${suricataInstallerUrl}
$suricataInstallerSha256 = ${suricataInstallerSha256}
$sensorArguments = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $sensorInstaller,
    '-InstallDir', $InstallDir, '-DataDir', (Join-Path $env:ProgramData 'AJNAT')
)
if ($IsUpdate) { $sensorArguments += '-SkipRuleUpdate' }
${requireInlineIps ? '' : "$sensorArguments += '-Optional'"}
if ($suricataInstallerUrl) {
    $sensorArguments += @(
        '-SuricataInstallerUrl', $suricataInstallerUrl,
        '-SuricataInstallerSha256', $suricataInstallerSha256
    )
}
& powershell.exe @sensorArguments
if ($LASTEXITCODE -ne 0) {
    throw "Windows Suricata/WinDivert inline IPS setup failed with exit code $LASTEXITCODE"
}
`;
}

function windowsAdvancedProcessTelemetrySnippet() {
  return `
# -- Native Windows process/task/service audit bootstrap --
$advancedTelemetryInstaller = Join-Path $InstallDir 'install-windows-advanced-telemetry.ps1'
if (Test-Path -LiteralPath $advancedTelemetryInstaller) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $advancedTelemetryInstaller -InstallDir $InstallDir
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Advanced process telemetry setup returned exit code $LASTEXITCODE; agent health will report degraded coverage."
    }
} else {
    Write-Warning 'Advanced process telemetry setup script is missing; coverage will be degraded.'
}
`;
}

function macNativeIpsBootstrapSnippet() {
  return `
# ── Native IPS firewall bootstrap ───────────────────────────────────────────
# Keep SOC rules in a dedicated PF anchor so existing PF rules remain intact.
PF_CONF="/etc/pf.conf"
PF_ANCHOR="/etc/pf.anchors/com.soc.agent"
PF_ISOLATION_ANCHOR="/etc/pf.anchors/com.soc.agent.isolation"
PF_ANCHOR_NAME="com.soc.agent"
PF_ANCHOR_LINE='anchor "com.soc.agent"'
PF_LOAD_LINE='load anchor "com.soc.agent" from "/etc/pf.anchors/com.soc.agent"'
PF_ISOLATION_LINE='anchor "com.soc.agent/isolation"'
PF_ISOLATION_LOAD_LINE='load anchor "com.soc.agent/isolation" from "/etc/pf.anchors/com.soc.agent.isolation"'

echo "Configuring native IPS firewall enforcement ..."
mkdir -p /etc/pf.anchors "$INSTALL_DIR/state"
if [ ! -f "$PF_ANCHOR" ]; then
  cat > "$PF_ANCHOR" <<'PFEOF'
table <soc_blocklist> persist
block drop quick from <soc_blocklist> to any
block drop quick from any to <soc_blocklist>
PFEOF
else
  grep -Fqx 'table <soc_blocklist> persist' "$PF_ANCHOR" || printf '%s\n' 'table <soc_blocklist> persist' >> "$PF_ANCHOR"
  grep -Fqx 'block drop quick from <soc_blocklist> to any' "$PF_ANCHOR" || printf '%s\n' 'block drop quick from <soc_blocklist> to any' >> "$PF_ANCHOR"
  grep -Fqx 'block drop quick from any to <soc_blocklist>' "$PF_ANCHOR" || printf '%s\n' 'block drop quick from any to <soc_blocklist>' >> "$PF_ANCHOR"
fi
chmod 600 "$PF_ANCHOR"
[ -f "$PF_ISOLATION_ANCHOR" ] || printf '%s\n' '# AJNAT isolation inactive' > "$PF_ISOLATION_ANCHOR"
chmod 600 "$PF_ISOLATION_ANCHOR"

[ -f "$PF_CONF" ] || touch "$PF_CONF"
cp "$PF_CONF" "$PF_CONF.soc-agent.bak" 2>/dev/null || true
grep -Fqx "$PF_ANCHOR_LINE" "$PF_CONF" || printf '\n%s\n' "$PF_ANCHOR_LINE" >> "$PF_CONF"
grep -Fqx "$PF_LOAD_LINE" "$PF_CONF" || printf '%s\n' "$PF_LOAD_LINE" >> "$PF_CONF"
grep -Fqx "$PF_ISOLATION_LINE" "$PF_CONF" || printf '%s\n' "$PF_ISOLATION_LINE" >> "$PF_CONF"
grep -Fqx "$PF_ISOLATION_LOAD_LINE" "$PF_CONF" || printf '%s\n' "$PF_ISOLATION_LOAD_LINE" >> "$PF_CONF"
pfctl -nf "$PF_CONF"
pfctl -f "$PF_CONF"
pfctl -E >/dev/null 2>&1 || true
pfctl -a "$PF_ANCHOR_NAME" -t soc_blocklist -T show >/dev/null
cat > "$INSTALL_DIR/state/ips-enforcement.json" <<EOF
{"platform":"macOS","backend":"pf","mode":"native-ip-block-after-detection","inline_packet_verdict":false}
EOF
chmod 600 "$INSTALL_DIR/state/ips-enforcement.json"
echo "  OK: macOS PF native IPS is ready"
`;
}

function macNativeIpsCleanupSnippet() {
  return `
# Remove only the SOC-owned PF anchor references and table.
PF_CONF="/etc/pf.conf"
PF_ANCHOR="/etc/pf.anchors/com.soc.agent"
PF_ISOLATION_ANCHOR="/etc/pf.anchors/com.soc.agent.isolation"
if [ -f "$PF_CONF" ]; then
  sed -i.bak '/^anchor "com\\.soc\\.agent"$/d; /^load anchor "com\\.soc\\.agent" from "\\/etc\\/pf\\.anchors\\/com\\.soc\\.agent"$/d; /^anchor "com\\.soc\\.agent\\/isolation"$/d; /^load anchor "com\\.soc\\.agent\\/isolation" from "\\/etc\\/pf\\.anchors\\/com\\.soc\\.agent\\.isolation"$/d' "$PF_CONF" 2>/dev/null || true
  pfctl -f "$PF_CONF" >/dev/null 2>&1 || true
fi
rm -f "$PF_ANCHOR" "$PF_ISOLATION_ANCHOR"
`;
}

function solarisRoleGuardSnippet() {
  return `
# ── Prevent system/server agent mismatch ─────────────────────────────────────
CONFIG_FILE="$INSTALL_DIR/config/company_config.json"
EXPECTED_ROLE="server"
if [ -f "$CONFIG_FILE" ]; then
  EXPECTED_ROLE="$(grep -o '"expected_device_role"[[:space:]]*:[[:space:]]*"[^"]*' "$CONFIG_FILE" | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]')"
  [ -n "$EXPECTED_ROLE" ] || EXPECTED_ROLE="$(grep -o '"agent_type"[[:space:]]*:[[:space:]]*"[^"]*' "$CONFIG_FILE" | cut -d'"' -f4 | tr '[:upper:]' '[:lower:]')"
  [ -n "$EXPECTED_ROLE" ] || EXPECTED_ROLE="server"
fi
if [ "$EXPECTED_ROLE" != "server" ]; then
  echo "ERROR: Solaris package is server-only, but this config is for $EXPECTED_ROLE." >&2
  echo "Download the correct agent from SOC Dashboard." >&2
  exit 1
fi
`;
}

function linuxPostInstallScript(system, company, version, pkgMgr, options = {}) {
  const interactivePassword = options.interactivePassword !== false;
  const companyName = shellSingleQuote(company.name);
  const systemName = shellSingleQuote(system.name);
  return `#!/usr/bin/env bash
set -e
INSTALL_DIR="/opt/soc-agent"
SVC="soc-agent"
VERSION="${version}"

echo "Installing SOC Agent v$VERSION"
echo "Company : ${companyName}"
echo "System  : ${systemName}"

${interactivePassword ? unixPasswordInstallSnippet() : ''}

PYTHON=""
for cmd in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
  command -v "$cmd" >/dev/null 2>&1 && PYTHON="$cmd" && break
done
if [ -z "$PYTHON" ]; then
  ${pkgMgr === 'apt'
    ? 'apt-get update -qq >/dev/null 2>&1 || true\n  apt-get install -y python3 python3-pip python3-venv >/dev/null 2>&1 || true'
    : 'dnf install -y python3 python3-pip >/dev/null 2>&1 || yum install -y python3 python3-pip >/dev/null 2>&1 || true'}
  PYTHON="python3"
fi
SYSTEM_PYTHON="$PYTHON"
VENV_DIR="$INSTALL_DIR/.venv"
if [ ! -x "$VENV_DIR/bin/python3" ]; then
  if ! "$SYSTEM_PYTHON" -m venv "$VENV_DIR"; then
    ${pkgMgr === 'apt'
    ? 'apt-get update -qq >/dev/null 2>&1\n    apt-get install -y python3-venv python3-pip'
    : 'dnf install -y python3-pip >/dev/null 2>&1 || yum install -y python3-pip'}
    "$SYSTEM_PYTHON" -m venv "$VENV_DIR"
  fi
fi
PYTHON="$VENV_DIR/bin/python3"
[ -x "$PYTHON" ] || { echo "ERROR: AJNAT Python runtime was not created." >&2; exit 1; }

chmod +x "$INSTALL_DIR/agent.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true
chown root:root "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chmod 600 "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chown -R root:root "$INSTALL_DIR" 2>/dev/null || true
find "$INSTALL_DIR" -type d -exec chmod 700 {} +
find "$INSTALL_DIR" -type f -exec chmod 600 {} +
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true
if [ -x "$INSTALL_DIR/install-linux-advanced-telemetry.sh" ]; then
  "$INSTALL_DIR/install-linux-advanced-telemetry.sh" || true
fi
${linuxLocationProviderInstallSnippet()}
${linuxRoleGuardSnippet()}
${linuxVelociraptorInstallSnippet(pkgMgr)}
${linuxDepsSnippet(pkgMgr)}
${linuxNetworkSensorInstallSnippet()}
chown -R root:root "$INSTALL_DIR"
chmod -R go-rwx "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true

cat > "/etc/systemd/system/$SVC.service" << SVCEOF
[Unit]
Description=SOC Security Agent v${version} - ${company.name}/${system.name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/agent.py run
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload >/dev/null 2>&1 || true
# A new package preinst may temporarily use KillMode=process to let legacy
# in-service dpkg updaters survive the old package's prerm. Restore the secure
# default before the upgraded service starts.
systemctl set-property --runtime "$SVC.service" KillMode=control-group >/dev/null 2>&1 || true
systemctl enable "$SVC" >/dev/null
systemctl restart "$SVC"
sleep 5
if ! systemctl is-active --quiet "$SVC"; then
  systemctl status "$SVC" --no-pager -l || true
  echo "ERROR: SOC Agent service did not remain active after installation." >&2
  exit 1
fi
"$PYTHON" "$INSTALL_DIR/agent.py" test
echo "SOC Agent v$VERSION installed and verified. Check: systemctl status $SVC"
`;
}

function linuxPreInstallScript() {
  return `#!/usr/bin/env bash
set -e
ACTION="\${1:-install}"
# v3.1.5 and older launched dpkg inside soc-agent.service. During an upgrade,
# the old prerm stops that service; systemd's default KillMode=control-group
# would kill dpkg itself before unpack completes. Keep only the legacy updater
# child alive for this one transition. postinst restores control-group mode.
if [ "$ACTION" = "upgrade" ] && systemctl is-active --quiet soc-agent.service; then
  systemctl set-property --runtime soc-agent.service KillMode=process >/dev/null 2>&1 || true
fi
exit 0
`;
}

function linuxPreRemoveScript(requirePassword = true) {
  return `#!/usr/bin/env bash
set -e
ACTION="\${1:-remove}"
if [ "$ACTION" = "remove" ] || [ "$ACTION" = "purge" ]; then
${requirePassword ? unixPasswordVerifySnippet() : ''}
${linuxUninstallNotificationSnippet()}
fi
systemctl stop soc-agent >/dev/null 2>&1 || true
systemctl disable soc-agent >/dev/null 2>&1 || true
systemctl stop suricata >/dev/null 2>&1 || true
systemctl disable soc-suricata-nfqueue.service >/dev/null 2>&1 || true
systemctl stop soc-suricata-nfqueue.service >/dev/null 2>&1 || true
nft delete table inet soc_suricata_ips >/dev/null 2>&1 || true
rm -f /etc/systemd/system/soc-agent.service
rm -f /etc/systemd/system/soc-suricata-nfqueue.service
rm -f /etc/systemd/system/suricata.service.d/soc-inline-ips.conf
systemctl daemon-reload >/dev/null 2>&1 || true
`;
}

function linuxUninstallNotificationSnippet() {
  return `
# ── Notify dashboard before package files are removed ───────────────────────
CONFIG_FILE="/opt/soc-agent/config/company_config.json"
PYTHON_BIN="/opt/soc-agent/venv/bin/python"
if [ -f "$CONFIG_FILE" ] && [ -x "$PYTHON_BIN" ]; then
  HTTP_CODE="$(PYTHONPATH=/opt/soc-agent "$PYTHON_BIN" - <<'PY' 2>/dev/null || echo 000
from core.config import AgentConfig
from core.secure_transport import secure_request
config = AgentConfig()
system_id = str(config.get('system_id') or '')
server_url = str(config.get('server_url') or '').rstrip('/')
if not system_id or not server_url:
    raise SystemExit('000')
payload = {'agent_key': config.get('agent_key', ''), 'reason': 'Agent package uninstalled'}
response = secure_request(config, 'POST', server_url + '/api/agent/system/' + system_id + '/offline', json=payload, timeout=8)
print(response.status_code)
PY
)"
  if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Dashboard notified. Installed count released."
  else
    echo "WARNING: Dashboard notification failed; uninstall will continue." >&2
  fi
else
  echo "WARNING: Dashboard notification skipped because config or agent Python is unavailable." >&2
fi
`;
}

function linuxPostRemoveScript() {
  return `#!/usr/bin/env bash
set -e
ACTION="\${1:-remove}"
if [ "$ACTION" = "remove" ] || [ "$ACTION" = "purge" ]; then
  rm -rf /opt/soc-agent /var/log/soc-agent /etc/soc-agent
fi
`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sanitize names for filenames
// ─────────────────────────────────────────────────────────────────────────────
function sanitize(name) {
  return (name || 'system').replace(/[^a-zA-Z0-9_.-]/g, '_');
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared Linux dependency install lines (DEB + RPM)
// ─────────────────────────────────────────────────────────────────────────────
function linuxDepsSnippet(pkgMgr) {
  const install = pkgMgr === 'apt'
    ? 'apt-get install -y --quiet'
    : 'dnf install -y';
  const pyudevInstall = pkgMgr === 'apt'
    ? `${install} python3-pyudev 2>/dev/null || true`
    : `${install} python3-pyudev 2>/dev/null || yum install -y python3-pyudev 2>/dev/null || true`;

  return `
# ── Python dependencies ───────────────────────────────────────────────────────
echo "📦  Installing Python dependencies …"
$PYTHON -m pip install --quiet --upgrade pip setuptools wheel
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
  if ! $PYTHON -m pip install --quiet --upgrade -r "$INSTALL_DIR/requirements.txt"; then
    echo "Full requirements install failed; retrying required runtime packages..." >&2
    $PYTHON -m pip install --quiet --upgrade \\
      requests "urllib3<3" psutil watchdog cryptography \\
      "python-socketio[client]" websocket-client yara-python pyudev pynput
  fi
else
  $PYTHON -m pip install --quiet --upgrade \\
    requests "urllib3<3" psutil watchdog cryptography \\
    "python-socketio[client]" websocket-client yara-python pyudev pynput
fi

# pyudev can also come from the OS when a platform wheel is unavailable.
$PYTHON -c 'import pyudev' >/dev/null 2>&1 || ${pyudevInstall}
$PYTHON -c 'import requests, psutil, watchdog, cryptography, socketio, websocket, yara, pyudev'
echo "  ✓ All required Python dependencies installed and verified"
`;
}

function unixPasswordInstallSnippet() {
  return `
# ── Uninstall password protection ───────────────────────────────────────────
PASS_DIR="/etc/soc-agent"
PASS_FILE="$PASS_DIR/uninstall.pass"
hash_password() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf "%s" "$1" | sha256sum | awk '{print $1}'
  else
    printf "%s" "$1" | shasum -a 256 | awk '{print $1}'
  fi
}
setup_uninstall_password() {
  mkdir -p "$PASS_DIR"
  chmod 700 "$PASS_DIR" 2>/dev/null || true
  if [ -f "$PASS_FILE" ]; then
    chmod 600 "$PASS_FILE" 2>/dev/null || true
    echo "  ✓ Existing uninstall password kept"
    return
  fi
  if [ ! -r /dev/tty ]; then
    echo "ERROR: SOC Agent install requires an interactive terminal to set the uninstall password." >&2
    echo "Run the installer from Terminal, for example: sudo apt install ./soc-agent*.deb" >&2
    exit 1
  fi
  echo ""
  echo "🔐  Set uninstall password (required to remove SOC Agent later)"
  while true; do
    read -rsp "Enter uninstall password: " PASS1 </dev/tty; echo ""
    read -rsp "Confirm uninstall password: " PASS2 </dev/tty; echo ""
    if [ -z "$PASS1" ]; then
      echo "Password cannot be empty."
    elif [ "$PASS1" != "$PASS2" ]; then
      echo "Passwords do not match."
    else
      hash_password "$PASS1" > "$PASS_FILE"
      chmod 600 "$PASS_FILE"
      unset PASS1 PASS2
      echo "  ✓ Uninstall password saved"
      break
    fi
  done
}
setup_uninstall_password
`;
}

function unixPasswordVerifySnippet() {
  return `
# ── Require uninstall password ──────────────────────────────────────────────
PASS_FILE="/etc/soc-agent/uninstall.pass"
hash_password() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf "%s" "$1" | sha256sum | awk '{print $1}'
  else
    printf "%s" "$1" | shasum -a 256 | awk '{print $1}'
  fi
}
if [ ! -f "$PASS_FILE" ]; then
  echo "ERROR: uninstall password is not configured." >&2
  echo "Repair/reinstall SOC Agent first so you can set a password, then uninstall again." >&2
  echo "Debian/Kali/Ubuntu: sudo dpkg --install ./soc-agent*.deb" >&2
  exit 1
else
  if [ ! -r /dev/tty ]; then
    echo "ERROR: SOC Agent uninstall requires an interactive terminal for password verification." >&2
    exit 1
  fi
  read -rsp "Enter uninstall password: " UNINSTALL_PASS </dev/tty; echo ""
  ENTERED_HASH="$(hash_password "$UNINSTALL_PASS")"
  SAVED_HASH="$(cat "$PASS_FILE" 2>/dev/null || true)"
  unset UNINSTALL_PASS
  if [ "$ENTERED_HASH" != "$SAVED_HASH" ]; then
    echo "ERROR: incorrect uninstall password."
    exit 1
  fi
  echo "✓ Password matched. Uninstall authorized."
fi
`;
}

function windowsPasswordInstallSnippet({ resetExisting = false } = {}) {
  const keepExistingCondition = resetExisting ? '$false' : '(Test-Path $passFile)';
  return `
# -- Uninstall password protection --
function New-PasswordRecord([string]$Value) {
    $iterations = 210000
    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Value, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try { $hash = $derive.GetBytes(32) } finally { $derive.Dispose() }
    return 'pbkdf2-sha256:{0}:{1}:{2}' -f $iterations, [Convert]::ToBase64String($salt), [Convert]::ToBase64String($hash)
}
function Read-PlainPassword([string]$Prompt) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'SOC Agent Password'
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size(430,170)
    $form.TopMost = $true
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.Location = New-Object System.Drawing.Point(18,18)
    $label.AutoSize = $true
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point(18,48)
    $box.Size = New-Object System.Drawing.Size(378,24)
    $box.UseSystemPasswordChar = $true
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'; $ok.Location = New-Object System.Drawing.Point(238,88); $ok.DialogResult = 'OK'
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(321,88); $cancel.DialogResult = 'Cancel'
    $form.Controls.AddRange(@($label, $box, $ok, $cancel))
    $form.AcceptButton = $ok; $form.CancelButton = $cancel
    $form.Add_Shown({ $box.Select() })
    if ($form.ShowDialog() -ne 'OK') { throw 'Password entry was cancelled' }
    return $box.Text
}
$passDir = "C:\\ProgramData\\AJNAT"
$passFile = "$passDir\\uninstall.pass"
New-Item -ItemType Directory -Path $passDir -Force | Out-Null
$legacyPassFile = "C:\\ProgramData\\SOCAgent\\uninstall.pass"
if (-not (Test-Path $passFile) -and (Test-Path $legacyPassFile)) {
    & takeown.exe /F $legacyPassFile /A | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not take ownership of the legacy uninstall password (exit code $LASTEXITCODE)" }
    & icacls.exe $legacyPassFile /reset /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not reset the legacy uninstall password ACL (exit code $LASTEXITCODE)" }
    & icacls.exe $legacyPassFile /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not repair the legacy uninstall password ACL (exit code $LASTEXITCODE)" }
    Copy-Item -LiteralPath $legacyPassFile -Destination $passFile -Force
}
if (${keepExistingCondition}) {
    Write-Host "  OK: Existing uninstall password kept" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Set uninstall password (required to remove SOC Agent later)" -ForegroundColor Yellow
    while ($true) {
        $p1 = Read-PlainPassword "Enter uninstall password"
        $p2 = Read-PlainPassword "Confirm uninstall password"
        if ($p1.Length -lt 8) {
            [System.Windows.Forms.MessageBox]::Show('Password must contain at least 8 characters.', 'SOC Agent', 'OK', 'Error') | Out-Null
        } elseif ($p1 -ne $p2) {
            [System.Windows.Forms.MessageBox]::Show('Passwords do not match.', 'SOC Agent', 'OK', 'Error') | Out-Null
        } else {
            New-PasswordRecord $p1 | Set-Content -Path $passFile -NoNewline
            $p1 = $null; $p2 = $null
            Write-Host "  OK: Uninstall password saved" -ForegroundColor Green
            break
        }
    }
}
& icacls.exe $passFile /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure the uninstall password ACL (exit code $LASTEXITCODE)" }
`;
}

function windowsPasswordVerifySnippet() {
  return `
# -- Require uninstall password --
function Get-LegacyPasswordHash([string]$Value) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([BitConverter]::ToString($hashBytes)).Replace("-", "").ToLowerInvariant()
}

function Test-PasswordRecord([string]$Value, [string]$Record) {
    if ($Record -match '^pbkdf2-sha256:(\\d+):([^:]+):([^:]+)$') {
        $iterations = [int]$Matches[1]
        $salt = [Convert]::FromBase64String($Matches[2])
        $expected = [Convert]::FromBase64String($Matches[3])
        $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $Value, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        try { $actual = $derive.GetBytes($expected.Length) } finally { $derive.Dispose() }
        if ($actual.Length -ne $expected.Length) { return $false }
        $difference = 0
        for ($index = 0; $index -lt $actual.Length; $index++) {
            $difference = $difference -bor ($actual[$index] -bxor $expected[$index])
        }
        return $difference -eq 0
    }
    return (Get-LegacyPasswordHash $Value) -eq $Record
}
function Read-PlainPassword([string]$Prompt) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'SOC Agent Uninstall Authorization'
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size(430,170)
    $form.TopMost = $true
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.Location = New-Object System.Drawing.Point(18,18)
    $label.AutoSize = $true
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point(18,48)
    $box.Size = New-Object System.Drawing.Size(378,24)
    $box.UseSystemPasswordChar = $true
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Authorize'; $ok.Location = New-Object System.Drawing.Point(220,88); $ok.DialogResult = 'OK'
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(321,88); $cancel.DialogResult = 'Cancel'
    $form.Controls.AddRange(@($label, $box, $ok, $cancel))
    $form.AcceptButton = $ok; $form.CancelButton = $cancel
    $form.Add_Shown({ $box.Select() })
    if ($form.ShowDialog() -ne 'OK') { throw 'Uninstall authorization was cancelled' }
    return $box.Text
}
$passFile = "C:\\ProgramData\\AJNAT\\uninstall.pass"
if (-not (Test-Path $passFile) -and (Test-Path "C:\\ProgramData\\SOCAgent\\uninstall.pass")) {
    $passFile = "C:\\ProgramData\\SOCAgent\\uninstall.pass"
}
if (-not (Test-Path $passFile)) {
    Write-Host "ERROR: uninstall password is not configured. Re-run install/update first." -ForegroundColor Red
    exit 1
}
$entered = Read-PlainPassword "Enter uninstall password"
$savedHash = (Get-Content $passFile -Raw).Trim()
if (-not (Test-PasswordRecord $entered $savedHash)) {
    $entered = $null
    Write-Host "ERROR: incorrect uninstall password." -ForegroundColor Red
    exit 1
}
$entered = $null
Write-Host "OK: Password verified" -ForegroundColor Green
`;
}

function windowsMsiInteractiveActionPrelude(actionLabel) {
  return `
$ErrorActionPreference = 'Stop'
trap {
    $detail = '${actionLabel} failed: ' + $_.Exception.Message
    try { Add-Content -LiteralPath (Join-Path $env:TEMP 'ajnat-msi-password-action.log') -Value $detail -Encoding UTF8 } catch {}
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show($detail, 'SOC Agent Installer', 'OK', 'Error') | Out-Null
    } catch {}
    exit 1
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($args -contains '--ajnat-elevated') { throw 'Administrator privileges are required' }
    $quotedScript = $PSCommandPath.Replace('"', '""')
    $argumentLine = '-NoProfile -STA -ExecutionPolicy Bypass -File "' + $quotedScript + '" --ajnat-elevated'
    $elevated = Start-Process -FilePath 'powershell.exe' -ArgumentList $argumentLine -Verb RunAs -Wait -PassThru
    exit $elevated.ExitCode
}
`;
}

function windowsProtectedAclSnippet() {
  return `
# -- Protect installed code and runtime secrets --
$runtimeDir = "C:\\ProgramData\\AJNAT"
$runtimeLogDir = Join-Path $runtimeDir 'logs'
New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
New-Item -ItemType Directory -Path $runtimeLogDir -Force | Out-Null
function Invoke-ProtectedAcl([string[]]$Arguments, [string]$Description) {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & icacls.exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($code -ne 0) { throw ("{0} failed with icacls exit code {1}: {2}" -f $Description, $code, ($output -join ' ')) }
}
# Keep ownership with the local Administrators SID. SID-based rules work on
# non-English Windows too. Users can execute installed code and read logs, but
# only SYSTEM/Administrators can modify code, configuration, or runtime data.
Invoke-ProtectedAcl -Arguments @($InstallDir, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q') -Description 'Install directory ownership update'
Invoke-ProtectedAcl -Arguments @($InstallDir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX', '/T', '/C', '/Q') -Description 'Install directory ACL update'
# Inheritance flags alone are not a reliable effective ACE on existing files.
# Add direct rights recursively while retaining the inheritable directory rules
# above for files created by later agent runs and upgrades.
Invoke-ProtectedAcl -Arguments @($InstallDir, '/grant', '*S-1-5-18:F', '*S-1-5-32-544:F', '*S-1-5-32-545:RX', '/T', '/C', '/Q') -Description 'Install file direct ACL update'
Invoke-ProtectedAcl -Arguments @($runtimeDir, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q') -Description 'Runtime directory ownership update'
Invoke-ProtectedAcl -Arguments @($runtimeDir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '/T', '/C', '/Q') -Description 'Runtime directory ACL update'
Invoke-ProtectedAcl -Arguments @($runtimeDir, '/grant', '*S-1-5-18:F', '*S-1-5-32-544:F', '/T', '/C', '/Q') -Description 'Runtime file direct ACL update'
Invoke-ProtectedAcl -Arguments @($runtimeDir, '/grant:r', '*S-1-5-32-545:RX', '/Q') -Description 'Runtime directory traversal ACL update'
Invoke-ProtectedAcl -Arguments @($runtimeLogDir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX', '/T', '/C', '/Q') -Description 'Runtime log ACL update'
Invoke-ProtectedAcl -Arguments @($runtimeLogDir, '/grant', '*S-1-5-18:F', '*S-1-5-32-544:F', '*S-1-5-32-545:RX', '/T', '/C', '/Q') -Description 'Runtime log direct ACL update'
$secretConfig = Join-Path $runtimeDir 'config\\company_config.json'
if (-not (Test-Path $secretConfig)) { $secretConfig = Join-Path $InstallDir 'config\\company_config.json' }
if (Test-Path $secretConfig) {
    Invoke-ProtectedAcl -Arguments @($secretConfig, '/inheritance:r', '/grant:r', '*S-1-5-18:F', '*S-1-5-32-544:F', '/Q') -Description 'Configuration ACL update'
}
`;
}

function windowsPywin32ServiceHostSnippet(nativeInvoker) {
  return `
# A venv contains python.exe under Scripts, while pywin32 places its SCM host
# at the venv root. The service host needs the base Python DLL beside it and
# must be able to import the service module without relying on a working dir.
$serviceWrapper = Join-Path $InstallDir 'windows_service.py'
if (-not (Test-Path -LiteralPath $serviceWrapper)) { throw "Native Windows service wrapper is missing: $serviceWrapper" }
$serviceSitePackages = ([string](& $pythonPath -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")).Trim()
if (-not $serviceSitePackages -or -not (Test-Path -LiteralPath $serviceSitePackages)) {
    throw 'Could not resolve AJNAT Python site-packages for the Windows service host'
}
Copy-Item -LiteralPath $serviceWrapper -Destination (Join-Path $serviceSitePackages 'windows_service.py') -Force
$pythonServiceExe = Join-Path $pythonRuntimeDir 'pythonservice.exe'
$packagedPythonServiceExe = Join-Path $serviceSitePackages 'win32\\pythonservice.exe'
if (Test-Path -LiteralPath $packagedPythonServiceExe) {
    # Refresh on update too: pythonservice.exe must match the pywin32 package
    # that was just installed into this private runtime.
    Copy-Item -LiteralPath $packagedPythonServiceExe -Destination $pythonServiceExe -Force
}
$basePythonDir = ([string](& $pythonPath -c 'import sys; print(sys.base_prefix)')).Trim()
if ($basePythonDir -and (Test-Path -LiteralPath $basePythonDir)) {
    $basePythonDlls = @(Get-ChildItem -LiteralPath $basePythonDir -Filter 'python*.dll' -File -ErrorAction Stop)
    if ($basePythonDlls.Count -eq 0) { throw "Base Python DLL is missing from $basePythonDir" }
    $basePythonDlls | ForEach-Object {
        $targetDll = Join-Path $pythonRuntimeDir $_.Name
        if (-not [string]::Equals($_.FullName, $targetDll, [StringComparison]::OrdinalIgnoreCase)) {
            Copy-Item -LiteralPath $_.FullName -Destination $targetDll -Force
        }
    }
}
if (-not (Test-Path -LiteralPath $pythonServiceExe)) { throw "pywin32 service host is missing: $pythonServiceExe" }
${nativeInvoker} -FilePath $pythonPath -Arguments @('-c', 'import windows_service, win32serviceutil, win32service, servicemanager') -Description 'AJNAT Windows service host validation'
`;
}

function nsisEscape(value) {
  const normalized = process.platform === 'win32'
    ? path.win32.normalize(String(value || ''))
    : String(value || '').replace(/\\/g, '/');
  return normalized.replace(/"/g, '$\\"');
}

function findTool(name, localPath) {
  const candidates = [
    ...(localPath ? [
      path.resolve(process.cwd(), localPath),
      path.resolve(__dirname, '..', '..', '..', localPath),
    ] : []),
    `/usr/bin/${name}`,
    `/usr/local/bin/${name}`,
  ];

  if (process.platform === 'win32') {
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    const executable = name.toLowerCase().endsWith('.exe') ? name : `${name}.exe`;
    if (name.toLowerCase() === 'makensis') {
      candidates.push(
        path.resolve(process.cwd(), '.tools', 'nsis-runtime', executable),
        path.join(repoRoot(), '.tools', 'nsis-runtime', executable),
        path.join(programFiles, 'NSIS', executable),
        path.join(programFilesX86, 'NSIS', executable),
      );
    }
    if (['candle', 'light'].includes(name.toLowerCase())) {
      candidates.push(
        path.resolve(process.cwd(), '.tools', 'wix', executable),
        path.join(repoRoot(), '.tools', 'wix', executable),
      );
      for (const version of ['v3.14', 'v3.11', 'v3.10']) {
        candidates.push(
          path.join(programFilesX86, `WiX Toolset ${version}`, 'bin', executable),
          path.join(programFiles, `WiX Toolset ${version}`, 'bin', executable),
        );
      }
    }
  }

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch { /* skip */ }
  }

  try {
    const locator = process.platform === 'win32' ? 'where.exe' : 'which';
    return execFileSync(locator, [name], { encoding: 'utf8' })
      .trim()
      .split(/\r?\n/)[0];
  } catch {
    return '';
  }
}

function signWindowsArtifact(filePath) {
  const required = String(process.env.WINDOWS_CODE_SIGN_REQUIRED || '').toLowerCase() === 'true';
  const pfxPath = String(process.env.WINDOWS_CODE_SIGN_PFX || '').trim();
  const passwordFile = String(process.env.WINDOWS_CODE_SIGN_PASSWORD_FILE || '').trim();
  const certificatePath = String(process.env.WINDOWS_CODE_SIGN_CERT || '').trim();
  const configuredTool = String(process.env.WINDOWS_CODE_SIGN_TOOL || '').trim();
  const signTool = configuredTool || findTool('osslsigncode', '.local-signing-tools/usr/bin/osslsigncode');

  if (!pfxPath || !passwordFile || !signTool) {
    if (required) throw new Error('Windows Authenticode signing is required but its PFX, password file, or signing tool is missing');
    return false;
  }
  for (const requiredFile of [pfxPath, passwordFile, signTool]) {
    if (!fs.existsSync(requiredFile)) throw new Error(`Windows signing dependency is missing: ${requiredFile}`);
  }

  const parsed = path.parse(filePath);
  const signedPath = path.join(parsed.dir, `${parsed.name}.signed${parsed.ext}`);
  const args = [
    'sign', '-pkcs12', pfxPath, '-readpass', passwordFile,
    '-h', 'sha256', '-n', 'AJNAT SOC Agent',
    '-i', 'https://ajnat.example',
  ];
  const timestampUrl = String(process.env.WINDOWS_CODE_SIGN_TIMESTAMP_URL || '').trim();
  if (timestampUrl) args.push('-ts', timestampUrl);
  args.push('-in', filePath, '-out', signedPath);

  try {
    try {
      execFileSync(signTool, args, { stdio: 'pipe', timeout: 120000 });
    } catch (timestampError) {
      const localTestSigning = String(process.env.WINDOWS_CODE_SIGN_MODE || '').toLowerCase() === 'local-test';
      if (!timestampUrl || !localTestSigning) throw timestampError;
      // Developer/test certificates must still produce usable installers when
      // the public timestamp service is temporarily unavailable. Production
      // signing remains fail-closed and always requires its configured TSA.
      fs.rmSync(signedPath, { force: true });
      const offlineArgs = args.filter((value, index) => (
        value !== '-ts' && args[index - 1] !== '-ts'
      ));
      execFileSync(signTool, offlineArgs, { stdio: 'pipe', timeout: 120000 });
    }
    fs.renameSync(signedPath, filePath);
    const verifyArgs = ['verify'];
    if (certificatePath && fs.existsSync(certificatePath)) verifyArgs.push('-CAfile', certificatePath);
    verifyArgs.push('-in', filePath);
    execFileSync(signTool, verifyArgs, { stdio: 'pipe', timeout: 30000 });
    return true;
  } catch (error) {
    fs.rmSync(signedPath, { force: true });
    throw new Error(`Windows Authenticode signing failed for ${path.basename(filePath)}: ${error.message}`);
  }
}

function repoRoot() {
  return path.resolve(__dirname, '..', '..', '..');
}

function localMsiToolsRoot() {
  const candidates = [
    path.resolve(process.cwd(), '.local-msi-tools'),
    path.join(repoRoot(), '.local-msi-tools'),
  ];
  return candidates.find(candidate => fs.existsSync(candidate)) || candidates[0];
}

function buildNsisExeFromZip(zipBuffer, dirName, system, company, version, options = {}) {
  const makensis = findTool('makensis');
  if (!makensis) {
    throw new Error('EXE builder not available: makensis is not installed');
  }

  const AdmZip = require('adm-zip');
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-agent-exe-'));
  try {
    const extracted = path.join(tmpRoot, 'extracted');
    fs.mkdirSync(extracted, { recursive: true });
    new AdmZip(zipBuffer).extractAllTo(extracted, true);

    const payloadRoot = path.join(extracted, dirName);
    const outFile = path.join(tmpRoot, `soc-agent_${sanitize(company.name)}_${sanitize(system.name)}_windows.exe`);
    const nsiPath = path.join(tmpRoot, 'installer.nsi');
    const preflightPath = path.join(tmpRoot, 'preflight.ps1');
    const errorViewerPath = path.join(tmpRoot, 'show-install-error.ps1');
    fs.writeFileSync(preflightPath, `param([string]$StageDir)
$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Administrator privileges are required"
}
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
exit 0
`, 'utf8');
    fs.writeFileSync(errorViewerPath, `param()
$LogPath = Join-Path $env:TEMP "soc-agent-install-bootstrap.log"
$InstallLog = Join-Path $env:ProgramData "AJNAT\\logs\\install.log"
$ServiceLog = Join-Path $env:ProgramData "AJNAT\\logs\\service-install.log"
$Host.UI.RawUI.WindowTitle = "SOC Agent Installation Error"
Clear-Host
Write-Host "SOC Agent installation failed." -ForegroundColor Red
Write-Host "Detailed log: $LogPath" -ForegroundColor Yellow
Write-Host "This PowerShell window will remain open so you can review or copy the error." -ForegroundColor Cyan
Write-Host ""
foreach ($DiagnosticLog in @($InstallLog, $ServiceLog)) {
  if (Test-Path -LiteralPath $DiagnosticLog) {
    try {
      Add-Content -LiteralPath $LogPath -Value ([Environment]::NewLine + "===== $DiagnosticLog =====") -Encoding UTF8
      Get-Content -LiteralPath $DiagnosticLog -Tail 200 -ErrorAction Stop | Add-Content -LiteralPath $LogPath -Encoding UTF8
    } catch {
      Add-Content -LiteralPath $LogPath -Value "Unable to read diagnostic log: $($_.Exception.Message)" -Encoding UTF8
    }
  }
}
if (Test-Path -LiteralPath $LogPath) {
  Get-Content -LiteralPath $LogPath
} else {
  Write-Host "Install log was not created." -ForegroundColor Red
}
`, 'utf8');

    const nsi = `
Unicode true
!include LogicLib.nsh
Name "SOC Agent"
OutFile "${nsisEscape(outFile)}"
InstallDir "$PROGRAMFILES64\\AJNAT"
RequestExecutionLevel admin
ShowInstDetails show
BrandingText "SOC Agent v${version}"
VIProductVersion "${nsisVersion(version)}"
VIAddVersionKey "ProductName" "SOC Agent"
VIAddVersionKey "CompanyName" "${nsisEscape(company.name || 'SOC')}"
VIAddVersionKey "FileDescription" "SOC Agent Windows Installer"
VIAddVersionKey "FileVersion" "${nsisVersion(version)}"
VIAddVersionKey "ProductVersion" "${nsisVersion(version)}"
VIAddVersionKey "LegalCopyright" "SOC Agent"

Page directory
Page instfiles

${options.isAgentUpdate ? '' : `Function .onInit
  \${If} \${Silent}
    IfFileExists "$COMMONAPPDATA\\AJNAT\\uninstall.pass" silent_update_allowed 0
    IfFileExists "$COMMONAPPDATA\\SOCAgent\\uninstall.pass" silent_update_allowed 0
    MessageBox MB_ICONSTOP "Silent installation is disabled because an uninstall password must be set interactively."
    Abort
    silent_update_allowed:
  \${EndIf}
FunctionEnd`}

Section "Install"
  SetShellVarContext all
  ; A unique stage prevents an interrupted legacy update from leaving a locked
  ; static directory that makes the next silent preflight wait indefinitely.
  ClearErrors
  GetTempFileName $3 "$TEMP"
  IfErrors stage_path_failure
  StrCmp $3 "" stage_path_failure
  Delete "$3"
  StrCpy $3 "$3-AJNAT-agent-stage"
  DetailPrint "Preparing isolated AJNAT installation stage..."
  SetOutPath "$TEMP"
  File /oname=soc-agent-preflight.ps1 "${nsisEscape(preflightPath)}"
  File /oname=soc-agent-show-error.ps1 "${nsisEscape(errorViewerPath)}"
  IfSilent silent_prepare_stage interactive_prepare_stage
  silent_prepare_stage:
    ; The OTA caller already runs as LocalSystem. Avoid every blocking helper
    ; before the asynchronous launch so legacy agents can never wait here.
    CreateDirectory "$3"
    Goto stage_payload
  interactive_prepare_stage:
  ExecWait 'powershell -NoProfile -ExecutionPolicy Bypass -File "$TEMP\\soc-agent-preflight.ps1" -StageDir "$3"' $0
  Delete "$TEMP\\soc-agent-preflight.ps1"
  \${If} $0 != 0
    IfSilent silent_preflight_failure interactive_preflight_failure
    interactive_preflight_failure:
    MessageBox MB_ICONSTOP "Administrator preflight failed (exit code $0)."
    Abort
    silent_preflight_failure:
    ; Never display a Session-0 message box during OTA: nobody can dismiss it,
    ; and the legacy agent otherwise kills this updater after ten minutes.
    SetErrorLevel $0
    Abort
  \${EndIf}
  Goto stage_payload
  stage_path_failure:
    FileOpen $2 "$TEMP\\soc-agent-install-bootstrap.log" w
    FileWrite $2 "Unable to allocate the AJNAT staging directory under $TEMP.$\\r$\\n"
    FileClose $2
    IfSilent silent_stage_path_failure interactive_stage_path_failure
    interactive_stage_path_failure:
      MessageBox MB_ICONSTOP "Unable to create the AJNAT installation stage under $TEMP."
    silent_stage_path_failure:
      SetErrorLevel 2
      Abort
  stage_payload:
  SetOutPath "$3"
  File /r "${nsisEscape(path.join(payloadRoot, '*'))}"
  FileOpen $2 "$TEMP\\soc-agent-install-bootstrap.log" w
  FileWrite $2 "SOC Agent installer launching PowerShell...$\\r$\\n"
  FileClose $2
  ; OTA is initiated by the running SOCAgent service. A silent installer must
  ; return before install.ps1 stops that service, otherwise the agent and
  ; installer wait on one another until the agent's 10-minute timeout. Keep the
  ; staged payload for the detached PowerShell process; interactive installs
  ; still wait and report their exact exit code.
  IfSilent silent_agent_update interactive_install
  silent_agent_update:
    ; NSIS Exec is intentionally asynchronous. The legacy v0.0.1 agent waits
    ; synchronously for this EXE, so ExecWait (including cmd.exe start /b) keeps
    ; the installer inside the service process tree until the agent kills it at
    ; its ten-minute timeout. The staged payload remains available below.
    Exec 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$3\\install-update.ps1" -InstallDir "$INSTDIR"'
    ; Do not touch the protected install directory, registry, or cleanup from
    ; this bootstrap process. The PowerShell updater owns those operations.
    Quit
  interactive_install:
    ExecWait 'powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "$3\\install.ps1" -InstallDir "$INSTDIR"' $0
  install_process_started:
  FileOpen $2 "$TEMP\\soc-agent-install-bootstrap.log" a
  FileWrite $2 "Installer exit code: $0$\\r$\\n"
  FileClose $2
  \${If} $0 != 0
    IfSilent silent_install_failure interactive_install_failure
    interactive_install_failure:
    ; Exec directly so this window inherits the elevated installer token.
    ; ExecShell may route through Explorer and drop access to protected logs.
    Exec 'powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass -File "$TEMP\\soc-agent-show-error.ps1"'
    MessageBox MB_ICONSTOP "Installation failed. A PowerShell error window has been opened and will remain open."
    silent_install_failure:
    SetErrorLevel $0
    Abort
  \${EndIf}
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\\uninstall.exe"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent" "DisplayName" "SOC Agent"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent" "DisplayVersion" "${version}"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent" "Publisher" "${nsisEscape(company.name || 'SOC')}"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent" "UninstallString" '"$INSTDIR\\uninstall.exe"'
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent" "QuietUninstallString" '"$INSTDIR\\uninstall.exe" /S'
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent" "NoModify" 1
  WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent" "NoRepair" 1
  \${If} $4 != "detached"
    RMDir /r "$3"
  \${EndIf}
SectionEnd

Section "Uninstall"
  \${If} \${Silent}
    MessageBox MB_ICONSTOP "Silent uninstall is disabled because the uninstall password must be verified."
    Abort
  \${EndIf}
  ExecWait 'powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "$INSTDIR\\uninstall.ps1" -InstallDir "$INSTDIR"' $0
  \${If} $0 != 0
    MessageBox MB_ICONSTOP "Uninstall cancelled or password verification failed."
    Abort
  \${EndIf}
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SOC Agent"
  Delete "$INSTDIR\\uninstall.exe"
  RMDir /r "$INSTDIR"
SectionEnd
`;

    fs.writeFileSync(nsiPath, nsi, 'utf8');
    execFileSync(makensis, [nsiPath], { stdio: 'pipe', timeout: 120000 });
    if (!fs.existsSync(outFile)) throw new Error('EXE build finished but output file was not found');
    signWindowsArtifact(outFile);
    return fs.readFileSync(outFile);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

function xmlEscape(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function wixId(prefix, value) {
  const hash = crypto.createHash('sha1').update(String(value)).digest('hex').slice(0, 18);
  return `${prefix}_${hash}`;
}

function stableGuid(seed) {
  const hex = crypto.createHash('sha1').update(String(seed)).digest('hex').slice(0, 32);
  return `{${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}}`;
}

function nsisVersion(version) {
  return `${msiVersion(version)}.0`;
}

function msiVersion(version) {
  const parts = String(version || '1.0.0')
    .split('.')
    .map(part => Number.parseInt(part.replace(/\D/g, ''), 10))
    .filter(Number.isFinite)
    .slice(0, 3);
  while (parts.length < 3) parts.push(0);
  return parts.map((part, index) => {
    const max = index === 0 ? 255 : 65535;
    return Math.max(0, Math.min(part, max));
  }).join('.');
}

function writeFilesToDir(files, rootDir) {
  for (const f of files) {
    if (f.rel === 'config/company_config.json') continue;
    const relNorm = f.rel.replace(/\\/g, '/');
    const target = path.join(rootDir, relNorm);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, f.content);
  }
  fs.writeFileSync(path.join(rootDir, 'integrity_manifest.json'), integrityManifestBuffer(files));
}

function collectPayloadFilePaths(rootDir, prefix = '') {
  const entries = fs.readdirSync(path.join(rootDir, prefix), { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      files.push(...collectPayloadFilePaths(rootDir, rel));
    } else {
      files.push(rel);
    }
  }
  return files;
}

function directorySizeBytes(dir) {
  let total = 0;
  if (!fs.existsSync(dir)) return total;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) total += directorySizeBytes(full);
    else total += fs.statSync(full).size;
  }
  return total;
}

function createCpioGz(rootDir) {
  const outFile = path.join(os.tmpdir(), `soc-agent-${crypto.randomUUID()}.cpio.gz`);
  try {
    execFileSync('sh', ['-c', 'find . -print | cpio -o --format=odc | gzip -c > "$1"', 'sh', outFile], {
      cwd: rootDir,
      stdio: 'pipe',
      timeout: 120000,
    });
    return fs.readFileSync(outFile);
  } finally {
    fs.rmSync(outFile, { force: true });
  }
}

function buildWixDirectoryTree(rootDir, relDir, componentRefs) {
  const absDir = relDir ? path.join(rootDir, relDir) : rootDir;
  const entries = fs.readdirSync(absDir, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name));
  let xml = '';

  for (const entry of entries) {
    const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      const dirId = wixId('DIR', rel);
      xml += `        <Directory Id="${dirId}" Name="${xmlEscape(entry.name)}">\n`;
      xml += buildWixDirectoryTree(rootDir, rel, componentRefs);
      xml += `        </Directory>\n`;
    } else {
      const componentId = wixId('CMP', rel);
      const fileId = wixId('FIL', rel);
      const guid = stableGuid(`soc-agent-msi:${rel}`);
      const source = path.join(rootDir, rel);
      componentRefs.push(componentId);
      xml += `        <Component Id="${componentId}" Guid="${guid}" Win64="yes">\n`;
      xml += `          <File Id="${fileId}" Source="${xmlEscape(source)}" KeyPath="yes" />\n`;
      xml += `        </Component>\n`;
    }
  }

  return xml;
}

function buildMsiFromPayload(payloadRoot, system, company, version, { isAgentUpdate = false } = {}) {
  const wixl = findTool('wixl', '.local-msi-tools/usr/bin/wixl');
  const candle = findTool('candle');
  const light = findTool('light');
  if (!wixl && !(candle && light)) {
    throw new Error('MSI builder not available: install wixl/msitools or WiX Toolset v3 (candle/light)');
  }

  const toolsRoot = localMsiToolsRoot();
  const localLib = path.join(toolsRoot, 'usr/lib/x86_64-linux-gnu');
  const localShare = path.join(toolsRoot, 'usr/share');
  const env = { ...process.env };
  if (fs.existsSync(localLib)) {
    env.LD_LIBRARY_PATH = env.LD_LIBRARY_PATH ? `${localLib}:${env.LD_LIBRARY_PATH}` : localLib;
  }
  if (fs.existsSync(localShare)) {
    env.XDG_DATA_DIRS = env.XDG_DATA_DIRS ? `${localShare}:${env.XDG_DATA_DIRS}` : `${localShare}:/usr/local/share:/usr/share`;
  }

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-agent-msi-'));
  try {
    const outFile = path.join(tmpRoot, `soc-agent_${sanitize(company.name)}_${sanitize(system.name)}_windows.msi`);
    const wxsPath = path.join(tmpRoot, 'soc-agent.wxs');
    const licensePath = path.join(tmpRoot, 'License.rtf');
    const componentRefs = [];
    const componentsXml = buildWixDirectoryTree(payloadRoot, '', componentRefs);
    const serviceControlComponentId = 'CMP_SOCAgentServiceControl';
    const serviceControlGuid = stableGuid('soc-agent-msi:service-control');
    componentRefs.push(serviceControlComponentId);
    const refsXml = componentRefs.map(id => `      <ComponentRef Id="${id}" />`).join('\n');
    const upgradeCode = stableGuid(`soc-agent-upgrade:${company._id || company.name}`);
    // ProductCode must change for every generated MSI. The package is built
    // per endpoint and may be downloaded repeatedly at the same app version;
    // reusing a ProductCode makes Windows Installer reject the fresh package
    // with ERROR_PRODUCT_VERSION (1638: another version is already installed).
    // UpgradeCode remains stable so RemoveExistingProducts replaces the prior
    // registration, including a same-version repair/re-enrollment package.
    const productCode = `{${crypto.randomUUID().toUpperCase()}}`;
    const launchCondition = isAgentUpdate
      ? '1'
      : 'Installed OR AJNAT_RELATED_PRODUCTS OR UILevel &gt;= 4';
    const setupPasswordCondition = isAgentUpdate
      ? '0'
      : 'NOT (REMOVE=&quot;ALL&quot;) OR AJNAT_RELATED_PRODUCTS';

    const wxs = `<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="${productCode}" Name="SOC Agent" Language="1033" Version="${msiVersion(version)}" Manufacturer="${xmlEscape(company.name || 'SOC')}" UpgradeCode="${upgradeCode}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" InstallPrivileges="elevated" Platform="x64" Description="SOC Agent ${xmlEscape(version)}" />
    <MediaTemplate EmbedCab="yes" />
    <UIRef Id="WixUI_Minimal" />
    <Condition Message="SOC Agent must be installed interactively so an uninstall password can be configured.">${launchCondition}</Condition>
    <!-- The release number can intentionally be reset (for example 3.1.16 to
         0.0.1), so detect and replace every installed SOC Agent version. -->
    <Upgrade Id="${upgradeCode}">
      <UpgradeVersion Minimum="0.0.0" IncludeMinimum="yes" Property="AJNAT_RELATED_PRODUCTS" />
    </Upgrade>
    <CustomAction Id="SetupUninstallPassword" Directory="INSTALLFOLDER" Execute="immediate" Impersonate="yes" ExeCommand="powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER]password-setup.ps1&quot;" Return="check" />
    <CustomAction Id="VerifyUninstallPassword" Directory="INSTALLFOLDER" Execute="immediate" Impersonate="yes" ExeCommand="powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER]password-verify.ps1&quot;" Return="check" />
    <CustomAction Id="RunInstallPs1" Directory="INSTALLFOLDER" Execute="deferred" Impersonate="no" ExeCommand="powershell.exe -NoProfile -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER]install.ps1&quot; -MsiMode" Return="check" />
    <CustomAction Id="RunUninstallPs1" Directory="INSTALLFOLDER" Execute="deferred" Impersonate="no" ExeCommand="powershell.exe -NoProfile -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER]uninstall.ps1&quot; -MsiMode" Return="check" />
    <CustomAction Id="RunUpgradeCleanup" Directory="INSTALLFOLDER" Execute="deferred" Impersonate="no" ExeCommand="powershell.exe -NoProfile -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER]uninstall.ps1&quot; -MsiMode -PreserveData" Return="check" />
    <CustomAction Id="TrustPublisherRoot" Directory="INSTALLFOLDER" Execute="deferred" Impersonate="no" ExeCommand="certutil.exe -f -addstore Root &quot;[INSTALLFOLDER]certs\AJNAT-Local-Test-Publisher.cer&quot;" Return="check" />
    <CustomAction Id="TrustPublisherCodeSigning" Directory="INSTALLFOLDER" Execute="deferred" Impersonate="no" ExeCommand="certutil.exe -f -addstore TrustedPublisher &quot;[INSTALLFOLDER]certs\AJNAT-Local-Test-Publisher.cer&quot;" Return="check" />
    <InstallExecuteSequence>
      <!-- Keep major-upgrade removal between validation and initialization.
           Explicit numbers avoid wixl placing it at 1501/4003 (MSI error 2613). -->
      <RemoveExistingProducts Sequence="1450" />
      <Custom Action="VerifyUninstallPassword" Sequence="3400">REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE</Custom>
      <Custom Action="RunUninstallPs1" Sequence="3410">REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE</Custom>
      <Custom Action="RunUpgradeCleanup" Sequence="3420">REMOVE="ALL" AND UPGRADINGPRODUCTCODE</Custom>
      <!-- A major-upgrade session may keep REMOVE=ALL while installing the new
           ProductCode. AJNAT_RELATED_PRODUCTS distinguishes that valid install
           from a genuine uninstall of the current product. -->
      <Custom Action="SetupUninstallPassword" Sequence="4010">${setupPasswordCondition}</Custom>
      <!-- InstallFiles runs at 4000. Trust the packaged AJNAT publisher before
           PowerShell starts the signed agent installer on WDAC/AppLocker hosts. -->
      <Custom Action="TrustPublisherRoot" Sequence="4012">${isAgentUpdate ? '1' : '0'}</Custom>
      <Custom Action="TrustPublisherCodeSigning" Sequence="4014">${isAgentUpdate ? '1' : '0'}</Custom>
      <Custom Action="RunInstallPs1" Sequence="4020">NOT (REMOVE=&quot;ALL&quot;) OR AJNAT_RELATED_PRODUCTS</Custom>
    </InstallExecuteSequence>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLFOLDER" Name="AJNAT">
${componentsXml}        <Component Id="${serviceControlComponentId}" Guid="${serviceControlGuid}" Win64="yes">
          <CreateFolder />
          <ServiceControl Id="StopSOCAgentBeforeFileUpdate" Name="SOCAgent" Stop="both" Remove="uninstall" Wait="yes" />
        </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="DefaultFeature" Title="SOC Agent" Level="1">
${refsXml}
    </Feature>
  </Product>
</Wix>
`;

    fs.writeFileSync(wxsPath, wxs, 'utf8');
    fs.writeFileSync(
      licensePath,
      '{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Segoe UI;}}\\f0\\fs20 '
        + 'AJNAT SOC Agent\\par\\par '
        + 'Authorized endpoint security software for this organization. '
        + 'Installation requires administrator approval and configures the AJNAT service.\\par}',
      'ascii',
    );
    if (wixl) {
      // wixl defaults the MSI SummaryInformation template to Intel even when
      // Package/@Platform and all components are x64. Windows then rejects or
      // inconsistently services that mixed-architecture package. Pass the
      // target explicitly so install, repair, upgrade, and uninstall all use
      // the same 64-bit Windows Installer registry view.
      const wixlExtensionDir = path.join(localShare, 'wixl-0.106', 'ext');
      execFileSync(wixl, ['--arch', 'x64', '--extdir', wixlExtensionDir, '--ext', 'ui', '-o', outFile, wxsPath], {
        cwd: tmpRoot, env, stdio: 'pipe', timeout: 120000,
      });
      // wixl 0.106 emits InstallExecuteSequence references but silently drops
      // ExeCommand CustomAction definitions. Inject the missing MSI table so
      // Windows actually runs password setup, install, upgrade, and uninstall.
      const msiBuild = findTool('msibuild', '.local-msi-tools/usr/bin/msibuild');
      const msiInfo = findTool('msiinfo', '.local-msi-tools/usr/bin/msiinfo');
      if (!msiBuild || !msiInfo) {
        throw new Error('msibuild and msiinfo are required to finalize wixl MSI custom actions');
      }
      const customActionIdt = path.join(tmpRoot, 'CustomAction.idt');
      const immediateExe = 34;
      const deferredSystemExe = 34 + 1024 + 2048;
      const customActionRows = [
        ['SetupUninstallPassword', immediateExe, 'INSTALLFOLDER', 'powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "[INSTALLFOLDER]password-setup.ps1"', 0],
        ['VerifyUninstallPassword', immediateExe, 'INSTALLFOLDER', 'powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "[INSTALLFOLDER]password-verify.ps1"', 0],
        ['RunInstallPs1', deferredSystemExe, 'INSTALLFOLDER', 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "[INSTALLFOLDER]install.ps1" -MsiMode', 0],
        ['RunUninstallPs1', deferredSystemExe, 'INSTALLFOLDER', 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "[INSTALLFOLDER]uninstall.ps1" -MsiMode', 0],
        ['RunUpgradeCleanup', deferredSystemExe, 'INSTALLFOLDER', 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "[INSTALLFOLDER]uninstall.ps1" -MsiMode -PreserveData', 0],
        ['TrustPublisherRoot', deferredSystemExe, 'INSTALLFOLDER', 'certutil.exe -f -addstore Root "[INSTALLFOLDER]certs\\AJNAT-Local-Test-Publisher.cer"', 0],
        ['TrustPublisherCodeSigning', deferredSystemExe, 'INSTALLFOLDER', 'certutil.exe -f -addstore TrustedPublisher "[INSTALLFOLDER]certs\\AJNAT-Local-Test-Publisher.cer"', 0],
      ];
      const idt = [
        'Action\tType\tSource\tTarget\tExtendedType',
        's72\ti2\tS72\tS255\tI4',
        'CustomAction\tAction',
        ...customActionRows.map(row => row.join('\t')),
        '',
      ].join('\n');
      fs.writeFileSync(customActionIdt, idt, 'utf8');
      execFileSync(msiBuild, [outFile, '-i', customActionIdt], {
        cwd: tmpRoot, env, stdio: 'pipe', timeout: 30000,
      });
      const compiledActions = execFileSync(msiInfo, ['export', outFile, 'CustomAction'], {
        cwd: tmpRoot, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000,
      });
      for (const [action] of customActionRows) {
        if (!compiledActions.includes(`${action}\t`)) {
          throw new Error(`MSI custom action was not compiled: ${action}`);
        }
      }
    } else {
      const wixObjPath = path.join(tmpRoot, 'soc-agent.wixobj');
      execFileSync(candle, ['-nologo', '-arch', 'x64', '-out', wixObjPath, wxsPath], {
        env, stdio: 'pipe', timeout: 120000,
      });
      execFileSync(light, ['-nologo', '-ext', 'WixUIExtension', '-out', outFile, wixObjPath], {
        env, stdio: 'pipe', timeout: 120000,
      });
    }
    if (!fs.existsSync(outFile)) throw new Error('MSI build finished but output file was not found');
    signWindowsArtifact(outFile);
    return fs.readFileSync(outFile);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// README helpers
// ─────────────────────────────────────────────────────────────────────────────
function readmeLin(system, company, fmt, version) {
  const sn = sanitize(system.name);
  return `SOC Agent v${version} — Linux Package (${fmt.toUpperCase()})
======================================================
Company : ${company.name}
System  : ${system.name}
Version : ${version}

FRESH INSTALL
  unzip soc-agent_${sn}_${fmt}.zip
  cd soc-agent_${sn}_${fmt}
  sudo bash install.sh

UPDATE (agent already installed)
  unzip soc-agent_${sn}_${fmt}.zip
  cd soc-agent_${sn}_${fmt}
  sudo bash install.sh          ← same command, detects existing install

VERIFY
  systemctl status soc-agent
  journalctl -u soc-agent -f

TEST (no sudo)
  python3 /opt/soc-agent/agent.py test

UNINSTALL
  sudo bash uninstall.sh
`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Universal ZIP package  (source bundle with platform-aware installer)
// ─────────────────────────────────────────────────────────────────────────────
function buildUniversal(system, company, agentConfig) {
  const AdmZip     = require('adm-zip');
  const configJson = JSON.stringify(agentConfig, null, 2);
  const files      = collectAgentFiles();
  const zip        = new AdmZip();
  const dirName    = `soc-agent_${sanitize(system.name)}_universal`;
  const VERSION    = agentConfig.agent_version || DEFAULT_AGENT_VERSION;

  addAgentFiles(zip, files, dirName);
  zip.addFile(`${dirName}/config/company_config.json`, Buffer.from(configJson, 'utf8'));
  addVelociraptorBundleToZip(zip, dirName, 'deb');
  addVelociraptorBundleToZip(zip, dirName, 'rpm');
  addVelociraptorBundleToZip(zip, dirName, 'linuxBin');

  const installSh = `#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="/opt/soc-agent"
SVC="soc-agent"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="${VERSION}"
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"

echo "SOC Agent v$VERSION universal installer"
echo "Company : ${company.name}"
echo "System  : ${system.name}"

[ "$(id -u)" != "0" ] && { echo "ERROR: Run with sudo: sudo bash install.sh" >&2; exit 1; }
${unixPasswordInstallSnippet()}

PYTHON=""
for cmd in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
  command -v "$cmd" >/dev/null 2>&1 && PYTHON="$cmd" && break
done
if [ -z "$PYTHON" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y python3 python3-pip python3-venv >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip >/dev/null 2>&1 || true
  fi
  PYTHON="python3"
fi

mkdir -p "$INSTALL_DIR"
cp -rf "$SCRIPT_DIR"/. "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true
chown root:root "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chmod 600 "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chown -R root:root "$INSTALL_DIR" 2>/dev/null || true
find "$INSTALL_DIR" -type d -exec chmod 700 {} +
find "$INSTALL_DIR" -type f -exec chmod 600 {} +
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true

SYSTEM_PYTHON="$PYTHON"
VENV_DIR="$INSTALL_DIR/.venv"
if [ ! -x "$VENV_DIR/bin/python3" ]; then
  if ! "$SYSTEM_PYTHON" -m venv "$VENV_DIR"; then
    if [ "$OS_NAME" = "Linux" ] && command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -y python3-venv python3-pip
    fi
    "$SYSTEM_PYTHON" -m venv "$VENV_DIR"
  fi
fi
PYTHON="$VENV_DIR/bin/python3"
"$PYTHON" -m pip install --quiet --upgrade pip setuptools wheel
"$PYTHON" -m pip install --quiet --upgrade -r "$INSTALL_DIR/requirements.txt"
"$PYTHON" -c 'import requests, psutil, watchdog, cryptography, socketio, websocket, yara'
if [ "$OS_NAME" = "Linux" ]; then "$PYTHON" -c 'import pyudev'; fi
chown -R root:root "$INSTALL_DIR" 2>/dev/null || chown -R root:wheel "$INSTALL_DIR"
chmod -R go-rwx "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true

if [ "$OS_NAME" = "Darwin" ]; then
${macLocationProviderInstallSnippet()}
${macRoleGuardSnippet()}
${macNativeIpsBootstrapSnippet()}
  PLIST="/Library/LaunchDaemons/com.soc.agent.plist"
  cat > "$PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.soc.agent</string>
  <key>ProgramArguments</key>
  <array><string>$PYTHON</string><string>$INSTALL_DIR/agent.py</string><string>run</string></array>
  <key>WorkingDirectory</key><string>$INSTALL_DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/soc-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/soc-agent.err</string>
</dict>
</plist>
PLISTEOF
  chown root:wheel "$PLIST" 2>/dev/null || true
  chmod 644 "$PLIST"
  launchctl unload "$PLIST" >/dev/null 2>&1 || true
  launchctl load "$PLIST"
  launchctl print system/com.soc.agent >/dev/null
  "$PYTHON" "$INSTALL_DIR/agent.py" test
  echo "SOC Agent installed and verified. Check: launchctl print system/com.soc.agent"
else
${linuxRoleGuardSnippet()}
${linuxLocationProviderInstallSnippet()}
${linuxVelociraptorInstallSnippet('apt')}
${linuxNetworkSensorInstallSnippet()}
  cat > "/etc/systemd/system/$SVC.service" << SVCEOF
[Unit]
Description=SOC Security Agent v${VERSION} - ${company.name}/${system.name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/agent.py run
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable "$SVC" >/dev/null
  systemctl restart "$SVC"
  sleep 5
  if ! systemctl is-active --quiet "$SVC"; then
    systemctl status "$SVC" --no-pager -l || true
    echo "ERROR: SOC Agent service did not remain active after installation." >&2
    exit 1
  fi
  "$PYTHON" "$INSTALL_DIR/agent.py" test
  echo "SOC Agent installed and verified. Check: systemctl status $SVC"
fi
`;

  const uninstallSh = `#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" != "0" ] && { echo "ERROR: need sudo"; exit 1; }
${unixPasswordVerifySnippet()}
if [ "$(uname -s 2>/dev/null || echo unknown)" = "Darwin" ]; then
  PLIST="/Library/LaunchDaemons/com.soc.agent.plist"
  launchctl unload "$PLIST" >/dev/null 2>&1 || true
  rm -f "$PLIST"
${macNativeIpsCleanupSnippet()}
else
  systemctl stop soc-agent >/dev/null 2>&1 || true
  systemctl disable soc-agent >/dev/null 2>&1 || true
  systemctl stop suricata >/dev/null 2>&1 || true
  systemctl disable soc-suricata-nfqueue.service >/dev/null 2>&1 || true
  systemctl stop soc-suricata-nfqueue.service >/dev/null 2>&1 || true
  nft delete table inet soc_suricata_ips >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/soc-agent.service
  rm -f /etc/systemd/system/soc-suricata-nfqueue.service
  rm -f /etc/systemd/system/suricata.service.d/soc-inline-ips.conf
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
rm -rf /opt/soc-agent /var/log/soc-agent /etc/soc-agent
echo "SOC Agent removed."
`;

  const installPs1 = `# SOC Agent v${VERSION} - Universal Windows Installer
# Run as Administrator:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\\install.ps1
#Requires -RunAsAdministrator

param(
  [string]$InstallDir = "$env:ProgramFiles\\AJNAT",
  [string]$ServiceName = "SOCAgent"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Version = "${VERSION}"

Write-Host "SOC Agent v$Version universal Windows installer" -ForegroundColor Cyan
Write-Host "Company : ${company.name}" -ForegroundColor Gray
Write-Host "System  : ${system.name}" -ForegroundColor Gray
${windowsPasswordInstallSnippet()}

$python = $null
foreach ($cmd in @("python", "python3", "py")) {
  try {
    $ver = & $cmd --version 2>&1
    if ($ver -match "Python 3") {
      $python = $cmd
      break
    }
  } catch {}
}
if (-not $python) {
  $runtimeDir = Join-Path $InstallDir 'runtime\python'
  $installerPath = Join-Path $env:TEMP 'ajnat-python-3.12.10.exe'
  $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
  $pythonUrl = if ($architecture -eq 'arm64') {
    'https://www.python.org/ftp/python/3.12.10/python-3.12.10-arm64.exe'
  } else {
    'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe'
  }
  Write-Host 'Python 3 not found; installing the private AJNAT Python 3.12 runtime...' -ForegroundColor Yellow
  Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath -UseBasicParsing
  if ((Get-Item -LiteralPath $installerPath).Length -lt 5MB) { throw 'Python installer download is incomplete' }
  $pythonArguments = '/quiet InstallAllUsers=1 TargetDir="{0}" PrependPath=0 Include_launcher=0 AssociateFiles=0 Shortcuts=0 Include_pip=1 Include_test=0 Include_doc=0' -f $runtimeDir
  $pythonInstall = Start-Process -FilePath $installerPath -ArgumentList $pythonArguments -Wait -PassThru
  if ($pythonInstall.ExitCode -ne 0) { throw "Python installation failed with exit code $($pythonInstall.ExitCode)" }
  $python = Join-Path $runtimeDir 'python.exe'
}
$pythonPath = if (Test-Path -LiteralPath $python -PathType Leaf) { $python } else { (Get-Command $python).Source }

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$sourcePath = [System.IO.Path]::GetFullPath($ScriptDir).TrimEnd('\\')
$targetPath = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\\')
if (-not $sourcePath.Equals($targetPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    Copy-Item -Path "$ScriptDir\\*" -Destination $InstallDir -Recurse -Force
}
New-Item -ItemType Directory -Path "$InstallDir\\logs" -Force | Out-Null
try {
  $acl = Get-Acl "$InstallDir\\config\\company_config.json"
  $acl.SetAccessRuleProtection($true, $false)
  $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
  $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
  $acl.SetAccessRule($adminRule)
  $acl.AddAccessRule($systemRule)
  Set-Acl "$InstallDir\\config\\company_config.json" $acl
} catch {}
${windowsRoleGuardSnippet()}
${windowsLocationProviderInstallSnippet()}
${windowsVelociraptorInstallSnippet()}
${windowsNativeIpsBootstrapSnippet()}
${windowsNetworkSensorInstallSnippet()}
${windowsAdvancedProcessTelemetrySnippet()}

& $pythonPath -m pip install --quiet --disable-pip-version-check --upgrade -r "$InstallDir\requirements.txt"
if ($LASTEXITCODE -ne 0) { throw 'AJNAT Python dependency installation failed' }
& $pythonPath -c "import requests, psutil, watchdog, cryptography, socketio, websocket, yara, win32serviceutil, wmi"
if ($LASTEXITCODE -ne 0) { throw 'AJNAT Python dependency validation failed' }

$agentScript = "$InstallDir\\agent.py"
try { & sc.exe stop $ServiceName 2>$null | Out-Null } catch {}
try { & sc.exe delete $ServiceName 2>$null | Out-Null } catch {}
Start-Sleep -Seconds 1

$serviceWrapper = "$InstallDir\windows_service.py"
if (-not (Test-Path $serviceWrapper)) { throw "Native Windows service wrapper is missing" }
& $pythonPath -m pip install --quiet pywin32
if ($LASTEXITCODE -ne 0) { throw "pywin32 installation failed; Windows service cannot be registered" }
& $pythonPath $serviceWrapper --startup auto install
if ($LASTEXITCODE -ne 0) { throw "SOCAgent service registration failed" }
& sc.exe config $ServiceName start= delayed-auto | Out-Null
if ($LASTEXITCODE -ne 0) { throw "SOCAgent delayed startup configuration failed" }
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "SOCAgent recovery configuration failed" }
Start-Service $ServiceName -ErrorAction Stop
$service = Get-Service $ServiceName -ErrorAction Stop
$service.WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
if ((Get-Service $ServiceName).Status -ne 'Running') { throw "SOCAgent service did not reach Running state" }
$env:SOC_AGENT_CONFIG = "$InstallDir\config\company_config.json"
& $pythonPath "$InstallDir\agent.py" test
if ($LASTEXITCODE -ne 0) { throw 'SOCAgent health check failed' }
Start-Sleep -Seconds 5
if ((Get-Service $ServiceName).Status -ne 'Running') { throw "SOCAgent exited during the post-install stability check" }
${windowsProtectedAclSnippet()}

Write-Host "SOC Agent installed and verified. Check: Get-Service $ServiceName" -ForegroundColor Green
`;

  const uninstallPs1 = `# SOC Agent universal Windows uninstaller
#Requires -RunAsAdministrator
param(
  [string]$InstallDir = "$env:ProgramFiles\\AJNAT",
  [string]$ServiceName = "SOCAgent"
)
$ErrorActionPreference = "SilentlyContinue"
${windowsPasswordVerifySnippet()}
sc.exe stop $ServiceName | Out-Null
sc.exe delete $ServiceName | Out-Null
Remove-Item -Path $InstallDir -Recurse -Force
Write-Host "SOC Agent removed." -ForegroundColor Green
`;

  const readme = `SOC Agent v${VERSION} - Universal ZIP
Company : ${company.name}
System  : ${system.name}

Linux:
  unzip soc-agent_*_universal.zip
  cd soc-agent_*_universal
  sudo bash install.sh

macOS:
  unzip soc-agent_*_universal.zip
  cd soc-agent_*_universal
  sudo bash install.sh

Windows:
  Extract the zip
  Open PowerShell as Administrator
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\\install.ps1
`;

  zip.addFile(`${dirName}/install.sh`, Buffer.from(installSh, 'utf8'));
  zip.addFile(`${dirName}/uninstall.sh`, Buffer.from(uninstallSh, 'utf8'));
  zip.addFile(`${dirName}/install.ps1`, Buffer.from(installPs1, 'utf8'));
  zip.addFile(`${dirName}/uninstall.ps1`, Buffer.from(uninstallPs1, 'utf8'));
  zip.addFile(`${dirName}/README.txt`, Buffer.from(readme, 'utf8'));
  return zip.toBuffer();
}

// ─────────────────────────────────────────────────────────────────────────────
// .deb package  (Debian / Ubuntu / Kali / Mint)
// ─────────────────────────────────────────────────────────────────────────────
function buildDeb(system, company, agentConfig, options = {}) {
  const configJson = JSON.stringify(agentConfig, null, 2);
  const files      = collectAgentFiles();
  const INSTALL    = '/opt/soc-agent';
  const VERSION    = agentConfig.agent_version || DEFAULT_AGENT_VERSION;
  const tmpRoot    = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-agent-deb-'));
  const packageDir = path.join(tmpRoot, 'pkg');
  const debianDir  = path.join(packageDir, 'DEBIAN');
  const optDir     = path.join(packageDir, INSTALL);
  const outFile    = path.join(tmpRoot, `soc-agent_${packageVersion(VERSION)}_all.deb`);

  try {
    fs.mkdirSync(debianDir, { recursive: true });
    fs.mkdirSync(path.join(optDir, 'config'), { recursive: true });
    writeAgentFilesToDir(optDir, files);
    fs.writeFileSync(path.join(optDir, 'config', 'company_config.json'), configJson, 'utf8');
    fs.writeFileSync(path.join(optDir, 'README.txt'), readmeLin(system, company, 'deb', VERSION), 'utf8');
    // The endpoint already owns its Velociraptor installation during an agent
    // update. Re-bundling the large native client makes OTA downloads time out.
    if (!options.isAgentUpdate) {
      copyVelociraptorBundle(optDir, 'deb') || copyVelociraptorBundle(optDir, 'linuxBin');
    }
    chmodPackageTree(optDir);

    fs.writeFileSync(path.join(debianDir, 'control'), `Package: soc-agent
Version: ${packageVersion(VERSION)}
Section: admin
Priority: optional
Architecture: all
Maintainer: ${company.name} <admin@example.com>
Depends: python3, python3-pip, python3-venv, systemd
Description: SOC endpoint security agent
 SOC Agent configured for ${company.name} / ${system.name}.
`, 'utf8');

    fs.writeFileSync(path.join(debianDir, 'preinst'), linuxPreInstallScript(), 'utf8');
    fs.writeFileSync(path.join(debianDir, 'postinst'), linuxPostInstallScript(system, company, VERSION, 'apt'), 'utf8');
    fs.writeFileSync(path.join(debianDir, 'prerm'), linuxPreRemoveScript(true), 'utf8');
    fs.writeFileSync(path.join(debianDir, 'postrm'), linuxPostRemoveScript(), 'utf8');
    fs.chmodSync(path.join(debianDir, 'preinst'), 0o755);
    fs.chmodSync(path.join(debianDir, 'postinst'), 0o755);
    fs.chmodSync(path.join(debianDir, 'prerm'), 0o755);
    fs.chmodSync(path.join(debianDir, 'postrm'), 0o755);

    execFileSync('dpkg-deb', ['--build', '--root-owner-group', packageDir, outFile], { stdio: 'pipe', timeout: 120000 });
    return fs.readFileSync(outFile);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// .rpm package  (RHEL / CentOS / Fedora / Rocky)
// ─────────────────────────────────────────────────────────────────────────────
function buildRpm(system, company, agentConfig, options = {}) {
  const configJson = JSON.stringify(agentConfig, null, 2);
  const files      = collectAgentFiles();
  const INSTALL    = '/opt/soc-agent';
  const VERSION    = agentConfig.agent_version || DEFAULT_AGENT_VERSION;
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-agent-rpm-'));
  const topDir  = path.join(tmpRoot, 'rpmbuild');
  const buildRoot = path.join(tmpRoot, 'buildroot');
  const optDir = path.join(buildRoot, INSTALL);
  const version = packageVersion(VERSION);

  try {
    for (const dir of ['BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS']) {
      fs.mkdirSync(path.join(topDir, dir), { recursive: true });
    }
    fs.mkdirSync(path.join(optDir, 'config'), { recursive: true });
    writeAgentFilesToDir(optDir, files);
    fs.writeFileSync(path.join(optDir, 'config', 'company_config.json'), configJson, 'utf8');
    fs.writeFileSync(path.join(optDir, 'README.txt'), readmeLin(system, company, 'rpm', VERSION), 'utf8');
    if (!options.isAgentUpdate) {
      copyVelociraptorBundle(optDir, 'rpm') || copyVelociraptorBundle(optDir, 'linuxBin');
    }
    chmodPackageTree(optDir);

    const spec = `Name: soc-agent
Version: ${version}
Release: 1%{?dist}
Summary: SOC endpoint security agent
License: Proprietary
BuildArch: noarch
Requires: python3
Requires: python3-pip
Requires: systemd

%description
SOC Agent configured for ${company.name} / ${system.name}.

%prep

%build

%install
mkdir -p %{buildroot}/opt
cp -a ${buildRoot}/opt/soc-agent %{buildroot}/opt/

%post -p /bin/bash
${linuxPostInstallScript(system, company, VERSION, 'dnf')}

%preun -p /bin/bash
if [ "$1" = "0" ]; then
${linuxPreRemoveScript(true)}
fi

%postun -p /bin/bash
if [ "$1" = "0" ]; then
${linuxPostRemoveScript()}
fi

%files
%defattr(-,root,root,-)
/opt/soc-agent
`;

    const specPath = path.join(topDir, 'SPECS', 'soc-agent.spec');
    fs.writeFileSync(specPath, spec, 'utf8');
    execFileSync('rpmbuild', ['--define', `_topdir ${topDir}`, '--define', '_build_id_links none', '-bb', specPath], {
      stdio: 'pipe',
      timeout: 120000,
    });

    const rpmDir = path.join(topDir, 'RPMS', 'noarch');
    const rpmFile = fs.readdirSync(rpmDir).find(name => name.endsWith('.rpm'));
    if (!rpmFile) throw new Error('RPM build finished but output file was not found');
    return fs.readFileSync(path.join(rpmDir, rpmFile));
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// .exe package  (Windows — staged PowerShell installer + native pywin32 service)
// ─────────────────────────────────────────────────────────────────────────────
function buildExe(system, company, agentConfig, options = {}) {
  const AdmZip     = require('adm-zip');
  const tlsPackage = prepareWindowsTlsPackage(agentConfig);
  const publisherCertificate = loadWindowsPublisherCertificate();
  const effectiveAgentConfig = tlsPackage.config;
  const configJson = JSON.stringify(effectiveAgentConfig, null, 2);
  const b64Config  = Buffer.from(configJson, 'utf8').toString('base64');
  const files      = collectAgentFiles();
  const zip        = new AdmZip();
  const dirName    = `soc-agent_${sanitize(system.name)}_windows`;
  const VERSION    = effectiveAgentConfig.agent_version || DEFAULT_AGENT_VERSION;

  addAgentFiles(zip, files, dirName);
  zip.addFile(`${dirName}/config/company_config.json`, Buffer.from(configJson, 'utf8'));
  if (tlsPackage.caBundle) {
    zip.addFile(`${dirName}/certs/server-ca-bundle.pem`, tlsPackage.caBundle.content);
  }
  if (publisherCertificate) {
    zip.addFile(`${dirName}/certs/AJNAT-Local-Test-Publisher.cer`, publisherCertificate.content);
  }
  // The Windows client is about 70 MB and can exhaust NSIS memory during
  // on-demand builds. Fresh installers download it from the authenticated
  // AJNAT dependency endpoint. Air-gapped deployments may opt into embedding.
  const embedWindowsVelociraptor = String(process.env.AGENT_EMBED_WINDOWS_VELOCIRAPTOR || '').toLowerCase() === 'true';
  if (!options.isAgentUpdate && embedWindowsVelociraptor) {
    addVelociraptorBundleToZip(zip, dirName, 'winExe')
      || addVelociraptorBundleToZip(zip, dirName, 'winMsi');
  }

  // UTF-8 BOM fixes "Missing closing }" on Windows PS - emoji in strings
  // confuse the ANSI parser; BOM forces PowerShell to use UTF-8 mode.
  const PS1_BOM = '\uFEFF';
  const installPs1 = PS1_BOM + `# SOC Agent v${VERSION} - Windows Installer
# Company : ${company.name}
# System  : ${system.name}
# Version : ${VERSION}
#
# Run as Administrator:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\\install.ps1
#
# Supports: Fresh install AND update (safe to re-run)
#Requires -RunAsAdministrator

param(
  [string]$InstallDir  = "$env:ProgramFiles\\AJNAT",
  [string]$ServiceName = "SOCAgent"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Version   = "${VERSION}"
$DataDir = Join-Path $env:ProgramData "AJNAT"
$ConfigDir = Join-Path $DataDir "config"
$LogDir = Join-Path $DataDir "logs"
$InstallLog = Join-Path $LogDir "install.log"
$ServiceInstallLog = Join-Path $LogDir "service-install.log"
$UpdateLog = Join-Path $LogDir "update-rollback.log"
$BootstrapLog = Join-Path $env:TEMP "soc-agent-install-bootstrap.log"
$CurrentOperation = "initialization"
$IsUpdate = $false
try {
    $IsUpdate = [bool](Test-Path -LiteralPath "$InstallDir\\agent.py" -ErrorAction Stop)
} catch {
    # Legacy installers could protect the directory so aggressively that even
    # Test-Path throws AccessDenied. The service registration is a safe update
    # signal until the ACL is repaired below.
    $IsUpdate = $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
}
$BackupDir = Join-Path $env:TEMP ("AJNAT-backup-" + [guid]::NewGuid().ToString("N"))
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Administrator privileges are required" }
function Repair-InstallerAccess([string]$Path) {
    $pathAccessible = $false
    try { $pathAccessible = [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) } catch {}
    if (-not $pathAccessible) {
        # A missing path should simply be created. If it exists but an old ACL
        # hides it from Test-Path, creation fails and we continue to takeown.
        try {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
            return
        } catch {}
    }
    # Recover installations hardened by an older ACL routine. SID-based grants
    # work on every Windows display language and preserve no user write access.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $takeownOutput = & takeown.exe /F $Path /A /R /D Y 2>&1
        $takeownCode = $LASTEXITCODE
        if ($takeownCode -ne 0) { throw ("takeown exit {0}: {1}" -f $takeownCode, ($takeownOutput -join ' ')) }
        # Reset removes any explicit deny ACE left by an older installer before
        # restoring full control to SYSTEM and local Administrators.
        $resetOutput = & icacls.exe $Path /reset /T /C /Q 2>&1
        $resetCode = $LASTEXITCODE
        if ($resetCode -ne 0) { throw ("ACL reset exit {0}: {1}" -f $resetCode, ($resetOutput -join ' ')) }
        $grantOutput = & icacls.exe $Path /inheritance:e /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>&1
        $grantCode = $LASTEXITCODE
        if ($grantCode -ne 0) { throw ("ACL grant exit {0}: {1}" -f $grantCode, ($grantOutput -join ' ')) }
        $directOutput = & icacls.exe $Path /grant '*S-1-5-18:F' '*S-1-5-32-544:F' /T /C /Q 2>&1
        $directCode = $LASTEXITCODE
        if ($directCode -ne 0) { throw ("Direct ACL grant exit {0}: {1}" -f $directCode, ($directOutput -join ' ')) }
    } catch {
        throw ("Could not repair administrator access to {0}: {1}" -f $Path, $_.Exception.Message)
    } finally {
        $ErrorActionPreference = $savedPreference
    }
}
Repair-InstallerAccess -Path $InstallDir
if ($IsUpdate) {
    # Do not recursively walk all of ProgramData during OTA. Runtime logs,
    # spools, and retained forensic state can make that walk outlive the old
    # agent's ten-minute updater timeout. Only installer-owned config/log paths
    # need repair; existing runtime state is deliberately left untouched.
    Repair-InstallerAccess -Path $ConfigDir
    Repair-InstallerAccess -Path $LogDir
} else {
    Repair-InstallerAccess -Path $DataDir
}
New-Item -ItemType Directory -Path $ConfigDir,$LogDir -Force | Out-Null
$BackupComplete = $false
function Invoke-Sc([string[]]$Arguments, [int[]]$AllowedExitCodes = @(0)) {
    $output = & sc.exe @Arguments 2>&1
    $code = $LASTEXITCODE
    Add-Content -LiteralPath $ServiceInstallLog -Value "$(Get-Date -Format o) sc.exe $($Arguments -join ' ') exit=$code output=$($output -join ' ')" -Encoding UTF8
    if ($AllowedExitCodes -notcontains $code) { throw "sc.exe $($Arguments[0]) failed with Windows exit code $code" }
    return $output
}
function Invoke-Native([string]$FilePath, [string[]]$Arguments, [string]$Description) {
    # Windows PowerShell can promote native stderr to a terminating error when
    # ErrorActionPreference is Stop. Capture and validate the exit code here.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $FilePath @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($output) {
        $output | ForEach-Object { Write-Host "  $_" }
        $output | Add-Content -LiteralPath $ServiceInstallLog -Encoding UTF8
    }
    Add-Content -LiteralPath $ServiceInstallLog -Value "$(Get-Date -Format o) $Description args=$($Arguments -join ' ') exit=$code" -Encoding UTF8
    if ($code -ne 0) { throw "$Description failed with exit code $code" }
}
function Write-ServiceDiagnostics {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Add-Content -LiteralPath $ServiceInstallLog -Value "$(Get-Date -Format o) operation=$CurrentOperation service=$ServiceName state=$(if ($svc) {$svc.Status} else {'missing'}) python=$pythonPath wrapper=$InstallDir\\windows_service.py" -Encoding UTF8
    try {
        Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=(Get-Date).AddMinutes(-10) } -ErrorAction Stop |
            Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Message -like "*$ServiceName*" } |
            Select-Object -First 20 TimeCreated,Id,LevelDisplayName,Message |
            Format-List | Out-String | Add-Content -LiteralPath $ServiceInstallLog -Encoding UTF8
    } catch {}
}
try { Start-Transcript -Path $InstallLog -Force | Out-Null } catch {}
trap {
    $errorRecord = $_
    $exitCode = if ($LASTEXITCODE -is [int] -and $LASTEXITCODE -ne 0) { $LASTEXITCODE } else { 1 }
    $failure = "$(Get-Date -Format o) INSTALL FAILED mode=$(if ($IsUpdate) {'update'} else {'install'}) version=$Version operation=$CurrentOperation exit=$exitCode exception=$($errorRecord.Exception.GetType().FullName) message=$($errorRecord.Exception.Message) service=$ServiceName"
    Write-Host $failure -ForegroundColor Red
    try { Add-Content -LiteralPath $BootstrapLog -Value $failure -Encoding UTF8 } catch {}
    # Start-Transcript owns install.log and can lock it on Windows PowerShell 5.
    # Write-Host is already captured there; use the separate service log too.
    try { Add-Content -LiteralPath $ServiceInstallLog -Value $failure -Encoding UTF8 } catch {}
    try { Write-ServiceDiagnostics } catch {}
    if ($IsUpdate -and $BackupComplete -and (Test-Path $BackupDir)) {
        try {
            $CurrentOperation = "rollback"
            Add-Content -LiteralPath $UpdateLog -Value "$(Get-Date -Format o) rollback started" -Encoding UTF8
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Repair-InstallerAccess -Path $InstallDir
            Copy-Item -Path "$BackupDir\\app\\*" -Destination $InstallDir -Recurse -Force
            if (Test-Path "$BackupDir\\config\\company_config.json") { Copy-Item "$BackupDir\\config\\company_config.json" "$ConfigDir\\company_config.json" -Force }
            if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and (Test-Path "$InstallDir\\windows_service.py")) {
                & $pythonPath "$InstallDir\\windows_service.py" --startup auto install | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "rollback service registration failed with exit code $LASTEXITCODE" }
                & sc.exe config $ServiceName start= delayed-auto | Out-Null
            }
            Start-Service -Name $ServiceName -ErrorAction Stop
            (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            Add-Content -LiteralPath $UpdateLog -Value "$(Get-Date -Format o) rollback restored previous files/config and running service" -Encoding UTF8
        } catch { try { Add-Content -LiteralPath $UpdateLog -Value "$(Get-Date -Format o) rollback failed: $($_.Exception.Message)" -Encoding UTF8 } catch {} }
    } elseif ($IsUpdate) {
        # Before BackupComplete no installed file has been overwritten. If a
        # backup read fails, simply bring the untouched previous agent online.
        try {
            $existingServiceAfterFailure = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($existingServiceAfterFailure -and $existingServiceAfterFailure.Status -ne 'Running') {
                Start-Service -Name $ServiceName -ErrorAction Stop
                $existingServiceAfterFailure.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            }
        } catch {}
    }
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  SOC Agent v$Version - Windows"           -ForegroundColor White
Write-Host "  Company : ${company.name}"               -ForegroundColor Gray
Write-Host "  System  : ${system.name}"                -ForegroundColor Gray
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# -- Detect update vs fresh install --
if ($IsUpdate) {
    Write-Host "[UPDATE] Existing install detected - performing UPDATE ..." -ForegroundColor Yellow
} else {
    Write-Host "[NEW] Fresh installation ..." -ForegroundColor Green
}

# -- Step 1: Find Python --
Write-Host "[ 1/5 ] Checking Python ..." -ForegroundColor Yellow
$pythonPath = $null
$privatePythonRuntimeDir = Join-Path $InstallDir 'runtime\\python'
$pythonRuntimeDir = $privatePythonRuntimeDir
$packageDir = Join-Path $InstallDir 'packages'
New-Item -ItemType Directory -Path $privatePythonRuntimeDir,$packageDir -Force | Out-Null
$pythonCandidates = @(
    # A complete private install is valid. Do not select runtime\\python\\Scripts:
    # that is a venv, whose embedded pythonservice.exe cannot start reliably
    # under SCM on supported Windows builds.
    (Join-Path $privatePythonRuntimeDir 'python.exe'),
    "$env:ProgramFiles\\Python313\\python.exe",
    "$env:ProgramFiles\\Python312\\python.exe",
    "\${env:ProgramFiles(x86)}\\Python313\\python.exe",
    "\${env:ProgramFiles(x86)}\\Python312\\python.exe",
    "$env:LocalAppData\\Programs\\Python\\Python313\\python.exe",
    "$env:LocalAppData\\Programs\\Python\\Python312\\python.exe"
)
try { $pythonCandidates += (& py.exe -0p 2>$null | ForEach-Object { ($_ -replace '^\\s*-V:[^\\s]+\\s*', '').Trim() }) } catch {}
foreach ($commandName in @('python', 'python3')) {
    try { $pythonCandidates += (Get-Command $commandName -ErrorAction Stop).Source } catch {}
}
foreach ($candidate in ($pythonCandidates | Select-Object -Unique)) {
    if (-not $candidate -or -not (Test-Path $candidate)) { continue }
    try {
        $versionText = & $candidate -c "import sys; print(str(sys.version_info.major) + '.' + str(sys.version_info.minor))" 2>$null
        $parts = $versionText.Trim().Split('.')
        if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 8 -and [int]$parts[1] -le 13) {
            $pythonPath = $candidate
            break
        }
    } catch {}
}
if (-not $pythonPath) {
    $osArchitecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    $machineArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($machineArchitecture -eq 'Arm64') {
        $pythonPackage = 'python-3.12.10-arm64.exe'
        $architectureLabel = 'ARM64'
    } elseif ($osArchitecture -match '64') {
        $pythonPackage = 'python-3.12.10-amd64.exe'
        $architectureLabel = 'x64'
    } else {
        $pythonPackage = 'python-3.12.10.exe'
        $architectureLabel = 'x86'
    }
    $pythonInstaller = Join-Path $packageDir $pythonPackage
    $pythonUrl = "https://www.python.org/ftp/python/3.12.10/$pythonPackage"
    Write-Host "  Supported Python not found; downloading Python 3.12 ($architectureLabel) ..." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing -TimeoutSec 300
    } catch {
        Write-Host "  Primary download failed; retrying with BITS ..." -ForegroundColor Yellow
        Import-Module BitsTransfer -ErrorAction Stop
        Start-BitsTransfer -Source $pythonUrl -Destination $pythonInstaller -ErrorAction Stop
    } finally {
        $ProgressPreference = $oldProgress
    }
    if (-not (Test-Path $pythonInstaller) -or (Get-Item $pythonInstaller).Length -lt 5MB) {
        throw "Python $architectureLabel installer download is incomplete"
    }
    Write-Host "  Installing Python 3.12 ($architectureLabel) silently ..." -ForegroundColor Yellow
    $CurrentOperation = "install-python-runtime"
    # Start-Process joins a string[] without preserving quotes. TargetDir is
    # below Program Files, so pass one explicitly quoted command line.
    $pythonArguments = '/quiet InstallAllUsers=1 TargetDir="{0}" PrependPath=0 Include_launcher=0 AssociateFiles=0 Shortcuts=0 Include_pip=1 Include_test=0 Include_doc=0' -f $privatePythonRuntimeDir
    $install = Start-Process -FilePath $pythonInstaller -ArgumentList $pythonArguments -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw "Supported Python installation failed with exit code $($install.ExitCode)" }
    $pythonPath = Join-Path $privatePythonRuntimeDir 'python.exe'
    if (-not (Test-Path $pythonPath)) { throw "Python 3.12 installation completed but python.exe was not found" }
}
$pythonRuntimeDir = ([string](& $pythonPath -c 'import sys; print(sys.exec_prefix)')).Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonRuntimeDir)) { throw 'Could not resolve the selected Python runtime directory' }
Write-Host "  OK: $pythonPath" -ForegroundColor Green

# -- Step 2: Install agent files --
$CurrentOperation = "stage-and-preserve"
Write-Host "[ 2/5 ] Installing to $InstallDir ..." -ForegroundColor Yellow
if ($IsUpdate) {
    $CurrentOperation = "stop-existing-service"
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService -and $existingService.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        $existingService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $installedAgent = [System.IO.Path]::GetFullPath("$InstallDir\\agent.py")
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($installedAgent, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 } |
        ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction Stop | Out-Null }
    # Re-run the recursive repair after all agent processes have stopped.
    # Older releases protected child files without inheritable Administrator
    # rules, which can otherwise make an in-place update fail on one collector.
    $CurrentOperation = "repair-existing-install-access"
    Repair-InstallerAccess -Path $InstallDir
    $CurrentOperation = "backup-existing-install"
    New-Item -ItemType Directory -Path "$BackupDir\\app","$BackupDir\\config" -Force | Out-Null
    Copy-Item -Path "$InstallDir\\*" -Destination "$BackupDir\\app" -Recurse -Force
    $existingConfig = @(
        "$ConfigDir\\company_config.json",
        "$InstallDir\\config\\company_config.json",
        "$env:ProgramData\\SOCAgent\\config\\company_config.json"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($existingConfig) { Copy-Item -LiteralPath $existingConfig -Destination "$BackupDir\\config\\company_config.json" -Force }
    $BackupComplete = $true
}
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
$sourcePath = [System.IO.Path]::GetFullPath($ScriptDir).TrimEnd('\\')
$targetPath = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\\')
if (-not $sourcePath.Equals($targetPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    Copy-Item -Path "$ScriptDir\\*" -Destination $InstallDir -Recurse -Force
}

$CurrentOperation = "install-enrollment-configuration"
${windowsPublisherProvisionSnippet(publisherCertificate)}
${windowsCaProvisionSnippet(tlsPackage.caBundle)}
$configPath = "$ConfigDir\\company_config.json"
try {
    $configBytes = [System.Convert]::FromBase64String("${b64Config}")
    $packagedConfig = [System.Text.Encoding]::UTF8.GetString($configBytes) | ConvertFrom-Json
    $configToInstall = $packagedConfig
    $backupConfigPath = "$BackupDir\\config\\company_config.json"
    if ($IsUpdate -and (Test-Path -LiteralPath $backupConfigPath)) {
        try {
            $existingConfig = Get-Content -LiteralPath $backupConfigPath -Raw | ConvertFrom-Json
            $sameCompany = [string]::Equals([string]$existingConfig.company_id, [string]$packagedConfig.company_id, [System.StringComparison]::OrdinalIgnoreCase)
            $sameSystem = [string]::Equals([string]$existingConfig.system_id, [string]$packagedConfig.system_id, [System.StringComparison]::OrdinalIgnoreCase)
            $sameAgentKey = [string]::Equals([string]$existingConfig.agent_key, [string]$packagedConfig.agent_key, [System.StringComparison]::Ordinal)
            if ($sameCompany -and $sameSystem -and $sameAgentKey) {
                # Retain unknown local extension keys, but refresh every setting and
                # credential supplied by the newly downloaded package.
                foreach ($property in $packagedConfig.PSObject.Properties) {
                    if ($existingConfig.PSObject.Properties.Name -contains $property.Name) {
                        $existingConfig.($property.Name) = $property.Value
                    } else {
                        $existingConfig | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
                    }
                }
                $configToInstall = $existingConfig
                Write-Host "  OK: Matching enrollment retained and refreshed" -ForegroundColor Green
            } else {
                Write-Host "  INFO: Package targets a different or refreshed enrollment; replacing stale agent identity" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  WARN: Existing configuration is invalid; replacing it with packaged enrollment" -ForegroundColor Yellow
        }
    }
    if ($configToInstall.PSObject.Properties.Name -contains 'agent_version') {
        $configToInstall.agent_version = $Version
    } else {
        $configToInstall | Add-Member -NotePropertyName agent_version -NotePropertyValue $Version
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($configPath, ($configToInstall | ConvertTo-Json -Depth 30), $utf8NoBom)
} catch { throw "Could not install packaged enrollment configuration: $($_.Exception.Message)" }
Remove-Item "$InstallDir\\config\\company_config.json" -Force -ErrorAction SilentlyContinue
try {
    $acl = Get-Acl $configPath
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
    $acl.SetAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl $configPath $acl
} catch { throw "Could not secure service configuration: $($_.Exception.Message)" }
Write-Host "  OK: Files installed (v$Version)" -ForegroundColor Green
${windowsRoleGuardSnippet()}
${windowsLocationProviderInstallSnippet()}
$CurrentOperation = "preserve-uninstall-password"
${windowsPasswordInstallSnippet()}
if ($IsUpdate) {
    Write-Host "  INFO: Keeping the existing Velociraptor and packet-sensor installation during agent update." -ForegroundColor Gray
} else {
${windowsVelociraptorInstallSnippet()}
}
${windowsNativeIpsBootstrapSnippet()}
if (-not $IsUpdate) {
${windowsNetworkSensorInstallSnippet()}
}
${windowsAdvancedProcessTelemetrySnippet()}

# -- Step 3: Python dependencies --
Write-Host "[ 3/5 ] Checking Python dependencies ..." -ForegroundColor Yellow
$CurrentOperation = "install-python-dependencies"
$requiredImportsReady = $false
$savedPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & $pythonPath -c "import requests, psutil, watchdog, cryptography, socketio, websocket, yara, win32serviceutil, wmi" *> $null
    $requiredImportsReady = ($LASTEXITCODE -eq 0)
} finally {
    $ErrorActionPreference = $savedPreference
}
if ($requiredImportsReady) {
    Write-Host "  OK: Existing dependencies retained" -ForegroundColor Green
} else {
    $env:PIP_CACHE_DIR = Join-Path $packageDir 'pip-cache'
    New-Item -ItemType Directory -Path $env:PIP_CACHE_DIR -Force | Out-Null
    $requiredPackages = @(
        'requests', 'urllib3<3', 'psutil', 'watchdog', 'cryptography',
        'python-socketio[client]', 'websocket-client', 'yara-python', 'pywin32', 'wmi'
    )
    Invoke-Native -FilePath $pythonPath -Arguments (@('-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', '--upgrade') + $requiredPackages) -Description 'Required AJNAT Python dependencies installation'
    Invoke-Native -FilePath $pythonPath -Arguments @('-c', 'import requests, psutil, watchdog, cryptography, socketio, websocket, yara, win32serviceutil, wmi') -Description 'Required AJNAT Python dependencies validation'
    Write-Host "  OK: All required Python packages installed and verified" -ForegroundColor Green
}

# -- Step 4: Native pywin32 Windows service --
$CurrentOperation = "install-windows-service"
Write-Host "[ 4/5 ] Setting up Windows Service ..." -ForegroundColor Yellow
$serviceWrapper = "$InstallDir\\windows_service.py"
if (-not (Test-Path -LiteralPath $serviceWrapper)) { throw "Native Windows service wrapper is missing: $serviceWrapper" }
# Updating the stopped service in place avoids Windows error 1072
# (ERROR_SERVICE_MARKED_FOR_DELETE), which can persist while another process
# such as Services.msc still has a handle to the old service.
$serviceExists = $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
$CurrentOperation = "install-pywin32"
if (-not $requiredImportsReady) {
    Invoke-Native -FilePath $pythonPath -Arguments @('-m', 'pip', 'install', '--quiet', '--upgrade', 'pywin32') -Description 'pywin32 installation'
}
$pythonDir = Split-Path -Parent $pythonPath
$pywin32PostInstall = @(
    (Join-Path $pythonDir 'pywin32_postinstall.py'),
    (Join-Path $pythonDir 'Scripts\\pywin32_postinstall.py')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (Test-Path -LiteralPath $pywin32PostInstall) {
    $CurrentOperation = "initialize-pywin32"
    Invoke-Native -FilePath $pythonPath -Arguments @($pywin32PostInstall, '-install') -Description 'pywin32 initialization'
}
${windowsPywin32ServiceHostSnippet('Invoke-Native')}
$CurrentOperation = "validate-pywin32"
Invoke-Native -FilePath $pythonPath -Arguments @('-c', 'import win32serviceutil, win32service, servicemanager') -Description 'pywin32 import validation'
$serviceAction = if ($serviceExists) { 'update' } else { 'install' }
$CurrentOperation = "$serviceAction-windows-service"
Invoke-Native -FilePath $pythonPath -Arguments @($serviceWrapper, '--startup', 'auto', $serviceAction) -Description "Native service $serviceAction"
$CurrentOperation = "configure-windows-service"
Invoke-Sc -Arguments @('description', $ServiceName, 'AJNAT endpoint security monitoring and response agent') | Out-Null
Invoke-Sc -Arguments @('config', $ServiceName, 'start=', 'delayed-auto') | Out-Null
Invoke-Sc -Arguments @('failureflag', $ServiceName, '1') | Out-Null
Invoke-Sc -Arguments @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/60000') | Out-Null

$CurrentOperation = "start-and-verify-service"
Start-Service $ServiceName -ErrorAction Stop
$service = Get-Service $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Running') {
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}
$service = Get-Service $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Running') { throw "SOCAgent service was created but did not reach Running state" }
Write-Host "  VERIFIED: Service '$ServiceName' is Running" -ForegroundColor Green

# -- Step 5: Test connection --
$CurrentOperation = "health-check"
Write-Host "[ 5/5 ] Testing connection ..." -ForegroundColor Yellow
$env:AJNAT_DATA_DIR = $DataDir
$env:SOC_AGENT_CONFIG = $configPath
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$previousConsoleOutputEncoding = [Console]::OutputEncoding
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$healthDeadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $healthDeadline -and -not (Test-Path "$LogDir\\agent.log")) { Start-Sleep -Seconds 1 }
if (-not (Test-Path "$LogDir\\agent.log")) { throw "Agent runtime log was not created within 30 seconds" }
try {
    Invoke-Native -FilePath $pythonPath -Arguments @("$InstallDir\\agent.py", 'test', '--config', $configPath) -Description 'Agent health check'
} finally {
    [Console]::OutputEncoding = $previousConsoleOutputEncoding
}
# A service can briefly report Running before its child exits. Require it to
# remain alive after the health test so installation cannot report success for
# a transient start.
Start-Sleep -Seconds 5
$service = Get-Service $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Running') { throw "SOCAgent exited during the post-install stability check" }
${windowsProtectedAclSnippet()}
Write-Host "  VERIFIED: Runtime log and health check succeeded" -ForegroundColor Green
if (Test-Path $BackupDir) { Remove-Item $BackupDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
if ($IsUpdate) {
    Write-Host "  [OK] SOC Agent UPDATED to v$Version!" -ForegroundColor Green
} else {
    Write-Host "  [OK] SOC Agent v$Version installed!"  -ForegroundColor Green
}
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Logs   : $LogDir\\agent.log"              -ForegroundColor Gray
Write-Host "  Test   : $pythonPath $InstallDir\\agent.py test" -ForegroundColor Gray
Write-Host "  Stop   : Stop-Service $ServiceName"      -ForegroundColor Gray
Write-Host "  Remove : .\\uninstall.ps1"               -ForegroundColor Gray
Write-Host ""
try { Stop-Transcript | Out-Null } catch {}
`;

  // OTA deliberately uses a small, bounded updater. The full installer is for
  // fresh/interactive repair and performs dependency, ACL, backup, sensor, and
  // health checks which must never hold an already-enrolled service offline.
  const updatePs1 = PS1_BOM + `# SOC Agent v${VERSION} - bounded Windows OTA updater
#Requires -RunAsAdministrator
param(
  [string]$InstallDir = "$env:ProgramFiles\\AJNAT",
  [string]$ServiceName = "SOCAgent"
)
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DataDir = Join-Path $env:ProgramData 'AJNAT'
$ConfigDir = Join-Path $DataDir 'config'
$LogDir = Join-Path $DataDir 'logs'
$LogPath = Join-Path $LogDir 'ota-update.log'
$InstallLogPath = Join-Path $LogDir 'install.log'
New-Item -ItemType Directory -Path $ConfigDir,$LogDir -Force | Out-Null
function Write-OtaLog([string]$Message) {
  Add-Content -LiteralPath $LogPath -Value ("$(Get-Date -Format o) $Message") -Encoding UTF8
}
try {
  Write-OtaLog 'bounded OTA started target=${VERSION}'
  $service = Get-Service -Name $ServiceName -ErrorAction Stop
  if ($service.Status -ne 'Stopped') {
    & sc.exe stop $ServiceName | Out-Null
    $deadline = (Get-Date).AddSeconds(30)
    do {
      Start-Sleep -Milliseconds 500
      $service = Get-Service -Name $ServiceName -ErrorAction Stop
    } while ($service.Status -ne 'Stopped' -and (Get-Date) -lt $deadline)
    if ($service.Status -ne 'Stopped') { throw 'SOCAgent did not stop within 30 seconds' }
  }

  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  $copyArgs = @(
    $ScriptDir, $InstallDir, '/E', '/R:1', '/W:1', '/NFL', '/NDL', '/NJH', '/NJS', '/NP',
    '/XD', (Join-Path $ScriptDir 'config'),
    '/XF', 'install.bat', 'install.ps1', 'install-update.ps1', 'README.txt'
  )
  & robocopy.exe @copyArgs | Out-Null
  $copyCode = $LASTEXITCODE
  if ($copyCode -ge 8) { throw "Agent file copy failed with robocopy exit code $copyCode" }

  # pythonservice.exe imports the registered class from site-packages, not
  # from the service working directory. Keep that copy in sync during bounded
  # OTA updates as well as full EXE/MSI installs.
  $privatePythonRuntimeDir = Join-Path $InstallDir 'runtime\\python'
  $pythonPath = @(
    (Join-Path $privatePythonRuntimeDir 'python.exe'),
    "$env:ProgramFiles\\Python313\\python.exe",
    "$env:ProgramFiles\\Python312\\python.exe",
    "\${env:ProgramFiles(x86)}\\Python313\\python.exe",
    "\${env:ProgramFiles(x86)}\\Python312\\python.exe"
  ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $pythonPath) { throw 'A supported system or AJNAT Python runtime is missing after the update copy' }
  $pythonRuntimeDir = ([string](& $pythonPath -c 'import sys; print(sys.exec_prefix)')).Trim()
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonRuntimeDir)) {
    throw 'Could not resolve the selected Python runtime directory during update'
  }
  $serviceSitePackages = ([string](& $pythonPath -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")).Trim()
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $serviceSitePackages)) {
    throw 'Could not resolve AJNAT Python site-packages during update'
  }
  Copy-Item -LiteralPath (Join-Path $InstallDir 'windows_service.py') -Destination (Join-Path $serviceSitePackages 'windows_service.py') -Force

  $configPath = Join-Path $ConfigDir 'company_config.json'
${windowsPublisherProvisionSnippet(publisherCertificate)}
${windowsCaProvisionSnippet(tlsPackage.caBundle)}
  if (-not (Test-Path -LiteralPath $configPath)) {
    $configBytes = [Convert]::FromBase64String("${b64Config}")
    [IO.File]::WriteAllBytes($configPath, $configBytes)
  }
  $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
  $packagedConfigBytes = [Convert]::FromBase64String("${b64Config}")
  $packagedConfig = [Text.Encoding]::UTF8.GetString($packagedConfigBytes) | ConvertFrom-Json
  foreach ($tlsProperty in @('require_tls', 'tls_ca_bundle', 'tls_server_sha256')) {
    if ($packagedConfig.PSObject.Properties.Name -contains $tlsProperty) {
      if ($config.PSObject.Properties.Name -contains $tlsProperty) {
        $config.($tlsProperty) = $packagedConfig.($tlsProperty)
      } else {
        $config | Add-Member -NotePropertyName $tlsProperty -NotePropertyValue $packagedConfig.($tlsProperty)
      }
    }
  }
  if ($config.PSObject.Properties.Name -contains 'agent_version') {
    $config.agent_version = '${VERSION}'
  } else {
    $config | Add-Member -NotePropertyName agent_version -NotePropertyValue '${VERSION}'
  }
  [IO.File]::WriteAllText(
    $configPath,
    ($config | ConvertTo-Json -Depth 30),
    (New-Object Text.UTF8Encoding($false))
  )

${options.includeVelociraptor ? `  try {
    $velociraptorServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Velociraptor*' })
    if ($velociraptorServices.Count -eq 0) {
      $velociraptorDir = Join-Path $InstallDir 'velociraptor'
      $velociraptorBundle = Join-Path $velociraptorDir 'velociraptor_client_repacked.exe'
      New-Item -ItemType Directory -Path $velociraptorDir -Force | Out-Null
      $serverUrl = ([string]$config.server_url).TrimEnd('/')
      $agentKey = [Uri]::EscapeDataString([string]$config.agent_key)
      $dependencyUrl = "$serverUrl/api/agent/self-update/dependency/velociraptor/windows?agent_key=$agentKey"
      $headers = @{}
      if ($config.integration_secret) { $headers['x-integration-secret'] = [string]$config.integration_secret }
      Invoke-WebRequest -Uri $dependencyUrl -Headers $headers -OutFile $velociraptorBundle -UseBasicParsing -TimeoutSec 300
      if ((Get-Item -LiteralPath $velociraptorBundle).Length -lt 1MB) { throw 'Downloaded Velociraptor bundle is incomplete' }
    }
${windowsVelociraptorInstallSnippet()}
    Write-OtaLog 'Velociraptor client install/enrollment launched'
  } catch {
    # Forensic enrollment must not leave the primary AJNAT service offline.
    Write-OtaLog ("Velociraptor enrollment failed: " + $_.Exception.Message)
  }
` : ''}

  Start-Service -Name $ServiceName -ErrorAction Stop
  (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
  $installStatus = @(
    '',
    '==========================================',
    '  [OK] SOC Agent OTA UPDATED to v${VERSION}!',
    '  Service: Running',
    "  Updated: $(Get-Date -Format o)",
    '=========================================='
  ) -join [Environment]::NewLine
  Add-Content -LiteralPath $InstallLogPath -Value $installStatus -Encoding UTF8
  Write-OtaLog 'bounded OTA completed and service is running'
  exit 0
} catch {
  Write-OtaLog ("bounded OTA failed: " + $_.Exception.Message)
  try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch {}
  exit 1
}
`;

  const setUninstallPasswordPs1 = PS1_BOM + `# AJNAT uninstall-password setup/reset
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
function Read-Secret([string]$Prompt) {
  $secure = Read-Host $Prompt -AsSecureString
  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}
function New-PasswordRecord([string]$Value) {
  $iterations = 210000
  $salt = New-Object byte[] 16
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
  $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
    $Value, $salt, $iterations, [Security.Cryptography.HashAlgorithmName]::SHA256
  )
  try { $hash = $derive.GetBytes(32) } finally { $derive.Dispose() }
  return 'pbkdf2-sha256:{0}:{1}:{2}' -f $iterations,[Convert]::ToBase64String($salt),[Convert]::ToBase64String($hash)
}
$first = Read-Secret 'Enter new AJNAT uninstall password'
$second = Read-Secret 'Confirm new AJNAT uninstall password'
if ($first.Length -lt 8) { throw 'Password must contain at least 8 characters' }
if ($first -cne $second) { throw 'Passwords do not match' }
$passDir = Join-Path $env:ProgramData 'AJNAT'
$passFile = Join-Path $passDir 'uninstall.pass'
New-Item -ItemType Directory -Path $passDir -Force | Out-Null
New-PasswordRecord $first | Set-Content -LiteralPath $passFile -NoNewline -Encoding UTF8
$first = $null; $second = $null
& icacls.exe $passFile /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure uninstall password (exit code $LASTEXITCODE)" }
Write-Host 'AJNAT uninstall password updated successfully.' -ForegroundColor Green
`;

  const uninstallPs1 = `# SOC Agent — Windows Uninstaller
#Requires -RunAsAdministrator
param([string]$ServiceName = "SOCAgent", [string]$InstallDir = "$env:ProgramFiles\\AJNAT")

Write-Host "Removing SOC Agent ..." -ForegroundColor Red
${windowsPasswordVerifySnippet()}
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) { try { $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch {} }
& sc.exe delete $ServiceName 2>$null | Out-Null
Remove-Item $InstallDir              -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item C:\\ProgramData\\AJNAT    -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item C:\\ProgramData\\SOCAgent -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "SOC Agent removed." -ForegroundColor Green
`;

  const readme = `SOC Agent v${VERSION} — Windows Package
========================================
Company : ${company.name}
System  : ${system.name}
Version : ${VERSION}

REQUIREMENTS
  • Windows 10 / 11 / Server 2019 / 2022 (64-bit)
  • Python 3.8+ from https://python.org  (tick "Add Python to PATH")
  • Administrator access; installer provisions Python/pywin32 when needed

FRESH INSTALL  (PowerShell as Administrator)
  1. Extract this zip
  2. Right-click PowerShell → Run as Administrator
  3. cd ${sanitize(system.name)}_windows
  4. Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  5. .\\install.ps1

UPDATE  (already installed)
  Download a fresh package for the intended dashboard System and run it again.
  Matching enrollment is refreshed; a changed system/key replaces stale identity.
  The existing uninstall password is retained.

VERIFY
  Get-Service SOCAgent
  notepad "C:\\ProgramData\\AJNAT\\logs\\agent.log"

TEST (no admin needed)
  python "C:\\Program Files\\AJNAT\\agent.py" test

UNINSTALL
  .\\uninstall.ps1
`;

  // install.bat — double-click launcher for Windows users
  const installBat = `@echo off
title SOC Agent Installer v${VERSION}
echo ==========================================
echo   SOC Agent v${VERSION} - Windows Installer
echo   Company : ${company.name}
echo   System  : ${system.name}
echo ==========================================
echo.
echo Starting installer (requires Administrator) ...
echo.

:: Request admin elevation
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges ...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d \\"%~dp0\\" && powershell -ExecutionPolicy Bypass -File .\\\\install.ps1' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File ".\\install.ps1"
echo.
echo Press any key to close ...
pause >nul
`;

  zip.addFile(`${dirName}/install.bat`,   Buffer.from(installBat,  'utf8'));
  zip.addFile(`${dirName}/install.ps1`,   Buffer.from(installPs1,  'utf8'));
  zip.addFile(`${dirName}/install-update.ps1`, Buffer.from(updatePs1, 'utf8'));
  zip.addFile(`${dirName}/set-uninstall-password.ps1`, Buffer.from(setUninstallPasswordPs1, 'utf8'));
  zip.addFile(`${dirName}/uninstall.ps1`, Buffer.from(uninstallPs1,'utf8'));
  zip.addFile(`${dirName}/README.txt`,    Buffer.from(readme,       'utf8'));
  return buildNsisExeFromZip(zip.toBuffer(), dirName, system, company, VERSION, options);
}

function buildMsi(system, company, agentConfig, options = {}) {
  const tlsPackage = prepareWindowsTlsPackage(agentConfig);
  const publisherCertificate = loadWindowsPublisherCertificate();
  const effectiveAgentConfig = tlsPackage.config;
  const configJson = JSON.stringify(effectiveAgentConfig, null, 2);
  const b64Config  = Buffer.from(configJson, 'utf8').toString('base64');
  const files      = collectAgentFiles();
  const VERSION    = effectiveAgentConfig.agent_version || DEFAULT_AGENT_VERSION;
  const tmpRoot    = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-agent-msi-payload-'));
  const payloadRoot = path.join(tmpRoot, 'payload');

  try {
    fs.mkdirSync(payloadRoot, { recursive: true });
    writeFilesToDir(files, payloadRoot);
    fs.mkdirSync(path.join(payloadRoot, 'config'), { recursive: true });
    fs.writeFileSync(path.join(payloadRoot, 'config', 'company_config.json'), configJson, 'utf8');
    if (tlsPackage.caBundle) {
      fs.mkdirSync(path.join(payloadRoot, 'certs'), { recursive: true });
      fs.writeFileSync(path.join(payloadRoot, 'certs', 'server-ca-bundle.pem'), tlsPackage.caBundle.content);
    }
    if (publisherCertificate) {
      fs.mkdirSync(path.join(payloadRoot, 'certs'), { recursive: true });
      fs.writeFileSync(
        path.join(payloadRoot, 'certs', 'AJNAT-Local-Test-Publisher.cer'),
        publisherCertificate.content,
      );
    }
    // Keep MSI generation/download small and deterministic. The installer uses
    // the authenticated AJNAT dependency endpoint and stores the downloaded
    // client under Program Files\\AJNAT\\velociraptor before installing it.

    const installPs1 = '\uFEFF' + `# SOC Agent v${VERSION} - MSI Installer
#Requires -RunAsAdministrator
param(
  [switch]$MsiMode,
  [string]$InstallDir = "",
  [string]$ServiceName = "SOCAgent"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = $ScriptDir }
$Version = "${VERSION}"
$DataDir = Join-Path $env:ProgramData "AJNAT"
$InstallLogDir = Join-Path $DataDir "logs"
$InstallLog = Join-Path $InstallLogDir "msi-install.log"
$MsiDiagnosticLog = Join-Path $InstallLogDir "msi-service-install.log"
function Repair-MsiInstallerAccess([string]$Path) {
    $pathAccessible = $false
    try { $pathAccessible = [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) } catch {}
    if (-not $pathAccessible) {
        try {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
            return
        } catch {}
    }
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $takeownOutput = & takeown.exe /F $Path /A /R /D Y 2>&1
        $takeownCode = $LASTEXITCODE
        if ($takeownCode -ne 0) { throw ("takeown exit {0}: {1}" -f $takeownCode, ($takeownOutput -join ' ')) }
        $resetOutput = & icacls.exe $Path /reset /T /C /Q 2>&1
        $resetCode = $LASTEXITCODE
        if ($resetCode -ne 0) { throw ("ACL reset exit {0}: {1}" -f $resetCode, ($resetOutput -join ' ')) }
        $grantOutput = & icacls.exe $Path /inheritance:e /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>&1
        $grantCode = $LASTEXITCODE
        if ($grantCode -ne 0) { throw ("ACL grant exit {0}: {1}" -f $grantCode, ($grantOutput -join ' ')) }
        $directOutput = & icacls.exe $Path /grant '*S-1-5-18:F' '*S-1-5-32-544:F' /T /C /Q 2>&1
        $directCode = $LASTEXITCODE
        if ($directCode -ne 0) { throw ("Direct ACL grant exit {0}: {1}" -f $directCode, ($directOutput -join ' ')) }
    } catch {
        throw ("Could not repair MSI access to {0}: {1}" -f $Path, $_.Exception.Message)
    } finally {
        $ErrorActionPreference = $savedPreference
    }
}
Repair-MsiInstallerAccess -Path $InstallDir
Repair-MsiInstallerAccess -Path $DataDir
New-Item -ItemType Directory -Path $InstallLogDir -Force | Out-Null
try { Start-Transcript -Path $InstallLog -Force | Out-Null } catch {}
trap {
    $failure = "$(Get-Date -Format o) MSI INSTALL FAILED: $($_.Exception.Message)"
    Write-Host $failure -ForegroundColor Red
    try { Add-Content -LiteralPath $MsiDiagnosticLog -Value $failure -Encoding UTF8 } catch {}
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
function Invoke-MsiNative([string]$FilePath, [string[]]$Arguments, [string]$Description) {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($output) {
        $output | ForEach-Object { Write-Host "  $_" }
        $output | Add-Content -LiteralPath $MsiDiagnosticLog -Encoding UTF8
    }
    Add-Content -LiteralPath $MsiDiagnosticLog -Value "$(Get-Date -Format o) $Description args=$($Arguments -join ' ') exit=$code" -Encoding UTF8
    if ($code -ne 0) { throw "$Description failed with exit code $code" }
}

Write-Host "Installing SOC Agent v$Version from MSI..."

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$configB64 = "${b64Config}"
$configDir = Join-Path $env:ProgramData "AJNAT\\config"
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
${windowsPublisherProvisionSnippet(publisherCertificate)}
${windowsCaProvisionSnippet(tlsPackage.caBundle)}
$configPath = "$configDir\\company_config.json"
try {
    $configBytes = [System.Convert]::FromBase64String($configB64)
    $packagedConfig = [System.Text.Encoding]::UTF8.GetString($configBytes) | ConvertFrom-Json
    $configToInstall = $packagedConfig
    $legacyConfig = "$InstallDir\\config\\company_config.json"
    $existingConfigPath = @($configPath, $legacyConfig) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($existingConfigPath) {
        try {
            $existingConfig = Get-Content -LiteralPath $existingConfigPath -Raw | ConvertFrom-Json
            $sameCompany = [string]::Equals([string]$existingConfig.company_id, [string]$packagedConfig.company_id, [System.StringComparison]::OrdinalIgnoreCase)
            $sameSystem = [string]::Equals([string]$existingConfig.system_id, [string]$packagedConfig.system_id, [System.StringComparison]::OrdinalIgnoreCase)
            $sameAgentKey = [string]::Equals([string]$existingConfig.agent_key, [string]$packagedConfig.agent_key, [System.StringComparison]::Ordinal)
            if ($sameCompany -and $sameSystem -and $sameAgentKey) {
                foreach ($property in $packagedConfig.PSObject.Properties) {
                    if ($existingConfig.PSObject.Properties.Name -contains $property.Name) {
                        $existingConfig.($property.Name) = $property.Value
                    } else {
                        $existingConfig | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
                    }
                }
                $configToInstall = $existingConfig
                Write-Host "Matching enrollment retained and refreshed."
            } else {
                Write-Host "Package targets a different or refreshed enrollment; replacing stale agent identity."
            }
        } catch {
            Write-Host "Existing configuration is invalid; replacing it with packaged enrollment."
        }
    }
    if ($configToInstall.PSObject.Properties.Name -contains 'agent_version') {
        $configToInstall.agent_version = $Version
    } else {
        $configToInstall | Add-Member -NotePropertyName agent_version -NotePropertyValue $Version
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($configPath, ($configToInstall | ConvertTo-Json -Depth 30), $utf8NoBom)
} catch { throw "Could not install packaged enrollment configuration: $($_.Exception.Message)" }
try {
    $acl = Get-Acl $configPath
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
    $acl.SetAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl $configPath $acl
} catch {}
${windowsRoleGuardSnippet()}
${windowsLocationProviderInstallSnippet()}
$currentPassFile = Join-Path $DataDir 'uninstall.pass'
$legacyPassFile = Join-Path $env:ProgramData 'SOCAgent\\uninstall.pass'
if ($MsiMode -and -not (Test-Path -LiteralPath $currentPassFile) -and -not (Test-Path -LiteralPath $legacyPassFile)) {
    throw 'Uninstall password is missing. Run this MSI interactively to set it; silent first-time installation is blocked.'
}
${windowsVelociraptorInstallSnippet()}
${windowsNativeIpsBootstrapSnippet()}
${windowsNetworkSensorInstallSnippet()}
${windowsAdvancedProcessTelemetrySnippet()}

if (-not $MsiMode) {
${windowsPasswordInstallSnippet()}
}

$pythonPath = $null
$privatePythonRuntimeDir = Join-Path $InstallDir 'runtime\\python'
$pythonRuntimeDir = $privatePythonRuntimeDir
$packageDir = Join-Path $InstallDir 'packages'
New-Item -ItemType Directory -Path $privatePythonRuntimeDir,$packageDir -Force | Out-Null
$pythonCandidates = @(
    (Join-Path $privatePythonRuntimeDir 'python.exe'),
    "$env:ProgramFiles\\Python313\\python.exe",
    "$env:ProgramFiles\\Python312\\python.exe",
    "\${env:ProgramFiles(x86)}\\Python313\\python.exe",
    "\${env:ProgramFiles(x86)}\\Python312\\python.exe",
    "$env:LocalAppData\\Programs\\Python\\Python313\\python.exe",
    "$env:LocalAppData\\Programs\\Python\\Python312\\python.exe"
)
try { $pythonCandidates += (& py.exe -0p 2>$null | ForEach-Object { ($_ -replace '^\\s*-V:[^\\s]+\\s*', '').Trim() }) } catch {}
foreach ($commandName in @('python', 'python3')) {
    try { $pythonCandidates += (Get-Command $commandName -ErrorAction Stop).Source } catch {}
}
foreach ($candidate in ($pythonCandidates | Select-Object -Unique)) {
    if (-not $candidate -or -not (Test-Path $candidate)) { continue }
    try {
        $versionText = & $candidate -c "import sys; print(str(sys.version_info.major) + '.' + str(sys.version_info.minor))" 2>$null
        $parts = $versionText.Trim().Split('.')
        if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 8 -and [int]$parts[1] -le 13) { $pythonPath = $candidate; break }
    } catch {}
}
if (-not $pythonPath) {
    $osArchitecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    $machineArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($machineArchitecture -eq 'Arm64') { $pythonPackage = 'python-3.12.10-arm64.exe' }
    elseif ($osArchitecture -match '64') { $pythonPackage = 'python-3.12.10-amd64.exe' }
    else { $pythonPackage = 'python-3.12.10.exe' }
    $pythonInstaller = Join-Path $packageDir $pythonPackage
    $pythonUrl = "https://www.python.org/ftp/python/3.12.10/$pythonPackage"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing -TimeoutSec 300
    } catch {
        Import-Module BitsTransfer -ErrorAction Stop
        Start-BitsTransfer -Source $pythonUrl -Destination $pythonInstaller -ErrorAction Stop
    } finally { $ProgressPreference = $oldProgress }
    if (-not (Test-Path $pythonInstaller) -or (Get-Item $pythonInstaller).Length -lt 5MB) { throw "Python installer download is incomplete" }
    # Preserve the space in "C:\Program Files\AJNAT\...". Passing this as an
    # array makes Windows PowerShell strip the TargetDir quotes.
    $pythonArguments = '/quiet InstallAllUsers=1 TargetDir="{0}" PrependPath=0 Include_launcher=0 AssociateFiles=0 Shortcuts=0 Include_pip=1 Include_test=0 Include_doc=0' -f $privatePythonRuntimeDir
    $pythonInstall = Start-Process -FilePath $pythonInstaller -ArgumentList $pythonArguments -Wait -PassThru
    if ($pythonInstall.ExitCode -ne 0) { throw "Python installation failed with exit code $($pythonInstall.ExitCode)" }
    $pythonPath = Join-Path $privatePythonRuntimeDir 'python.exe'
    if (-not (Test-Path -LiteralPath $pythonPath)) { throw "Python installed but python.exe was not found at $pythonPath" }
}
$pythonRuntimeDir = ([string](& $pythonPath -c 'import sys; print(sys.exec_prefix)')).Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonRuntimeDir)) { throw 'Could not resolve the selected Python runtime directory' }

$env:PIP_CACHE_DIR = Join-Path $packageDir 'pip-cache'
New-Item -ItemType Directory -Path $env:PIP_CACHE_DIR -Force | Out-Null
$requiredPackages = @(
    'requests', 'urllib3<3', 'psutil', 'watchdog', 'cryptography',
    'python-socketio[client]', 'websocket-client', 'yara-python', 'pywin32', 'wmi'
)
Invoke-MsiNative -FilePath $pythonPath -Arguments (@('-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', '--upgrade') + $requiredPackages) -Description 'Required AJNAT Python dependencies installation'
Invoke-MsiNative -FilePath $pythonPath -Arguments @('-c', 'import requests, psutil, watchdog, cryptography, socketio, websocket, yara, win32serviceutil, wmi') -Description 'Required AJNAT Python dependencies validation'

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    $existingService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
Invoke-MsiNative -FilePath $pythonPath -Arguments @('-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', '--upgrade', 'pywin32') -Description 'pywin32 installation'
$pythonDir = Split-Path -Parent $pythonPath
$pywin32PostInstall = @(
    (Join-Path $pythonDir 'pywin32_postinstall.py'),
    (Join-Path $pythonDir 'Scripts\\pywin32_postinstall.py')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (Test-Path -LiteralPath $pywin32PostInstall) {
    Invoke-MsiNative -FilePath $pythonPath -Arguments @($pywin32PostInstall, '-install') -Description 'pywin32 initialization'
}
${windowsPywin32ServiceHostSnippet('Invoke-MsiNative')}
Invoke-MsiNative -FilePath $pythonPath -Arguments @('-c', 'import win32serviceutil, win32service, servicemanager') -Description 'pywin32 import validation'
$serviceAction = if ($existingService) { 'update' } else { 'install' }
Invoke-MsiNative -FilePath $pythonPath -Arguments @("$InstallDir\\windows_service.py", '--startup', 'auto', $serviceAction) -Description "Native SOCAgent service $serviceAction"
Invoke-MsiNative -FilePath 'sc.exe' -Arguments @('config', $ServiceName, 'start=', 'delayed-auto') -Description 'Delayed automatic startup configuration'
Invoke-MsiNative -FilePath 'sc.exe' -Arguments @('failureflag', $ServiceName, '1') -Description 'Service failure flag configuration'
Invoke-MsiNative -FilePath 'sc.exe' -Arguments @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/60000') -Description 'Service recovery configuration'
Start-Service $ServiceName -ErrorAction Stop

$service = Get-Service $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Running') {
    Start-Service $ServiceName -ErrorAction Stop
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
}
$service = Get-Service $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Running') { throw "SOCAgent service was created but did not reach Running state" }
$env:AJNAT_DATA_DIR = $DataDir
$env:SOC_AGENT_CONFIG = $configPath
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
Invoke-MsiNative -FilePath $pythonPath -Arguments @("$InstallDir\\agent.py", 'test', '--config', $configPath) -Description 'Agent health check'
Start-Sleep -Seconds 5
$service = Get-Service $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Running') { throw "SOCAgent exited during the post-install stability check" }
${windowsProtectedAclSnippet()}

Write-Host "SOC Agent MSI install and health check complete."
try { Stop-Transcript | Out-Null } catch {}
`;

    const uninstallPs1 = '\uFEFF' + `# SOC Agent - MSI Uninstaller
#Requires -RunAsAdministrator
param(
  [switch]$MsiMode,
  [switch]$PreserveData,
  [string]$ServiceName = "SOCAgent",
  [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = $ScriptDir }

if (-not $MsiMode) {
${windowsPasswordVerifySnippet()}
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060) {
        throw "Could not delete $ServiceName service (exit code $LASTEXITCODE)"
    }
}
Remove-Item C:\\ProgramData\\SOCAgent -Recurse -Force -ErrorAction SilentlyContinue
if (-not $PreserveData) {
    Remove-Item C:\\ProgramData\\AJNAT -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "SOC Agent service removed."
`;

    const readme = `SOC Agent v${VERSION} — Windows MSI
====================================
Company : ${company.name}
System  : ${system.name}
Version : ${VERSION}

Install:
  Double-click the .msi or run:
  msiexec /i soc-agent.msi /L*v "%TEMP%\\soc-agent-msi-install.log"

Update / re-enroll:
  Download a fresh MSI for the intended dashboard System and run the same
  command. The uninstall password is retained; stale enrollment is replaced.

Uninstall:
  Windows Settings → Apps → SOC Agent → Uninstall
  or:
  msiexec /x soc-agent.msi /L*v "%TEMP%\\soc-agent-msi-uninstall.log"

Requirements:
  Windows 10/11/Server 2019/2022
  Python 3.8+ available in PATH
`;

    fs.writeFileSync(path.join(payloadRoot, 'install.ps1'), installPs1, 'utf8');
    fs.writeFileSync(path.join(payloadRoot, 'uninstall.ps1'), uninstallPs1, 'utf8');
    const msiPasswordSetupPs1 = '\uFEFF'
      + windowsMsiInteractiveActionPrelude('Uninstall password setup')
      + windowsPasswordInstallSnippet({ resetExisting: true });
    fs.writeFileSync(path.join(payloadRoot, 'password-setup.ps1'), msiPasswordSetupPs1, 'utf8');
    fs.writeFileSync(path.join(payloadRoot, 'set-uninstall-password.ps1'), msiPasswordSetupPs1, 'utf8');
    fs.writeFileSync(
      path.join(payloadRoot, 'password-verify.ps1'),
      '\uFEFF'
        + windowsMsiInteractiveActionPrelude('Uninstall password verification')
        + windowsPasswordVerifySnippet(),
      'utf8',
    );
    fs.writeFileSync(path.join(payloadRoot, 'README-MSI.txt'), readme, 'utf8');

    return buildMsiFromPayload(payloadRoot, system, company, VERSION, options);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// macOS installer bundle  (ZIP with install.sh/uninstall.sh — LaunchDaemon)
// ─────────────────────────────────────────────────────────────────────────────
function buildPkg(system, company, agentConfig) {
  const AdmZip     = require('adm-zip');
  const configJson = JSON.stringify(agentConfig, null, 2);
  const files      = collectAgentFiles();
  const zip        = new AdmZip();
  const dirName    = `soc-agent_${sanitize(system.name)}_macos`;
  const INSTALL    = '/opt/soc-agent';
  const VERSION    = agentConfig.agent_version || DEFAULT_AGENT_VERSION;

  addAgentFiles(zip, files, dirName);
  zip.addFile(`${dirName}/config/company_config.json`, Buffer.from(configJson, 'utf8'));

  const installSh = `#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  SOC Agent v${VERSION} Installer — macOS (Intel + Apple Silicon)
#  Company : ${company.name}
#  System  : ${system.name}
#  Supports: Fresh install AND update (safe to re-run)
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail
INSTALL_DIR="${INSTALL}"
PLIST="/Library/LaunchDaemons/com.soc.agent.plist"
LOG_DIR="/Library/Logs/SOCAgent"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="${VERSION}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SOC Agent v$VERSION — macOS"
echo "  Company : ${company.name}"
echo "  System  : ${system.name}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[ "$(id -u)" != "0" ] && { echo "ERROR: need sudo: sudo bash install.sh"; exit 1; }
${unixPasswordInstallSnippet()}

IS_UPDATE=false
if [ -f "$INSTALL_DIR/agent.py" ]; then
  IS_UPDATE=true
  echo "🔄  Updating existing install …"
  launchctl unload "$PLIST" 2>/dev/null || true
fi

# ── Find Python ───────────────────────────────────────────────────────────────
PYTHON=""
for cmd in /usr/local/bin/python3 /opt/homebrew/bin/python3 python3 python; do
  if command -v "$cmd" &>/dev/null; then
    ver=$( "$cmd" --version 2>&1 || true )
    if echo "$ver" | grep -q "Python 3"; then PYTHON="$cmd"; break; fi
  fi
done
if [ -z "$PYTHON" ]; then
  if ! command -v brew &>/dev/null; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null || true
  fi
  brew install python3
  PYTHON="$(brew --prefix)/bin/python3"
fi
echo "✓  Python: $PYTHON ($($PYTHON --version 2>&1))"

# ── Install agent ─────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cp -rf "$SCRIPT_DIR"/. "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/agent.py" 2>/dev/null || true
echo "  ✓ Agent files updated (v$VERSION)"
chown root:wheel "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chmod 600 "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chown -R root:wheel "$INSTALL_DIR" 2>/dev/null || true
find "$INSTALL_DIR" -type d -exec chmod 700 {} +
find "$INSTALL_DIR" -type f -exec chmod 600 {} +
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true
${macRoleGuardSnippet()}
${macNativeIpsBootstrapSnippet()}

# ── Dependencies ──────────────────────────────────────────────────────────────
echo "📦  Installing Python dependencies …"
$PYTHON -m pip install --quiet --upgrade --break-system-packages requests "urllib3<3" psutil watchdog cryptography 2>/dev/null || \\
$PYTHON -m pip install --quiet --upgrade requests "urllib3<3" psutil watchdog cryptography 2>/dev/null || true
$PYTHON -m pip install --quiet --break-system-packages "python-socketio[client]" websocket-client 2>/dev/null || \\
$PYTHON -m pip install --quiet "python-socketio[client]" websocket-client 2>/dev/null || true
$PYTHON -m pip install --quiet --break-system-packages yara-python 2>/dev/null || \\
$PYTHON -m pip install --quiet yara-python 2>/dev/null || true
$PYTHON -m pip install --quiet --break-system-packages 'pyobjc-framework-CoreLocation>=10.0' 2>/dev/null || \\
$PYTHON -m pip install --quiet 'pyobjc-framework-CoreLocation>=10.0'
${macLocationProviderInstallSnippet()}
echo "  ✓ Dependencies installed"

# ── Config ────────────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/config"
[ -f "$INSTALL_DIR/config/company_config.json" ] || echo "⚠️  WARNING: config file missing!"

# ── LaunchDaemon ─────────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"
cat > "$PLIST" << PLEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.soc.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON</string>
    <string>$INSTALL_DIR/agent.py</string>
    <string>run</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$INSTALL_DIR</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/output.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/error.log</string>
</dict>
</plist>
PLEOF

chown root:wheel "$PLIST"
chmod 644        "$PLIST"
launchctl load   "$PLIST"

echo ""
if $IS_UPDATE; then
  echo "  ✅  SOC Agent UPDATED to v$VERSION!"
else
  echo "  ✅  SOC Agent v$VERSION installed!"
fi
echo "    Status : launchctl list | grep soc.agent"
echo "    Logs   : tail -f $LOG_DIR/output.log"
echo "    Test   : $PYTHON $INSTALL_DIR/agent.py test"
echo "    Remove : sudo bash $SCRIPT_DIR/uninstall.sh"
`;

const uninstallSh = `#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" != "0" ] && { echo "ERROR: need sudo"; exit 1; }
${unixPasswordVerifySnippet()}
PLIST="/Library/LaunchDaemons/com.soc.agent.plist"
launchctl unload "$PLIST" 2>/dev/null || true
rm -f  "$PLIST"
${macNativeIpsCleanupSnippet()}
rm -rf /opt/soc-agent /Library/Logs/SOCAgent /etc/soc-agent
echo "✅  SOC Agent removed."
`;

  const readme = `SOC Agent v${VERSION} — macOS Installer Bundle
=======================================
Company : ${company.name}
System  : ${system.name}
Version : ${VERSION}

REQUIREMENTS
  • macOS 12 Monterey or later (Intel & Apple Silicon)
  • Python 3 (installed automatically via Homebrew if missing)

FRESH INSTALL
  1. Extract this zip
  2. Double-click install.command

TERMINAL INSTALL
  cd ${sanitize(system.name)}_macos
  sudo bash install.sh

UPDATE  (already installed)
  Same command — detects and updates automatically.

VERIFY
  launchctl list | grep soc.agent
  tail -f /Library/Logs/SOCAgent/output.log

TEST (no sudo)
  python3 /opt/soc-agent/agent.py test

UNINSTALL
  sudo bash uninstall.sh
`;

  const installCommand = `#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
echo "SOC Agent macOS installer"
echo "This will ask for your macOS admin password."
echo ""
sudo bash ./install.sh
echo ""
echo "Install finished. You can close this window."
read -r -p "Press Enter to close..."
`;

  const uninstallCommand = `#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
echo "SOC Agent macOS uninstaller"
echo "This will ask for your macOS admin password and SOC Agent uninstall password."
echo ""
sudo bash ./uninstall.sh
echo ""
echo "Uninstall finished. You can close this window."
read -r -p "Press Enter to close..."
`;

  zip.addFile(`${dirName}/install.sh`,   Buffer.from(installSh,   'utf8'));
  zip.addFile(`${dirName}/uninstall.sh`, Buffer.from(uninstallSh, 'utf8'));
  zip.addFile(`${dirName}/install.command`, Buffer.from(installCommand, 'utf8'), 'Mac install launcher', 0o100755);
  zip.addFile(`${dirName}/uninstall.command`, Buffer.from(uninstallCommand, 'utf8'), 'Mac uninstall launcher', 0o100755);
  zip.addFile(`${dirName}/README.txt`,   Buffer.from(readme,       'utf8'));
  return zip.toBuffer();
}

// ─────────────────────────────────────────────────────────────────────────────
// Android debug-signed APK
// ─────────────────────────────────────────────────────────────────────────────
function buildApk(system, company, agentConfig) {
  const tlsPackage = prepareAndroidTlsPackage(agentConfig);
  const configJson = JSON.stringify(tlsPackage.config, null, 2);
  const templateDir = path.resolve(__dirname, '..', '..', 'android-agent');
  if (!fs.existsSync(templateDir)) {
    throw new Error('Android APK template not found at backend/android-agent');
  }

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-agent-apk-'));
  const tmpDir = path.join(tmpRoot, 'android-agent');
  try {
    fs.cpSync(templateDir, tmpDir, {
      recursive: true,
      filter: (src) => {
        const rel = path.relative(templateDir, src).replace(/\\/g, '/');
        return rel !== 'app/build' && !rel.startsWith('app/build/') && rel !== '.gradle' && !rel.startsWith('.gradle/');
      },
    });

    const assetsDir = path.join(tmpDir, 'app', 'src', 'main', 'assets');
    fs.mkdirSync(assetsDir, { recursive: true });
    fs.writeFileSync(path.join(assetsDir, 'company_config.json'), configJson);
    if (tlsPackage.caBundle) {
      fs.writeFileSync(path.join(assetsDir, 'server-ca-bundle.pem'), tlsPackage.caBundle.content);
    }

    const gradlew = path.join(tmpDir, 'gradlew');
    fs.chmodSync(gradlew, 0o755);

    execFileSync(gradlew, ['assembleDebug', '--no-daemon'], {
      cwd: tmpDir,
      stdio: 'pipe',
      env: {
        ...process.env,
        ANDROID_HOME: process.env.ANDROID_HOME || '/usr/lib/android-sdk',
        GRADLE_USER_HOME: process.env.GRADLE_USER_HOME || path.join(os.homedir(), '.gradle'),
      },
      timeout: 120000,
    });

    const apkPath = path.join(tmpDir, 'app', 'build', 'outputs', 'apk', 'debug', 'app-debug.apk');
    if (!fs.existsSync(apkPath)) throw new Error('Android APK build finished but app-debug.apk was not found');
    return fs.readFileSync(apkPath);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Solaris server package
// ─────────────────────────────────────────────────────────────────────────────
function buildSolaris(system, company, agentConfig) {
  const AdmZip     = require('adm-zip');
  const configJson = JSON.stringify(agentConfig, null, 2);
  const files      = collectAgentFiles();
  const zip        = new AdmZip();
  const dirName    = `soc-agent_${sanitize(system.name)}_solaris`;
  const VERSION    = agentConfig.agent_version || DEFAULT_AGENT_VERSION;

  addAgentFiles(zip, files, dirName);
  zip.addFile(`${dirName}/config/company_config.json`, Buffer.from(configJson, 'utf8'));

  const installSh = `#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="/opt/soc-agent"
SVC="soc-agent"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZFS_DATASET="\${SOC_AGENT_ZFS_DATASET:-rpool/opt/soc-agent}"

echo "SOC Agent v${VERSION} — Solaris Server"
echo "Company : ${company.name}"
echo "System  : ${system.name}"

[ "$(id -u)" != "0" ] && { echo "ERROR: Run with sudo: sudo bash install.sh" >&2; exit 1; }
${unixPasswordInstallSnippet()}

svcadm disable "$SVC" 2>/dev/null || true

if command -v zfs >/dev/null 2>&1; then
  echo "ZFS detected. Preparing dataset: $ZFS_DATASET"
  if zfs list "$ZFS_DATASET" >/dev/null 2>&1; then
    echo "  ✓ Existing ZFS dataset found"
  else
    PARENT_DATASET="$(dirname "$ZFS_DATASET")"
    if zfs list "$PARENT_DATASET" >/dev/null 2>&1; then
      zfs create -o mountpoint="$INSTALL_DIR" -o compression=lz4 "$ZFS_DATASET"
      echo "  ✓ Created ZFS dataset $ZFS_DATASET"
    else
      echo "  ⚠ Parent dataset $PARENT_DATASET not found. Using normal directory."
    fi
  fi
  if zfs list "$ZFS_DATASET" >/dev/null 2>&1; then
    zfs set mountpoint="$INSTALL_DIR" "$ZFS_DATASET"
    zfs set compression=lz4 "$ZFS_DATASET" 2>/dev/null || true
    zfs mount "$ZFS_DATASET" 2>/dev/null || true
  fi
else
  echo "ZFS command not found. Using normal directory."
fi

mkdir -p "$INSTALL_DIR"
cp -rf "$SCRIPT_DIR"/. "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/agent.py" 2>/dev/null || true
chown root:root "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chmod 600 "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chown -R root:root "$INSTALL_DIR" 2>/dev/null || true
find "$INSTALL_DIR" -type d -exec chmod 700 {} +
find "$INSTALL_DIR" -type f -exec chmod 600 {} +
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true
${solarisRoleGuardSnippet()}

PYTHON="$(command -v python3 || command -v python || true)"
[ -z "$PYTHON" ] && { echo "ERROR: python3 is required on Solaris."; exit 1; }

cat > "/var/svc/manifest/site/$SVC.xml" << SVCEOF
<?xml version="1.0"?>
<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">
<service_bundle type="manifest" name="soc-agent">
  <service name="site/soc-agent" type="service" version="1">
    <create_default_instance enabled="true"/>
    <single_instance/>
    <dependency name="network" grouping="require_all" restart_on="none" type="service">
      <service_fmri value="svc:/milestone/network:default"/>
    </dependency>
    <exec_method type="method" name="start" exec="$PYTHON $INSTALL_DIR/agent.py run" timeout_seconds="60"/>
    <exec_method type="method" name="stop" exec=":kill" timeout_seconds="60"/>
    <property_group name="startd" type="framework">
      <propval name="duration" type="astring" value="contract"/>
    </property_group>
    <stability value="Uncommitted"/>
  </service>
</service_bundle>
SVCEOF

svccfg import "/var/svc/manifest/site/$SVC.xml"
svcadm enable "$SVC"

echo "✅ SOC Agent installed on Solaris."
if command -v zfs >/dev/null 2>&1 && zfs list "$ZFS_DATASET" >/dev/null 2>&1; then
  echo "ZFS:    $ZFS_DATASET mounted at $INSTALL_DIR"
fi
echo "Status: svcs $SVC"
echo "Logs:   svcs -xv $SVC"
`;

const uninstallSh = `#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="/opt/soc-agent"
ZFS_DATASET="\${SOC_AGENT_ZFS_DATASET:-rpool/opt/soc-agent}"
[ "$(id -u)" != "0" ] && { echo "ERROR: need sudo"; exit 1; }
${unixPasswordVerifySnippet()}
svcadm disable soc-agent 2>/dev/null || true
svccfg delete -f site/soc-agent 2>/dev/null || true
rm -f /var/svc/manifest/site/soc-agent.xml
if command -v zfs >/dev/null 2>&1 && zfs list "$ZFS_DATASET" >/dev/null 2>&1; then
  zfs destroy "$ZFS_DATASET" 2>/dev/null || {
    echo "WARNING: Could not destroy ZFS dataset $ZFS_DATASET. Remove it manually if needed."
  }
else
  rm -rf "$INSTALL_DIR"
fi
rm -rf /etc/soc-agent
echo "✅ SOC Agent removed from Solaris."
`;

  zip.addFile(`${dirName}/install.sh`, Buffer.from(installSh, 'utf8'));
  zip.addFile(`${dirName}/uninstall.sh`, Buffer.from(uninstallSh, 'utf8'));
  zip.addFile(`${dirName}/README.txt`, Buffer.from(`SOC Agent v${VERSION} — Solaris Server
====================================
Company : ${company.name}
System  : ${system.name}

INSTALL
  chmod +x soc-agent_*_solaris-zfs.sh
  sudo ./soc-agent_*_solaris-zfs.sh

ZFS
  Default dataset: rpool/opt/soc-agent
  Custom dataset:
    sudo SOC_AGENT_ZFS_DATASET=tank/soc-agent bash install.sh

CHECK ZFS
  zfs list rpool/opt/soc-agent
  zfs get mountpoint,compression rpool/opt/soc-agent

VERIFY
  svcs soc-agent
  svcs -xv soc-agent

UNINSTALL
  sudo bash /opt/soc-agent/uninstall.sh
`, 'utf8'));

  const payloadB64 = zip.toBuffer().toString('base64');
  const selfExtractingInstaller = `#!/usr/bin/env bash
set -euo pipefail
TMP_DIR="\${TMPDIR:-/tmp}/soc-agent-solaris-zfs-$$"
PAYLOAD_ZIP="$TMP_DIR/payload.zip"
mkdir -p "$TMP_DIR"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

extract_payload() {
  if command -v base64 >/dev/null 2>&1; then
    sed -n '/^__SOC_AGENT_PAYLOAD__$/,$p' "$0" | sed '1d' | base64 -d > "$PAYLOAD_ZIP" 2>/dev/null || \\
    sed -n '/^__SOC_AGENT_PAYLOAD__$/,$p' "$0" | sed '1d' | base64 --decode > "$PAYLOAD_ZIP"
  else
    python3 - "$0" "$PAYLOAD_ZIP" <<'PY'
import base64, sys
script, out = sys.argv[1], sys.argv[2]
data = open(script, 'rb').read().split(b'__SOC_AGENT_PAYLOAD__\\n', 1)[1]
open(out, 'wb').write(base64.b64decode(data))
PY
  fi
}

extract_payload
if command -v unzip >/dev/null 2>&1; then
  unzip -q "$PAYLOAD_ZIP" -d "$TMP_DIR"
else
  python3 - "$PAYLOAD_ZIP" "$TMP_DIR" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    z.extractall(sys.argv[2])
PY
fi

exec bash "$TMP_DIR/${dirName}/install.sh" "$@"
exit 0
__SOC_AGENT_PAYLOAD__
${payloadB64}
`;
  return Buffer.from(selfExtractingInstaller, 'utf8');
}

function buildMacPkg(system, company, agentConfig) {
  const configJson = JSON.stringify(agentConfig, null, 2);
  const files = collectAgentFiles();
  const VERSION = agentConfig.agent_version || DEFAULT_AGENT_VERSION;
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-agent-macpkg-'));

  try {
    const payloadRoot = path.join(tmpRoot, 'payload');
    const installRoot = path.join(payloadRoot, 'opt', 'soc-agent');
    fs.mkdirSync(installRoot, { recursive: true });
    writeFilesToDir(files, installRoot);
    fs.mkdirSync(path.join(installRoot, 'config'), { recursive: true });
    fs.writeFileSync(path.join(installRoot, 'config', 'company_config.json'), configJson, 'utf8');

    const uninstallSh = `#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" != "0" ] && { echo "ERROR: need sudo"; exit 1; }
${unixPasswordVerifySnippet()}
${linuxUninstallNotificationSnippet()}
PLIST="/Library/LaunchDaemons/com.soc.agent.plist"
launchctl bootout system/com.soc.agent 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
${macNativeIpsCleanupSnippet()}
rm -rf /opt/soc-agent /Library/Logs/SOCAgent /etc/soc-agent
echo "SOC Agent removed."
`;
    fs.writeFileSync(path.join(installRoot, 'uninstall.sh'), uninstallSh, 'utf8');
    fs.chmodSync(path.join(installRoot, 'uninstall.sh'), 0o755);

    // Native macOS packages run postinstall without an interactive TTY, so
    // password enrollment is an explicit administrator step after install.
    const passwordSetupSh = `#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" != "0" ] && { echo "ERROR: run with sudo"; exit 1; }
${unixPasswordInstallSnippet()}
`;
    fs.writeFileSync(path.join(installRoot, 'set-uninstall-password.sh'), passwordSetupSh, 'utf8');
    fs.chmodSync(path.join(installRoot, 'set-uninstall-password.sh'), 0o755);

    const scriptsRoot = path.join(tmpRoot, 'scripts');
    fs.mkdirSync(scriptsRoot, { recursive: true });
    const postinstall = `#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="/opt/soc-agent"
PLIST="/Library/LaunchDaemons/com.soc.agent.plist"
LOG_DIR="/Library/Logs/SOCAgent"
VERSION="${VERSION}"

PYTHON=""
for cmd in /usr/local/bin/python3 /opt/homebrew/bin/python3 python3 python; do
  if command -v "$cmd" >/dev/null 2>&1; then
    ver="$("$cmd" --version 2>&1 || true)"
    if echo "$ver" | grep -q "Python 3"; then PYTHON="$cmd"; break; fi
  fi
done
if [ -z "$PYTHON" ]; then
  echo "Python 3 is required. Install Python 3 or Homebrew Python, then reinstall SOC Agent."
  exit 1
fi

SYSTEM_PYTHON="$PYTHON"
VENV_DIR="$INSTALL_DIR/.venv"
if [ ! -x "$VENV_DIR/bin/python3" ]; then
  "$SYSTEM_PYTHON" -m venv "$VENV_DIR"
fi
PYTHON="$VENV_DIR/bin/python3"
"$PYTHON" -m pip install --quiet --upgrade pip setuptools wheel
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
  "$PYTHON" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt" || {
    echo "Full dependency install failed; installing required runtime packages..."
    "$PYTHON" -m pip install --quiet requests "urllib3<2" psutil watchdog cryptography "python-socketio[client]" websocket-client
    "$PYTHON" -m pip install --quiet yara-python || true
  }
else
  "$PYTHON" -m pip install --quiet requests "urllib3<2" psutil watchdog cryptography "python-socketio[client]" websocket-client
  "$PYTHON" -m pip install --quiet yara-python || true
fi
"$PYTHON" -c 'import requests, psutil, watchdog, cryptography, socketio, websocket'
${macLocationProviderInstallSnippet()}

chmod +x "$INSTALL_DIR/agent.py" "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
chown root:wheel "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chmod 600 "$INSTALL_DIR/config/company_config.json" 2>/dev/null || true
chown -R root:wheel "$INSTALL_DIR" 2>/dev/null || true
find "$INSTALL_DIR" -type d -exec chmod 700 {} +
find "$INSTALL_DIR" -type f -exec chmod 600 {} +
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true
${macRoleGuardSnippet()}
${macNativeIpsBootstrapSnippet()}
chown -R root:wheel "$INSTALL_DIR" 2>/dev/null || true
chmod -R go-rwx "$INSTALL_DIR" 2>/dev/null || true
chmod 700 "$INSTALL_DIR/agent.py" "$INSTALL_DIR"/*.sh 2>/dev/null || true
find "$VENV_DIR/bin" -type f -exec chmod 700 {} + 2>/dev/null || true

mkdir -p "$LOG_DIR"
cat > "$PLIST" << PLEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.soc.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON</string>
    <string>$INSTALL_DIR/agent.py</string>
    <string>run</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$INSTALL_DIR</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/output.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/error.log</string>
</dict>
</plist>
PLEOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl bootout system/com.soc.agent 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
if ! launchctl bootstrap system "$PLIST"; then
  launchctl load "$PLIST"
fi
launchctl enable system/com.soc.agent 2>/dev/null || true
launchctl kickstart -k system/com.soc.agent 2>/dev/null || true
echo "SOC Agent v$VERSION installed."
echo "Required next step: sudo bash /opt/soc-agent/set-uninstall-password.sh"
exit 0
`;
    fs.writeFileSync(path.join(scriptsRoot, 'postinstall'), postinstall, 'utf8');
    fs.chmodSync(path.join(scriptsRoot, 'postinstall'), 0o755);

    const payload = createCpioGz(payloadRoot);
    const scripts = createCpioGz(scriptsRoot);
    fs.writeFileSync(path.join(tmpRoot, 'Payload'), payload);
    fs.writeFileSync(path.join(tmpRoot, 'Scripts'), scripts);
    fs.writeFileSync(path.join(tmpRoot, 'Bom'), '');

    const fileCount = collectPayloadFilePaths(payloadRoot).length;
    const installKBytes = Math.max(1, Math.ceil(directorySizeBytes(payloadRoot) / 1024));
    const packageInfo = `<?xml version="1.0" encoding="utf-8"?>
<pkg-info format-version="2" identifier="com.soc.agent" version="${xmlEscape(VERSION)}" install-location="/" auth="root">
  <payload installKBytes="${installKBytes}" numberOfFiles="${fileCount}"/>
  <scripts>
    <postinstall file="./postinstall"/>
  </scripts>
</pkg-info>
`;
    fs.writeFileSync(path.join(tmpRoot, 'PackageInfo'), packageInfo, 'utf8');

    const outFile = path.join(tmpRoot, `soc-agent_${sanitize(company.name)}_${sanitize(system.name)}_macos.pkg`);
    execFileSync('xar', ['-cf', outFile, 'PackageInfo', 'Payload', 'Scripts', 'Bom'], {
      cwd: tmpRoot,
      stdio: 'pipe',
      timeout: 120000,
    });
    return fs.readFileSync(outFile);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

function buildDmg(system, company, agentConfig) {
  const VERSION = agentConfig.agent_version || DEFAULT_AGENT_VERSION;
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-agent-dmg-'));
  try {
    const dmgRoot = path.join(tmpRoot, 'SOC Agent');
    fs.mkdirSync(dmgRoot, { recursive: true });
    fs.writeFileSync(path.join(dmgRoot, 'SOC-Agent.pkg'), buildMacPkg(system, company, agentConfig));
    fs.writeFileSync(path.join(dmgRoot, 'README.txt'), `SOC Agent v${VERSION} macOS installer

INSTALL
  1. Open SOC-Agent.pkg
  2. Complete the macOS Installer steps
  3. Set the required uninstall password:
     sudo bash /opt/soc-agent/set-uninstall-password.sh
  4. Verify:
     sudo launchctl print system/com.soc.agent
     sudo /opt/soc-agent/.venv/bin/python3 /opt/soc-agent/agent.py test

UNINSTALL
  sudo bash /opt/soc-agent/uninstall.sh
`, 'utf8');
    const passwordCommand = `#!/usr/bin/env bash
echo "AJNAT uninstall password setup"
echo "This will ask for your macOS administrator password."
sudo bash /opt/soc-agent/set-uninstall-password.sh
status=$?
echo ""
if [ "$status" -eq 0 ]; then echo "Uninstall password configured."; else echo "Password setup failed."; fi
read -r -p "Press Enter to close..."
exit "$status"
`;
    const uninstallCommand = `#!/usr/bin/env bash
echo "AJNAT macOS uninstaller"
sudo bash /opt/soc-agent/uninstall.sh
status=$?
echo ""
read -r -p "Press Enter to close..."
exit "$status"
`;
    fs.writeFileSync(path.join(dmgRoot, 'Set Uninstall Password.command'), passwordCommand, 'utf8');
    fs.chmodSync(path.join(dmgRoot, 'Set Uninstall Password.command'), 0o755);
    fs.writeFileSync(path.join(dmgRoot, 'Uninstall AJNAT.command'), uninstallCommand, 'utf8');
    fs.chmodSync(path.join(dmgRoot, 'Uninstall AJNAT.command'), 0o755);

    const outFile = path.join(tmpRoot, `soc-agent_${sanitize(company.name)}_${sanitize(system.name)}_macos.dmg`);
    execFileSync('xorriso', ['-as', 'mkisofs', '-V', 'SOC Agent', '-o', outFile, dmgRoot], {
      stdio: 'pipe',
      timeout: 120000,
    });
    return fs.readFileSync(outFile);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

module.exports = {
  buildDeb, buildRpm, buildUniversal, buildExe, buildMsi, buildPkg, buildMacPkg,
  buildDmg, buildApk, buildSolaris, linuxPreInstallScript, getAgentIntegrityManifest,
  windowsPasswordVerifySnippet, getWindowsVelociraptorBundle, prepareWindowsTlsPackage,
  prepareAndroidTlsPackage, loadWindowsPublisherCertificate,
};
