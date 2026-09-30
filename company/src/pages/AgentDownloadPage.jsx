import React, { useEffect, useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import Swal from 'sweetalert2';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';

// ── Code block with copy ───────────────────────────────────────────────────────
function CodeBlock({ code }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ position:'relative', marginTop:6 }}>
      <pre style={{
        background:'#020b14', border:'1px solid #1e3a5f', borderRadius:6,
        padding:'10px 44px 10px 14px', fontSize:12, color:'#7dd3fc',
        overflowX:'auto', margin:0, lineHeight:1.7, fontFamily:'monospace',
        whiteSpace:'pre-wrap', wordBreak:'normal', overflowWrap:'anywhere',
      }}>{code}</pre>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(()=>setCopied(false),2000); }}
        style={{
          position:'absolute', top:6, right:6, fontSize:10, padding:'3px 8px',
          borderRadius:4, border:'none', cursor:'pointer',
          background: copied ? '#064e3b' : '#1e3a5f',
          color:      copied ? '#34d399' : '#60a5fa',
        }}>
        {copied ? '✓ Copied' : 'Copy'}
      </button>
    </div>
  );
}

// ── OS config ─────────────────────────────────────────────────────────────────
const OS_TABS = [
  {
    key: 'linux', icon: '🐧', label: 'Linux', color: '#f59e0b',
    distros: 'Ubuntu · Debian · CentOS · RHEL · Fedora · Kali',
    packages: [
      { type:'deb', label:'.deb', desc:'Debian · Ubuntu · Mint · Kali', badge:'apt install', suffix:'linux-deb', velo:'Velociraptor auto-install' },
      { type:'rpm', label:'.rpm', desc:'RHEL · CentOS · Fedora · Rocky', badge:'dnf install', suffix:'linux-rpm', velo:'Velociraptor auto-install' },
    ],
    install: [
      { title:'Choose the package', code:'Debian / Ubuntu / Mint / Kali: download .deb\nRHEL / CentOS / Fedora / Rocky: download .rpm' },
      { title:'Find and install the downloaded .deb', code:'cd ~/Downloads\nls -lh ./soc-agent*_linux-deb.deb\nsudo apt install ./soc-agent*_linux-deb.deb\n# If installation finishes with "installed and verified", an _apt permission notice is harmless.' },
      { title:'Find and install the downloaded .rpm', code:'cd ~/Downloads\nls -lh ./soc-agent*_linux-rpm.rpm\nsudo dnf install ./soc-agent*_linux-rpm.rpm' },
      { title:'Create uninstall password', code:'The installer asks for an uninstall password and confirmation.\nKeep it safely; removal is blocked without it.' },
      { title:'Verify service and connection', code:'sudo systemctl is-active soc-agent\nsudo python3 /opt/soc-agent/agent.py test' },
    ],
    uninstall: [
      { title:'Debian / Ubuntu / Mint / Kali', code:'sudo apt remove soc-agent\n# Enter the SOC Agent uninstall password when prompted' },
      { title:'RHEL / CentOS / Fedora / Rocky', code:'sudo dnf remove soc-agent\n# Enter the SOC Agent uninstall password when prompted' },
      { title:'Verify removal', code:'sudo systemctl is-active soc-agent 2>/dev/null || echo "Agent uninstalled"\ntest ! -e /opt/soc-agent && echo "Files removed"' },
    ],
  },
  {
    key: 'windows', icon: '🪟', label: 'Windows', color: '#60a5fa',
    distros: 'Windows 10 · Windows 11 · Windows Server 2019/2022',
    packages: [
      { type:'exe', label:'.exe', desc:'Windows 10/11 · Server', badge:'Portable', velo:'SOC heartbeat client-id sync' },
      { type:'msi', label:'.msi', desc:'Enterprise / GPO deploy', badge:'MSI installer', velo:'SOC heartbeat client-id sync' },
    ],
    install: [
      { title:'Step 1 - Download for the correct System', code:'Download the .exe or .msi from this system row.\nA package contains that system\'s current agent key; do not reuse another system\'s package.\nFor updates, keep the same format (.exe or .msi); uninstall first before switching formats.' },
      { title:'Step 2 - Double-click the downloaded installer', code:'.exe: double-click the downloaded file.\n.msi: double-click the downloaded file, then click Install.\nSelect Yes when Windows shows the UAC administrator prompt. No PowerShell command is required.' },
      { title:'Step 3 - Automatic install or update', code:'The installer automatically requests administrator access, repairs an existing AJNAT installation, installs dependencies, and starts SOCAgent.' },
      { title:'Step 4 - Password and enrollment behavior', code:'On first install, enter and confirm an 8+ character uninstall password.\nUpdates retain that password. If the downloaded package has a new system/key, stale enrollment is replaced automatically.' },
      { title:'Step 5 - Verify service, identity, and connection', code:'Get-Service SOCAgent\npython "$env:ProgramFiles\\AJNAT\\agent.py" test --config "$env:ProgramData\\AJNAT\\config\\company_config.json"\nGet-Content "$env:ProgramData\\AJNAT\\logs\\install.log" -Tail 80' },
      { title:'If installation fails', code:'Get-Content "$env:TEMP\\soc-agent-install-bootstrap.log" -Tail 120 -ErrorAction SilentlyContinue\nGet-Content "$env:TEMP\\soc-agent-msi-install.log" -Tail 120 -ErrorAction SilentlyContinue\nGet-Content "$env:ProgramData\\AJNAT\\logs\\service-install.log" -Tail 120 -ErrorAction SilentlyContinue' },
    ],
    uninstall: [
      { title:'Uninstall an .exe installation', code:'Start-Process "$env:ProgramFiles\\AJNAT\\uninstall.exe" -Verb RunAs -Wait\n# Enter the uninstall password in the protected dialog' },
      { title:'Uninstall an .msi installation', code:'$msi = (Get-ChildItem "$env:USERPROFILE\\Downloads\\soc-agent_*_windows-msi.msi" | Select-Object -First 1).FullName\nmsiexec.exe /x "$msi" /L*v "$env:TEMP\\soc-agent-msi-uninstall.log"\n# Enter the uninstall password when prompted.' },
      { title:'Verify removal', code:'Get-Service SOCAgent -ErrorAction SilentlyContinue\nTest-Path "$env:ProgramFiles\\AJNAT"\nTest-Path "$env:ProgramData\\AJNAT"\n# Both Test-Path commands should return False after a clean uninstall.' },
      { title:'Recovery only after supported uninstall', code:'# Run only if uninstall completed but a stale service entry remains:\nsc.exe stop SOCAgent\nsc.exe delete SOCAgent\n# Reboot before reinstall if Windows reports the service is marked for deletion.' },
    ],
  },
  {
    key: 'macos', icon: '🍎', label: 'macOS', color: '#34d399',
    distros: 'macOS 12 Monterey · 13 Ventura · 14 Sonoma — Intel & Apple Silicon',
    packages: [
      { type:'macpkg', label:'.pkg', desc:'macOS Installer package', badge:'Installer', suffix:'macos', velo:'SOC heartbeat client-id sync' },
      { type:'dmg', label:'.dmg', desc:'Disk image containing .pkg installer', badge:'Disk Image', suffix:'macos', velo:'SOC heartbeat client-id sync' },
    ],
    install: [
      { title:'Step 1 - Open terminal in Downloads', code:'cd ~/Downloads\nls -lh soc-agent_*' },
      { title:'Step 2A - Install .pkg', code:'sudo installer -pkg soc-agent_*.pkg -target /' },
      { title:'Step 2B - Install from .dmg', code:'open soc-agent_*.dmg\n# Double-click the included SOC Agent .pkg installer' },
      { title:'Step 3 - Create uninstall password', code:'sudo bash /opt/soc-agent/set-uninstall-password.sh\n# Enter and confirm the SOC Agent uninstall password' },
      { title:'Step 4 - Verify service and connection', code:'launchctl list | grep soc.agent\nsudo python3 /opt/soc-agent/agent.py test' },
    ],
    uninstall: [
      { title:'Run protected uninstaller', code:'sudo bash /opt/soc-agent/uninstall.sh\n# Enter the macOS administrator password\n# Enter the SOC Agent uninstall password' },
      { title:'Verify removal', code:'launchctl list | grep soc.agent || echo "Agent service removed"\ntest ! -e /opt/soc-agent && echo "Files removed"' },
    ],
  },
  {
    key: 'zip', icon: '📦', label: 'Universal', color: '#64748b',
    distros: 'Any OS — auto-detects platform and installs accordingly',
    packages: [
      { type:'zip', label:'.zip', desc:'All platforms (auto-detect)', badge:'Universal', velo:'Velociraptor auto-install on Linux' },
    ],
    install: [
      { title:'Step 1 - Extract on Linux / macOS', code:'cd ~/Downloads\nunzip soc-agent_*_universal.zip\ncd soc-agent_*_universal' },
      { title:'Step 2 - Install on Linux / macOS', code:'sudo bash install.sh\n# Set uninstall password when prompted' },
      { title:'Step 1 - Extract on Windows', code:'cd $env:USERPROFILE\\Downloads\nExpand-Archive .\\soc-agent_*_universal.zip -DestinationPath .\\soc-agent_universal -Force\ncd .\\soc-agent_universal\\soc-agent_*_universal' },
      { title:'Step 2 - Install on Windows', code:'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass\n.\\install.ps1\n# Set uninstall password when prompted' },
      { title:'Step 3 - Verify', code:'# Linux:\nsudo systemctl status soc-agent --no-pager\n\n# macOS:\nlaunchctl list | grep soc.agent\n\n# Windows:\nGet-Service SOCAgent' },
    ],
    uninstall: [
      { title:'Linux / macOS', code:'sudo bash /opt/soc-agent/uninstall.sh\n# Enter the SOC Agent uninstall password' },
      { title:'Windows PowerShell as Administrator', code:'powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\\AJNAT\\uninstall.ps1"\n# Enter the uninstall password in the protected dialog' },
    ],
  },
  {
    key: 'android', icon: '🤖', label: 'Android', color: '#22c55e',
    distros: 'Android 8+',
    packages: [
      { id:'android-apk', type:'apk', label:'.apk', desc:'Installable Android agent app', badge:'APK', suffix:'android', velo:'Not supported on Android' },
    ],
    install: [
      { title:'Step 1 - Prepare managed device', code:'For enforced uninstall protection, use a new/factory-reset device.\nDo not add Google or work accounts before Device Owner provisioning.' },
      { title:'Step 2 - Install APK', code:'adb install -r soc-agent_*.apk\n# Or transfer the APK to the device and open it' },
      { title:'Step 3 - Enable Device Owner protection', code:'adb shell dpm set-device-owner com.soc.agent/.AgentDeviceAdminReceiver' },
      { title:'Step 4 - Set password and start agent', code:'Open SOC Agent on the phone.\nCreate and confirm an 8+ character protection password.\nGrant requested permissions, then tap START AGENT.' },
      { title:'Step 5 - Verify', code:'adb shell pm path com.soc.agent\nadb shell dpm list-owners' },
    ],
    uninstall: [
      { title:'Authorize inside the app', code:'Open SOC Agent > UNINSTALL AGENT\nEnter the protection password\nConfirm the Android uninstall dialog' },
      { title:'Verify removal', code:'adb shell pm path com.soc.agent || echo "Agent uninstalled"' },
      { title:'Important', code:'Do not use adb uninstall for managed removal.\nOS-level uninstall blocking requires Device Owner mode.' },
    ],
  },
  {
    key: 'iphone', icon: '📱', label: 'iPhone', color: '#a78bfa',
    distros: 'iOS / iPadOS — requires Apple Developer signing',
    packages: [
      { id:'iphone-ipa', type:'ipa', label:'.ipa', desc:'iPhone/iPad agent package', badge:'iOS', suffix:'iphone', unavailable:true, velo:'Not available yet' },
    ],
    install: [
      { title:'Distribution', code:'iOS apps require Apple Developer signing\nUse TestFlight, Apple Business Manager, or MDM' },
      { title:'Status', code:'iPhone package builder is not connected yet' },
    ],
    uninstall: [
      { title:'Not currently applicable', code:'No iPhone agent package is available yet.' },
    ],
  },
  {
    key: 'linux-server', icon: '🖥️', label: 'Linux Server', color: '#14b8a6',
    distros: 'Ubuntu Server · Debian Server · RHEL · Rocky · AlmaLinux',
    packages: [
      { id:'linux-server-deb', type:'deb', label:'.deb', desc:'Linux server Debian/Ubuntu package', badge:'server deb', suffix:'linux-server-deb', velo:'Velociraptor auto-install' },
      { id:'linux-server-rpm', type:'rpm', label:'.rpm', desc:'Linux server RHEL/Rocky/Fedora package', badge:'server rpm', suffix:'linux-server-rpm', velo:'Velociraptor auto-install' },
    ],
    install: [
      { title:'Install on Debian / Ubuntu Server', code:'cd ~/Downloads\nsudo apt install ./soc-agent*_linux-server-deb.deb' },
      { title:'Install on RHEL / Rocky / AlmaLinux', code:'cd ~/Downloads\nsudo dnf install ./soc-agent*_linux-server-rpm.rpm' },
      { title:'Create uninstall password', code:'Enter and confirm the uninstall password when prompted.\nKeep it safely; removal is blocked without it.' },
      { title:'Verify service and connection', code:'sudo systemctl is-active soc-agent\nsudo python3 /opt/soc-agent/agent.py test' },
    ],
    uninstall: [
      { title:'Debian / Ubuntu Server', code:'sudo apt remove soc-agent\n# Enter the SOC Agent uninstall password' },
      { title:'RHEL / Rocky / AlmaLinux', code:'sudo dnf remove soc-agent\n# Enter the SOC Agent uninstall password' },
      { title:'Verify removal', code:'sudo systemctl is-active soc-agent 2>/dev/null || echo "Agent uninstalled"' },
    ],
  },
  {
    key: 'windows-server', icon: '▦', label: 'Windows Server', color: '#38bdf8',
    distros: 'Windows Server 2016 · 2019 · 2022',
    packages: [
      { id:'windows-server-exe', type:'exe', label:'.exe', desc:'Windows Server executable package', badge:'server exe', suffix:'windows-server-exe', velo:'SOC heartbeat client-id sync' },
      { id:'windows-server-msi', type:'msi', label:'.msi', desc:'Windows Server MSI deployment package', badge:'server msi', suffix:'windows-server-msi', velo:'SOC heartbeat client-id sync' },
    ],
    install: [
      { title:'Step 1 - Download for the correct server System', code:'Download the server .exe or .msi from this system row.\nEach package contains the selected server\'s current enrollment key. Keep the same installer format for updates.' },
      { title:'Step 2 - Double-click the downloaded installer', code:'.exe: double-click the downloaded file.\n.msi: double-click the downloaded file, then click Install.\nSelect Yes on the Windows UAC prompt. No PowerShell command is required.' },
      { title:'Step 3 - Automatic install or update', code:'The package requests administrator access automatically, installs dependencies, repairs AJNAT when needed, and starts SOCAgent.' },
      { title:'Step 4 - Verify', code:'Get-Service SOCAgent\npython "$env:ProgramFiles\\AJNAT\\agent.py" test --config "$env:ProgramData\\AJNAT\\config\\company_config.json"\nGet-Content "$env:ProgramData\\AJNAT\\logs\\service-install.log" -Tail 80' },
    ],
    uninstall: [
      { title:'Uninstall .exe deployment', code:'Start-Process "$env:ProgramFiles\\AJNAT\\uninstall.exe" -Verb RunAs -Wait\n# Enter the uninstall password' },
      { title:'Uninstall .msi deployment', code:'$msi = (Get-ChildItem "$env:USERPROFILE\\Downloads\\soc-agent_*_windows-server-msi.msi" | Select-Object -First 1).FullName\nmsiexec.exe /x "$msi" /L*v "$env:TEMP\\soc-agent-msi-uninstall.log"' },
      { title:'Verify or recover stale service', code:'Get-Service SOCAgent -ErrorAction SilentlyContinue\n# After a successful uninstall only, remove a stale service entry with:\nsc.exe delete SOCAgent' },
    ],
  },
  {
    key: 'solaris-server', icon: '☀️', label: 'Solaris Server', color: '#fb7185',
    distros: 'Solaris server package support · ZFS-backed install',
    packages: [
      { id:'solaris-server', type:'solaris', label:'.sh', desc:'Solaris server ZFS installer', badge:'ZFS', suffix:'solaris-zfs', velo:'Not supported on Solaris' },
    ],
    install: [
      { title:'Step 1 - Open shell in package folder', code:'cd ~/Downloads\nchmod +x soc-agent_*_solaris-zfs.sh' },
      { title:'Step 2A - Install on default ZFS dataset', code:'sudo ./soc-agent_*_solaris-zfs.sh\n# Set uninstall password when prompted' },
      { title:'Step 2B - Install with custom ZFS dataset', code:'sudo SOC_AGENT_ZFS_DATASET=tank/soc-agent ./soc-agent_*_solaris-zfs.sh\n# Set uninstall password when prompted' },
      { title:'Step 3 - Check ZFS dataset', code:'zfs list rpool/opt/soc-agent\nzfs get mountpoint,compression rpool/opt/soc-agent' },
      { title:'Step 4 - Verify service', code:'svcs soc-agent\nsvcs -xv soc-agent' },
    ],
    uninstall: [
      { title:'Default ZFS dataset', code:'sudo bash /opt/soc-agent/uninstall.sh\n# Enter the SOC Agent uninstall password' },
      { title:'Custom ZFS dataset', code:'sudo SOC_AGENT_ZFS_DATASET=tank/soc-agent bash /opt/soc-agent/uninstall.sh\n# Enter the SOC Agent uninstall password' },
      { title:'Verify removal', code:'svcs soc-agent 2>/dev/null || echo "Agent service removed"\nzfs list rpool/opt/soc-agent 2>/dev/null || echo "Dataset removed"' },
    ],
  },
];

// ── Styles ────────────────────────────────────────────────────────────────────
const S = {
  card: {
    background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:10,
    padding:'18px 20px', marginBottom:18,
  },
  osTab: (active, color) => ({
    display:'flex', alignItems:'center', gap:6, padding:'10px 18px',
    border:'none', borderBottom: active ? `2px solid ${color}` : '2px solid transparent',
    background:'transparent', color: active ? color : '#475569',
    cursor:'pointer', fontSize:13, fontWeight: active ? 600 : 400,
    transition:'all .15s',
  }),
  badge: (color) => ({
    fontSize:9, padding:'2px 8px', borderRadius:10,
    background:`${color}22`, color, border:`1px solid ${color}44`,
    fontWeight:600, whiteSpace:'nowrap',
  }),
  statusBadge: (status) => ({
    fontSize:9, padding:'2px 8px', borderRadius:10,
    background: status==='active'?'#064e3b':status==='pending'?'#78350f':'#1f2937',
    color:      status==='active'?'#34d399':status==='pending'?'#fcd34d':'#6b7280',
    fontWeight:600,
  }),
};

// ── Helper: Handle download errors with SweetAlert2 for critical errors ───────
function handleDownloadError(err, navigate) {
  const response = err.response?.data;
  const statusCode = err.response?.status;
  const msg = response?.message || err.message || 'Download failed';
  const current = response?.current ?? response?.used ?? 0;
  const limit = response?.limit ?? 0;

  // For NO_SYSTEM_FOUND error, show a popup to add a system first
  if (response?.code === 'NO_SYSTEM_FOUND' || (statusCode === 400 && msg.includes('Please add a system'))) {
    Swal.fire({
      icon: 'warning',
      title: '⚠️ No System Found',
      html: `
        <div style="text-align: left; color: #000000;">
          <p style="margin: 12px 0; font-size: 14px; font-weight: bold;">Before downloading the agent, you need to add at least one system first.</p>
          <p style="margin: 12px 0; font-size: 13px; color: #000000;">
            Please go to the Systems page to register your first system.
          </p>
        </div>
      `,
      confirmButtonColor: '#3b82f6',
      confirmButtonText: '➕ Add System',
      showCancelButton: true,
      cancelButtonColor: '#6b7280',
      cancelButtonText: 'Cancel',
      allowOutsideClick: false,
    }).then((result) => {
      if (result.isConfirmed) {
        navigate('/systems');
      }
    });
  } else if (response?.type === 'limit_exceeded' || statusCode === 403) {
    // For limit_exceeded or 403 status, show a prominent alert with payment option
    Swal.fire({
      icon: 'error',
      title: '💳 Subscription Limit Exceeded',
      html: `
        <div style="text-align: left; color: #000000;">
          <p style="margin: 12px 0; font-size: 14px; font-weight: bold;">Your agent subscription limit has been reached.</p>
          <p style="margin: 12px 0; font-size: 13px; color: #000000; font-weight: bold;">
            To download more agents, please upgrade your plan.
          </p>
        </div>
      `,
      confirmButtonColor: '#3b82f6',
      confirmButtonText: '⬆️ Add more License',
      showCancelButton: true,
      cancelButtonColor: '#6b7280',
      cancelButtonText: 'Cancel',
      allowOutsideClick: false,
    }).then((result) => {
      if (result.isConfirmed) {
        navigate('/payments?tab=upgrade');
      }
    });
  } else if (statusCode === 400 || statusCode === 404) {
    // For client/not-found errors
    toast.error(msg, {
      duration: 5000,
      position: 'top-center',
      style: {
        background: '#7f1d1d',
        color: '#fecaca',
        border: '2px solid #dc2626',
        borderRadius: '8px',
        fontSize: '14px',
        fontWeight: '600',
        padding: '16px 20px',
      },
    });
  } else {
    // For other errors, show toast
    toast.error(msg, {
      duration: 5000,
      position: 'top-center',
      style: {
        background: '#7f1d1d',
        color: '#fecaca',
        border: '2px solid #dc2626',
        borderRadius: '8px',
        fontSize: '14px',
        fontWeight: '600',
        padding: '16px 20px',
      },
    });
  }
}

function getPackageCategory(pkg, activeOs = '') {
  const type = typeof pkg === 'string' ? pkg : (pkg?.type || '');
  const text = `${activeOs} ${type} ${pkg?.id || ''} ${pkg?.suffix || ''}`.toLowerCase();
  if (/zip|universal/.test(text)) return 'universal';
  if (/android|iphone|ipad|ios|ipados|apk|ipa/.test(text)) return 'android';
  if (/server|solaris|sunos/.test(text)) return 'server';
  return 'system';
}

function incrementDeviceCount(stats, category) {
  const key = category === 'server'
    ? 'servers'
    : category === 'system'
      ? 'systems'
      : category;

  return {
    ...stats,
    totalDownloads: (stats.totalDownloads || 0) + 1,
    downloadsByDevice: {
      ...(stats.downloadsByDevice || {}),
      [key]: ((stats.downloadsByDevice || {})[key] || 0) + 1,
    },
  };
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function AgentDownloadPage() {
  const navigate = useNavigate();
  const { isDeptAdmin } = useAuth();
  const [stats,       setStats]       = useState(null);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState('');
  const [activeOs,    setActiveOs]    = useState('linux');
  const [downloading, setDownloading] = useState(new Set()); // Track multiple concurrent downloads
  const [prebuildingPackages, setPrebuildingPackages] = useState(false); // Track prebuild status
  const [completed,   setCompleted]   = useState({});  // Track completed downloads: { 'deb': true, 'rpm': true, ... }
  const [showInstall, setShowInstall] = useState(null); // Show install modal for selected package type
  const [openPackageCards, setOpenPackageCards] = useState({});
  const [showOsDetails, setShowOsDetails] = useState(true);
  const downloadsDisabled = true;

  const load = useCallback(() => {
    setLoading(true); setError('');
    api.get('/agent/stats')
      .then(r => setStats(r.data))
      .catch(err => setError(err.response?.data?.message || 'Failed to load'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  // ── Download package (license-based, uses first available system) ────────
  const downloadPkg = async (pkg, osKey = activeOs) => {
    if (downloadsDisabled) {
      toast.error('Agent downloads are currently disabled.', {
        duration: 3500,
        position: 'top-center',
      });
      return;
    }

    const pkgType = typeof pkg === 'string' ? pkg : pkg.type;
    const downloadKey = typeof pkg === 'string' ? pkg : (pkg.id || pkg.type);
    const downloadCategory = getPackageCategory(pkg, osKey);
    if (pkg?.unavailable) {
      toast.error(`${pkg.label} package builder is not connected yet.`, {
        duration: 3500,
        position: 'top-center',
      });
      return;
    }
    // Add to downloading set
    setDownloading(prev => new Set(prev).add(downloadKey));
    try {
      // Use the company-level download endpoint
      const resp = await api.get(`/agent/download/${pkgType}?category=${encodeURIComponent(downloadCategory)}`, { responseType:'blob' });
      const url  = URL.createObjectURL(resp.data);
      const a    = document.createElement('a');
      a.href     = url;
      const suffix = pkg?.suffix || { deb:'linux', rpm:'linux', exe:'windows-exe', msi:'windows-msi', pkg:'macos-installer', macpkg:'macos', dmg:'macos', zip:'universal', apk:'android', solaris:'solaris-zfs' }[pkgType] || pkgType;
      const ext = pkgType === 'apk' ? 'apk' : pkgType === 'exe' ? 'exe' : pkgType === 'msi' ? 'msi' : pkgType === 'macpkg' ? 'pkg' : pkgType === 'dmg' ? 'dmg' : pkgType === 'deb' ? 'deb' : pkgType === 'rpm' ? 'rpm' : pkgType === 'solaris' ? 'sh' : 'zip';
      a.download = `soc-agent_v${currentVersion}_${suffix}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      
      // Mark as completed
      setCompleted(prev => ({ ...prev, [downloadKey]: true }));
      
      const installHint = ['exe', 'msi'].includes(pkgType)
        ? 'Double-click the downloaded installer and select Yes on the Windows UAC prompt.'
        : pkgType === 'deb'
        ? `Install/repair with sudo apt install ./soc-agent*_${suffix}.deb`
        : pkgType === 'rpm'
          ? `Install with sudo dnf install ./soc-agent*_${suffix}.rpm`
          : 'Install package downloaded';
      toast.success(`✅ Agent v${currentVersion} downloaded! ${installHint}`, {
        duration: 4000,
        position: 'top-center',
        style: {
          background: '#064e3b',
          color: '#34d399',
          border: '2px solid #10b981',
          borderRadius: '8px',
          fontSize: '14px',
          fontWeight: '600',
          padding: '16px 20px',
        },
      });
      setStats(prev => prev ? incrementDeviceCount(prev, downloadCategory) : prev);
    } catch (err) {
      handleDownloadError(err, navigate);
    } finally { 
      // Remove from downloading set
      setDownloading(prev => {
        const newSet = new Set(prev);
        newSet.delete(downloadKey);
        return newSet;
      });
    }
  };

  // ── Prepare package builders ───────────────────────────────────────────────
  const triggerPrebuild = async () => {
    if (!confirm('Prepare all agent package types (deb, rpm, exe, msi, pkg, zip, apk)?\n\nCompany/system config will still be added only at download time.')) return;
    
    setPrebuildingPackages(true);
    try {
      const resp = await api.post('/agent/prebuild');
      toast.success(resp.data?.message || '✅ Agent package builders are ready.', {
        duration: 5000,
        position: 'top-center',
        style: {
          background: '#064e3b',
          color: '#34d399',
          border: '2px solid #10b981',
          borderRadius: '8px',
          fontSize: '14px',
          fontWeight: '600',
          padding: '16px 20px',
        },
      });
      // Refresh stats after a delay
      setTimeout(() => {
        load();
        setPrebuildingPackages(false);
      }, 3000);
    } catch (err) {
      toast.error('Failed to start pre-build: ' + (err.response?.data?.message || err.message), {
        duration: 5000,
        position: 'top-center',
        style: {
          background: '#7f1d1d',
          color: '#fecaca',
          border: '2px solid #dc2626',
          borderRadius: '8px',
          fontSize: '14px',
          fontWeight: '600',
          padding: '16px 20px',
        },
      });
      setPrebuildingPackages(false);
    }
  };

  const plan     = stats?.plan      || {};
  const systems  = stats?.systems   || [];
  const byOs     = stats?.byOs      || {};
  const byDevice = stats?.byDevice  || {};
  const byStatus = stats?.byStatus  || {};
  const systemCount = byDevice.systems ?? systems.filter(s => {
    const text = `${s.agentType || ''} ${s.os || ''} ${s.osType || ''} ${s.name || ''} ${s.hostname || ''}`.toLowerCase();
    if (s.agentType === 'system') return true;
    return !/android|iphone|ipad|ios|ipados|server|solaris|sunos/.test(text);
  }).length;
  const serverCount = byDevice.servers ?? systems.filter(s => {
    const text = `${s.agentType || ''} ${s.os || ''} ${s.osType || ''} ${s.name || ''} ${s.hostname || ''}`.toLowerCase();
    return s.agentType === 'server' || /server|solaris|sunos/.test(text);
  }).length;
  const androidCount = byDevice.android ?? byOs.android ?? systems.filter(s => {
    const text = `${s.agentType || ''} ${s.os || ''} ${s.osType || ''} ${s.name || ''} ${s.hostname || ''}`.toLowerCase();
    return s.agentType === 'phone' || /android|iphone|ipad|ios|ipados/.test(text);
  }).length;
  const universalCount = byDevice.universal ?? 0;
  const currentVersion = stats?.currentVersion || '—';
  const activeTab = OS_TABS.find(t => t.key === activeOs) || OS_TABS[0];
  // Check if download limit reached based on TOTAL DOWNLOADS, not installed systems
  const limitReached = plan.limit > 0 && stats?.totalDownloads && stats.totalDownloads >= plan.limit;

  return (
    <div>
      {/* ── Header ── */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:20 }}>
        <div>
          <h2 style={{ fontSize:20, color:'#e0f2fe', margin:0 }}>Download Agent</h2>
          <p style={{ fontSize:12, color:'#1e40af', marginTop:4 }}>
            Download once → Install on endpoints → Each installed agent uses 1 license.
          </p>
        </div>
        <button onClick={load} disabled={loading} style={{
          fontSize:11, padding:'6px 12px', borderRadius:6,
          border:'1px solid #1e3a5f', background:'none', color:'#60a5fa', cursor:'pointer',
        }}>{loading ? '⟳' : '↺ Refresh'}</button>
      </div>

      {error && <div style={{ background:'#1c0a0a', color:'#fca5a5', padding:'10px 14px', borderRadius:6, marginBottom:14, fontSize:13 }}>{error}</div>}

      {/* ── NEW VERSION AVAILABLE BANNER ── */}
      {stats?.systems?.some(s => s.agentVersion && s.agentVersion !== currentVersion) && (
        <div style={{
          background: 'linear-gradient(135deg, #f59e0b 0%, #f97316 100%)',
          border: '2px solid #fbbf24',
          borderRadius: 8,
          padding: 14,
          marginBottom: 16,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 14,
          flexWrap: 'wrap',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ fontSize: 20 }}>⬆️</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#78350f' }}>
                New Agent Version Available: v{currentVersion}
              </div>
              <div style={{ fontSize: 11, color: '#92400e', marginTop: 2 }}>
                Some of your systems are running older versions. Download the latest release to update them.
              </div>
            </div>
          </div>
          <div style={{ fontSize: 10, color: '#92400e', fontWeight: 600 }}>
            Current: {stats?.systems?.filter(s => s.agentVersion).map(s => s.agentVersion).join(', ') || '?'}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          SECTION 1: License Overview
          ══════════════════════════════════════════════════════════════════════ */}
      <div style={S.card}>
        <div style={{
          display:'grid',
          gridTemplateColumns:'repeat(7, minmax(92px, 1fr)) repeat(4, 66px)',
          gap:10,
          overflowX:'auto',
          marginBottom:12,
        }}>
          {/* License stats */}
          {[
            { label:'Total Licenses',  value: plan.limit || 0, color:'#60a5fa' },
            { label:'System Licenses', value: plan.systemCount || 0, color:'#38bdf8' },
            { label:'Phone Licenses',  value: plan.phoneCount || 0, color:'#a78bfa' },
            { label:'Server Licenses', value: plan.serverCount || 0, color:'#14b8a6' },
            { label:'Installed',       value: plan.used || 0, color:'#34d399' },
            { label:'Registered',      value: stats?.systems?.length || 0, color:'#93c5fd' },
            { label:'Total Downloads', value: stats?.totalDownloads || 0, color:'#c084fc' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              background:'#060e1a', borderRadius:8, padding:'8px 8px',
              border:`1px solid ${color}22`, minWidth:0, textAlign:'center',
            }}>
              <div style={{ fontSize:22, fontWeight:700, color }}>{value}</div>
              <div style={{ fontSize:9, color:'#1e40af', marginTop:2, whiteSpace:'nowrap' }}>{label}</div>
            </div>
          ))}
          {/* Device/package counters */}
          {[
            { key:'system',  icon:'💻', label:'System',  value: systemCount },
            { key:'server',  icon:'🖥️', label:'Server',  value: serverCount },
            { key:'android', icon:'🤖', label:'Android', value: androidCount },
            { key:'universal', icon:'📦', label:'Universal', value: universalCount },
          ].map(({ key, icon, label, value }) => (
            <div key={key} style={{
              background:'#060e1a', borderRadius:8, padding:'8px 6px',
              border:'1px solid #1e3a5f', minWidth:0, textAlign:'center',
            }}>
              <div style={{ fontSize:16, marginBottom:1 }}>{icon}</div>
              <div style={{ fontSize:19, fontWeight:600, color:'#e2e8f0' }}>{typeof value === 'number' ? value : byOs[key] || 0}</div>
              <div style={{ fontSize:9, color:'#1e40af' }}>{label}</div>
            </div>
          ))}
        </div>

        {/* License bar */}
        {plan.limit > 0 && (
          <div>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
              <span style={{ fontSize:10, color:'#1e40af' }}>
                License usage
                <span style={{ marginLeft:6, color:'#475569' }}>
                  ({plan.systemCount || 0} systems + {plan.serverCount || 0} servers + {plan.phoneCount || 0} phones)
                </span>
              </span>
              <span style={{ fontSize:10, color:'#1e40af' }}>{plan.used||0}/{plan.limit} ({plan.pct||0}%)</span>
            </div>
            <div style={{ background:'#060e1a', borderRadius:6, height:8, overflow:'hidden', border:'1px solid #1e3a5f' }}>
              <div style={{
                height:'100%', borderRadius:6, transition:'width .6s',
                width:`${Math.min(plan.pct||0,100)}%`,
                background: plan.pct>=100?'#f87171':plan.pct>=80?'#f59e0b':'#2563eb',
              }}/>
            </div>
            {limitReached && (
              <p style={{ fontSize:11, color:'#f87171', marginTop:6 }}>
                ⚠ License limit reached. <Link to="/payments?tab=upgrade" style={{ color:'#f59e0b', textDecoration:'none' }}>Add more License →</Link>
              </p>
            )}
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          SECTION 2: Download Card — All Packages Grid + Tab View
          ══════════════════════════════════════════════════════════════════════ */}
      <div style={S.card}>
        {/* ── WARNING: Systems showing ACTIVE but agent uninstalled ── */}
        {stats?.systems?.some(s => s.status === 'active' && !s.agentVersion) && (
          <div style={{
            background: '#7c2d12',
            border: '2px solid #ea580c',
            borderRadius: 8,
            padding: 12,
            marginBottom: 14,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
          }}>
            <div style={{ fontSize: 20 }}>⚠️</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#fed7aa' }}>
                Agent Uninstalled But Still Shows ACTIVE
              </div>
              <div style={{ fontSize: 11, color: '#fdba74', marginTop: 4 }}>
                {stats.systems.filter(s => s.status === 'active' && !s.agentVersion).map(s => s.name).join(', ')} {' '}
                — Uninstalled the agent but server still shows
                ACTIVE. Go to Systems to mark as offline or delete.
              </div>
            </div>
          </div>
        )}

        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:8, gap:12 }}>
          <div style={{ flex:1 }}>
            <h3 style={{ fontSize:14, color:'#60a5fa', margin:0, marginBottom:4 }}>
              📥 Download Agent Packages
            </h3>
            <div style={{ display:'flex', gap:12, alignItems:'center', marginBottom:0 }}>
              <span style={{ fontSize:11, background:'#2563eb33', color:'#3b82f6', padding:'4px 10px', borderRadius:6, fontWeight:600 }}>
                v{currentVersion}
              </span>
              <span style={{ fontSize:10, color:'#475569' }}>
                📦 {OS_TABS.reduce((acc, os) => acc + os.packages.length, 0)} packages available
              </span>
            </div>
          </div>
          <div style={{ display:'flex', alignItems:'flex-end', gap:8, flexDirection:'column' }}>
            {!isDeptAdmin && <button
              onClick={triggerPrebuild}
              disabled={prebuildingPackages}
              style={{
                fontSize:10, padding:'6px 12px', borderRadius:6,
                border:'1px solid #f59e0b', background:'#f59e0b22', color:'#f59e0b', 
                cursor:prebuildingPackages?'wait':'pointer', fontWeight:600, whiteSpace:'nowrap',
                opacity:prebuildingPackages?0.6:1,
              }}>
              {prebuildingPackages ? '⟳ Updating...' : '⚡ Update Package Types'}
            </button>}
            <div style={{ textAlign:'right' }}>
              <div style={{ fontSize:10, color:'#1e40af', marginBottom:2 }}>Latest version</div>
              <div style={{ fontSize:13, fontWeight:700, color:'#34d399' }}>v{currentVersion}</div>
            </div>
          </div>
        </div>
        <p style={{ fontSize:11, color:'#1e40af', marginBottom:14 }}>
          Download once → Install on endpoints → Each install uses <strong style={{ color:'#f59e0b' }}>1 license</strong>. Auto-detects OS during installation.
        </p>

        {/* ── PRE-BUILD INFO ──────────────────────────────────────────────── */}
        <div style={{
          background: '#1e3a8a22',
          border: '1px solid #1e3a5f',
          borderRadius: 8,
          padding: 12,
          marginBottom: 16,
          fontSize: 11,
          color: '#93c5fd',
          lineHeight: 1.6,
        }}>
          <strong style={{ color:'#60a5fa' }}>💡 Package build/update:</strong> Clicking <strong>"⚡ Update Package Types"</strong> prepares the agent package types (Linux .deb/.rpm, Windows .exe/.msi, macOS .pkg/.dmg, Universal .zip, Android .apk, Solaris). Company/system config is added only when you download, and completed packages are not stored on the server.
          <br />
          <strong style={{ color:'#34d399' }}>Server connection:</strong> Every downloaded package includes <code>company_config.json</code> with the backend URL from <code>SERVER_PROTO</code>, <code>SERVER_IP</code>, and <code>SERVER_PORT</code>. The agent connects to that server on first heartbeat.
          <br />
          <strong style={{ color:'#22d3ee' }}>Log collection baseline:</strong> The agent collects logs from the install/start time only. Existing old system logs are skipped and are not uploaded as new alerts.
          <br />
          <strong style={{ color:'#f59e0b' }}>Velociraptor:</strong> Linux packages can auto-install the bundled Velociraptor client during SOC agent install, then the SOC agent reads the local <code>C.xxxx</code> id and sends it to the server.
        </div>

        {/* ── ALL PACKAGES GRID VIEW ────────────────────────────────────── */}
        <div style={{ marginBottom:20 }}>
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:14 }}>
            <div style={{ fontSize:11, color:'#1e40af', fontWeight:600 }}>ALL AVAILABLE PACKAGES:</div>
            <div style={{ flex:1, height:'1px', background:'linear-gradient(90deg, #1e3a5f, transparent)' }}/>
          </div>
          <div style={{
            background:'#052e2b55',
            border:'1px solid #0f766e',
            borderRadius:8,
            padding:10,
            marginBottom:14,
            fontSize:11,
            color:'#99f6e4',
            lineHeight:1.55,
          }}>
            <strong style={{ color:'#2dd4bf' }}>Auto setup:</strong> Packages install the SOC agent, write the system-specific config at download time, connect back to the configured SOC backend, and on Linux auto-start bundled Velociraptor when the client bundle is readable.
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(280px, 1fr))', gap:14 }}>
            {OS_TABS.map(os => {
              const isOpen = !!openPackageCards[os.key];
              const osBusy = os.packages.some(pkg => downloading.has(pkg.id || pkg.type));
              const osCompleted = os.packages.some(pkg => completed[pkg.id || pkg.type]);
              return (
                <div key={os.key}
                  onClick={() => setOpenPackageCards(prev => ({ ...prev, [os.key]: !prev[os.key] }))}
                  style={{
                    background:'#060e1a',
                    border:'2px solid #1e3a5f',
                    borderRadius:10,
                    padding:14,
                    cursor:'pointer',
                    transition:'all .2s',
                    minHeight: isOpen ? 0 : 118,
                  }}>
                  <div style={{ display:'flex', alignItems:'flex-start', gap:10 }}>
                    <span style={{ fontSize:26 }}>{os.icon}</span>
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:8 }}>
                        <div style={{ fontSize:14, fontWeight:700, color:'#e2e8f0' }}>{os.label}</div>
                        <div style={{ fontSize:16, color:os.color }}>{isOpen ? '⌃' : '⌄'}</div>
                      </div>
                      <div style={{ fontSize:10, color:'#1e40af', marginTop:4, lineHeight:1.4 }}>{os.distros}</div>
                    </div>
                  </div>

                  <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginTop:12 }}>
                    {os.packages.map(pkg => (
                      <span key={pkg.id || pkg.type} style={S.badge(pkg.unavailable ? '#64748b' : os.color)}>
                        {pkg.label}
                      </span>
                    ))}
                  </div>

                  {isOpen && (
                    <div style={{ marginTop:14, display:'grid', gap:10 }}>
                      {os.packages.map(pkg => {
                        const pkgKey = pkg.id || pkg.type;
                        const busy = downloading.has(pkgKey);
                        const isCompleted = completed[pkgKey];
                        const disabled = downloadsDisabled || downloading.size > 0 || limitReached || pkg.unavailable;
                        return (
                          <button key={pkgKey}
                            onClick={e => {
                              e.stopPropagation();
                              downloadPkg(pkg, os.key);
                            }}
                            disabled={disabled}
                            style={{
                              display:'flex',
                              alignItems:'center',
                              justifyContent:'space-between',
                              gap:10,
                              padding:'11px 12px',
                              borderRadius:8,
                              border:`1px solid ${isCompleted ? '#34d399' : pkg.unavailable ? '#334155' : os.color}`,
                              background:downloadsDisabled ? '#020b14' : isCompleted ? '#064e3b33' : pkg.unavailable ? '#020b14' : `${os.color}12`,
                              color:disabled && !busy && !isCompleted ? '#64748b' : '#e2e8f0',
                              cursor:disabled ? 'not-allowed' : 'pointer',
                              textAlign:'left',
                            }}>
                            <div>
                              <div style={{ fontSize:13, fontWeight:700, color:isCompleted ? '#34d399' : pkg.unavailable ? '#64748b' : os.color }}>
                                {downloadsDisabled ? `${pkg.label} Download Disabled` : busy ? '⟳ Downloading...' : isCompleted ? `✓ ${pkg.label} Downloaded` : `↓ Download ${pkg.label}`}
                              </div>
                              <div style={{ fontSize:10, color:'#1e40af', marginTop:3 }}>{pkg.desc}</div>
                              {pkg.velo && (
                                <div style={{
                                  fontSize:10,
                                  color: pkg.velo.includes('auto-install') ? '#34d399' : pkg.velo.includes('Not') ? '#64748b' : '#38bdf8',
                                  marginTop:5,
                                  fontWeight:700,
                                }}>
                                  {pkg.velo.includes('auto-install') ? '🦖 ' : '🔗 '}{pkg.velo}
                                </div>
                              )}
                            </div>
                            <span style={S.badge(isCompleted ? '#34d399' : pkg.unavailable ? '#64748b' : os.color)}>
                              {downloadsDisabled ? 'Disabled' : pkg.unavailable ? 'Coming soon' : pkg.badge}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {limitReached && (
            <div style={{
              marginTop:14, padding:'10px 14px', borderRadius:8,
              background:'#1c0a0a', border:'1px solid #7f1d1d', fontSize:12, color:'#fca5a5',
            }}>
              🚫 License limit reached ({plan.used}/{plan.limit}). <Link to="/payments?tab=upgrade" style={{ color:'#f59e0b' }}>Add more License →</Link>
            </div>
          )}
        </div>

        <hr style={{ borderColor:'#1e3a5f', margin:'20px 0' }}/>

        <div style={{
          marginTop:20,
          background:'#060e1a',
          border:`1px solid ${showOsDetails ? activeTab.color : '#1e3a5f'}`,
          borderRadius:10,
          overflow:'hidden',
        }}>
          <button
            onClick={() => setShowOsDetails(prev => !prev)}
            style={{
              width:'100%',
              display:'flex',
              alignItems:'center',
              justifyContent:'space-between',
              gap:12,
              padding:'14px 16px',
              border:'none',
              background:'transparent',
              color:'#93c5fd',
              cursor:'pointer',
              textAlign:'left',
            }}>
            <span style={{ fontSize:11, color:'#1e40af', fontWeight:600 }}>INSTALL / UNINSTALL STEP BY STEP</span>
            <span style={{ fontSize:16, color:activeTab.color }}>{showOsDetails ? '⌃' : '⌄'}</span>
          </button>

          {showOsDetails && (
            <div style={{ padding:'0 16px 16px 16px' }}>
              <div style={{ display:'flex', gap:0, borderBottom:'1px solid #1e3a5f', flexWrap:'wrap', marginBottom:0 }}>
                {OS_TABS.map(tab => (
                  <button key={tab.key} onClick={() => setActiveOs(tab.key)}
                    style={S.osTab(activeOs===tab.key, tab.color)}>
                    <span style={{ fontSize:18 }}>{tab.icon}</span>
                    <span>{tab.label}</span>
                  </button>
                ))}
              </div>

              <div style={{
                fontSize:11, color:'#1e3a5f', marginTop:12, padding:'8px 12px',
                background:'#020b14', borderRadius:6, border:'1px solid #0d2240',
              }}>
                ℹ️ Supported: {activeTab.distros}
              </div>

              <div style={{ padding:'16px 0 0 0' }}>
                <div style={{ fontSize:11, color:'#34d399', fontWeight:700, marginBottom:12 }}>INSTALLATION</div>
                {activeTab.install.map((step, i) => (
                  <div key={i} style={{ marginBottom:16 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:6 }}>
                      <div style={{
                        width:22, height:22, borderRadius:'50%',
                        background: activeTab.color, color:'#000',
                        fontSize:11, fontWeight:700, flexShrink:0,
                        display:'flex', alignItems:'center', justifyContent:'center',
                      }}>{i+1}</div>
                      <span style={{ fontSize:12, color:'#93c5fd', fontWeight:500 }}>{step.title}</span>
                    </div>
                    <CodeBlock code={step.code}/>
                  </div>
                ))}

                <div style={{ borderTop:'1px solid #1e3a5f', paddingTop:16, marginTop:6 }}>
                  <div style={{ fontSize:11, color:'#fb7185', fontWeight:700, marginBottom:12 }}>UNINSTALLATION</div>
                  <div style={{ fontSize:11, color:'#fbbf24', marginBottom:14, lineHeight:1.5 }}>
                    Use the supported uninstaller below. The uninstall password created during setup is required; silent or manual file deletion is not supported.
                  </div>
                  {(activeTab.uninstall || []).map((step, i) => (
                    <div key={i} style={{ marginBottom:16 }}>
                      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:6 }}>
                        <div style={{
                          width:22, height:22, borderRadius:'50%',
                          background:'#fb7185', color:'#000',
                          fontSize:11, fontWeight:700, flexShrink:0,
                          display:'flex', alignItems:'center', justifyContent:'center',
                        }}>{i+1}</div>
                        <span style={{ fontSize:12, color:'#fda4af', fontWeight:500 }}>{step.title}</span>
                      </div>
                      <CodeBlock code={step.code}/>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

      </div>


      {/* ── Config paths ── */}
      <div style={S.card}>
        <h3 style={{ fontSize:13, color:'#60a5fa', marginBottom:10 }}>Config File Location</h3>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <thead>
            <tr style={{ borderBottom:'1px solid #1e3a5f' }}>
              {['OS','Install Path','Config Path'].map(h => (
                <th key={h} style={{ padding:'6px 10px', color:'#60a5fa', textAlign:'left', fontWeight:500 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { os:'🐧 Linux / Server', install:'/opt/soc-agent', cfg:'/opt/soc-agent/config/company_config.json' },
              { os:'🪟 Windows / Server', install:'C:\\Program Files\\AJNAT', cfg:'C:\\ProgramData\\AJNAT\\config\\company_config.json' },
              { os:'🍎 macOS', install:'/opt/soc-agent', cfg:'/opt/soc-agent/config/company_config.json' },
              { os:'🤖 Android', install:'Android app sandbox', cfg:'Bundled APK assets' },
              { os:'☀️ Solaris', install:'/opt/soc-agent', cfg:'/opt/soc-agent/config/company_config.json' },
            ].map(r => (
              <tr key={r.os} style={{ borderBottom:'1px solid #060e1a' }}>
                <td style={{ padding:'8px 10px', color:'#e2e8f0' }}>{r.os}</td>
                <td style={{ padding:'8px 10px', color:'#7dd3fc', fontFamily:'monospace', fontSize:11 }}>{r.install}</td>
                <td style={{ padding:'8px 10px', color:'#a78bfa', fontFamily:'monospace', fontSize:11 }}>{r.cfg}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Install Instructions Modal ── */}
      {showInstall && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '20px',
        }}>
          <div style={{
            background: '#0c1a2e',
            borderRadius: 12,
            border: '2px solid #2563eb',
            maxWidth: '600px',
            maxHeight: '90vh',
            overflowY: 'auto',
            padding: '24px',
            position: 'relative',
          }}>
            {/* Close button */}
            <button
              onClick={() => setShowInstall(null)}
              style={{
                position: 'absolute',
                top: '12px',
                right: '12px',
                background: 'none',
                border: 'none',
                color: '#60a5fa',
                fontSize: '24px',
                cursor: 'pointer',
                padding: '4px 8px',
              }}
            >
              ✕
            </button>

            <h2 style={{ fontSize: 16, color: '#60a5fa', marginTop: 0, marginBottom: 16 }}>
                📥 Installation Instructions for {{ 'deb': 'Linux (Debian/Ubuntu)', 'rpm': 'Linux (RHEL/CentOS)', 'exe': 'Windows (.exe)', 'msi': 'Windows (MSI)', 'macpkg': 'macOS (.pkg)', 'dmg': 'macOS (.dmg)', 'zip': 'Universal' }[showInstall]}
            </h2>

            {/* Find the appropriate install steps */}
            {showInstall === 'zip' ? (
              <div style={{ color: '#e2e8f0' }}>
                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 0 }}>Step 1: Extract the ZIP</h3>
                <CodeBlock code="# Linux / macOS:\nunzip soc-agent_*_universal.zip\ncd soc-agent_*_universal\n\n# Windows PowerShell:\nExpand-Archive .\\soc-agent_*_universal.zip -DestinationPath .\\soc-agent_universal\ncd .\\soc-agent_universal\\soc-agent_*_universal"/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Step 2: Run Installer</h3>
                <CodeBlock code="# Linux / macOS:\nsudo bash install.sh\n\n# Windows (PowerShell as Admin):\nSet-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass\n.\\install.ps1"/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Step 3: Verify Installation</h3>
                <CodeBlock code="# Linux:\nsystemctl status soc-agent\n\n# macOS:\nlaunchctl list | grep soc.agent\n\n# Windows:\nGet-Service SOCAgent"/>
              </div>
            ) : ['deb', 'rpm'].includes(showInstall) ? (
              <div style={{ color: '#e2e8f0' }}>
                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 0 }}>Install</h3>
                <CodeBlock code={showInstall === 'deb' ? 'cd ~/Downloads\nls -lh ./soc-agent*_linux-deb.deb\nsudo apt install ./soc-agent*_linux-deb.deb\n# If installation finishes with "installed and verified", an _apt permission notice is harmless.' : 'cd ~/Downloads\nls -lh ./soc-agent*_linux-rpm.rpm\nsudo dnf install ./soc-agent*_linux-rpm.rpm'}/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Verify</h3>
                <CodeBlock code={'sudo systemctl is-active soc-agent\nsudo python3 /opt/soc-agent/agent.py test'}/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Uninstall</h3>
                <CodeBlock code={showInstall === 'deb' ? 'sudo dpkg --remove soc-agent' : 'sudo dnf remove soc-agent'}/>
              </div>
            ) : showInstall === 'exe' ? (
              <div style={{ color: '#e2e8f0' }}>
                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 0 }}>Install or update .exe</h3>
                <CodeBlock code={'Double-click the downloaded .exe file.\nSelect Yes on the Windows UAC prompt.\nNo PowerShell command is required.'}/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Verify</h3>
                <CodeBlock code={'Get-Service SOCAgent\npython "$env:ProgramFiles\\AJNAT\\agent.py" test --config "$env:ProgramData\\AJNAT\\config\\company_config.json"'}/>

                <h3 style={{ color: '#fb7185', fontSize: 13, marginTop: 16 }}>Uninstall</h3>
                <CodeBlock code={'Start-Process "$env:ProgramFiles\\AJNAT\\uninstall.exe" -Verb RunAs -Wait'}/>
              </div>
            ) : showInstall === 'msi' ? (
              <div style={{ color: '#e2e8f0' }}>
                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 0 }}>Install or update .msi</h3>
                <CodeBlock code={'Double-click the downloaded .msi file, then click Install.\nSelect Yes on the Windows UAC prompt.\nNo PowerShell command is required.'}/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Verify</h3>
                <CodeBlock code={'Get-Service SOCAgent\npython "$env:ProgramFiles\\AJNAT\\agent.py" test --config "$env:ProgramData\\AJNAT\\config\\company_config.json"'}/>

                <h3 style={{ color: '#fb7185', fontSize: 13, marginTop: 16 }}>Uninstall with verbose logging</h3>
                <CodeBlock code={'msiexec.exe /x "$msi" /L*v "$env:TEMP\\soc-agent-msi-uninstall.log"'}/>
              </div>
            ) : ['macpkg', 'dmg'].includes(showInstall) ? (
              <div style={{ color: '#e2e8f0' }}>
                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 0 }}>Step 1: Install Package</h3>
                <CodeBlock code={showInstall === 'dmg' ? 'open soc-agent_*.dmg\n# Run the included SOC Agent .pkg installer' : 'sudo installer -pkg soc-agent_*.pkg -target /'}/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Step 2: Set Uninstall Password</h3>
                <CodeBlock code="sudo bash /opt/soc-agent/set-uninstall-password.sh"/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Step 3: Verify</h3>
                <CodeBlock code="sudo launchctl print system/com.soc.agent\nsudo /opt/soc-agent/.venv/bin/python3 /opt/soc-agent/agent.py test"/>

                <h3 style={{ color: '#34d399', fontSize: 13, marginTop: 16 }}>Step 4: Check Firewall</h3>
                <CodeBlock code="bash /opt/soc-agent/check-firewall.sh"/>

                <h3 style={{ color: '#fb7185', fontSize: 13, marginTop: 16 }}>Uninstall</h3>
                <CodeBlock code="sudo bash /opt/soc-agent/uninstall.sh"/>
              </div>
            ) : null}

            <div style={{ marginTop: 20, display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button
                onClick={() => setShowInstall(null)}
                style={{
                  padding: '8px 16px',
                  borderRadius: 6,
                  border: '1px solid #1e3a5f',
                  background: 'transparent',
                  color: '#60a5fa',
                  cursor: 'pointer',
                  fontSize: 12,
                  fontWeight: 600,
                }}
              >
                Close
              </button>
              <a
                href="https://docs.soc-platform.com/agent-installation"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  padding: '8px 16px',
                  borderRadius: 6,
                  border: 'none',
                  background: '#2563eb',
                  color: '#e0f2fe',
                  cursor: 'pointer',
                  fontSize: 12,
                  fontWeight: 600,
                  textDecoration: 'none',
                }}
              >
                📖 Full Documentation
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
