import { StatusBar } from 'expo-status-bar';
import { createContext, useContext, useMemo, useState } from 'react';
import { Image, Pressable, SafeAreaView, ScrollView, StyleSheet, Text, View, useColorScheme } from 'react-native';
import { nexusTokens } from './designTokens';

type Tab = 'Dashboard' | 'Devices' | 'Manage' | 'Terminal' | 'Settings';
type DeviceName = 'NixOS Workstation' | 'Debian Homelab Server';
type ManageScreen = 'overview' | 'services' | 'files' | 'network' | 'minecraft' | 'recipes';
const tabs: { name: Tab; icon: string }[] = [
  { name: 'Dashboard', icon: '▦' }, { name: 'Devices', icon: '▤' },
  { name: 'Manage', icon: '⌘' }, { name: 'Terminal', icon: '>_' }, { name: 'Settings', icon: '⚙' },
];
type ThemeColors = {
  bg: string; card: string; raised: string; line: string; text: string; muted: string;
  cyan: string; green: string; amber: string; red: string; cardBorder: string;
  demoBg: string; demoBorder: string; navBg: string; deviceIconBg: string;
  terminalBg: string; terminalText: string; codeBg: string; primaryBg: string;
};
type NexusTheme = { appearance: 'light' | 'dark'; C: ThemeColors; styles: ReturnType<typeof createStyles> };
const ThemeContext = createContext<NexusTheme | null>(null);

function makeColors(appearance: 'light' | 'dark'): ThemeColors {
  const p = appearance === 'light' ? nexusTokens.lightColor : nexusTokens.color;
  return {
    bg: p.background, card: p.surface, raised: p.raised, line: p.separator,
    text: p.text, muted: p.muted, cyan: p.accent, green: p.positive,
    amber: p.caution, red: p.critical,
    cardBorder: appearance === 'light' ? '#D7D7DC' : '#20242D',
    demoBg: appearance === 'light' ? '#E4F4F8' : '#142832',
    demoBorder: appearance === 'light' ? '#9BCBD6' : '#346579',
    navBg: appearance === 'light' ? '#FFFFFF' : '#11141A',
    deviceIconBg: appearance === 'light' ? '#E4F4F8' : '#1B2933',
    terminalBg: appearance === 'light' ? '#20232A' : '#0E1117',
    terminalText: '#B9D9CB',
    codeBg: appearance === 'light' ? '#E7E9ED' : '#0E1117',
    primaryBg: appearance === 'light' ? '#087B98' : '#1B748F',
  };
}

function useNexusTheme(): NexusTheme {
  const theme = useContext(ThemeContext);
  if (!theme) throw new Error('Nexus theme is missing');
  return theme;
}

export default function App() {
  const systemScheme = useColorScheme();
  const appearance: 'light' | 'dark' = systemScheme === 'dark' ? 'dark' : 'light';
  const theme = useMemo(() => {
    const C = makeColors(appearance);
    return { appearance, C, styles: createStyles(C) };
  }, [appearance]);
  return <ThemeContext.Provider value={theme}><MainApp /></ThemeContext.Provider>;
}

function Card({ children, style }: { children: React.ReactNode; style?: object }) {
  const { styles } = useNexusTheme();
  return <View style={[styles.card, style]}>{children}</View>;
}
function Label({ children }: { children: React.ReactNode }) {
  const { styles } = useNexusTheme();
  return <Text style={styles.sectionLabel}>{children}</Text>;
}
function Metric({ name, value, amount, color }: { name: string; value: string; amount: number; color: string }) {
  const { styles } = useNexusTheme();
  return <View style={styles.metric}><View style={styles.row}><Text style={styles.body}>{name}</Text><Text style={styles.value}>{value}</Text></View><View style={styles.track}><View style={[styles.fill, { width: `${amount}%`, backgroundColor: color }]} /></View></View>;
}
function Status({ text, color }: { text: string; color?: string }) {
  const { C, styles } = useNexusTheme();
  const statusColor = color ?? C.green;
  return <View style={styles.status}><View style={[styles.dot, { backgroundColor: statusColor }]} /><Text style={[styles.caption, { color: statusColor }]}>{text}</Text></View>;
}

function MainApp() {
  const { C, styles, appearance } = useNexusTheme();
  const [tab, setTab] = useState<Tab>('Dashboard');
  const [selectedDevice, setSelectedDevice] = useState<DeviceName | null>(null);
  const [manageScreen, setManageScreen] = useState<ManageScreen>('overview');
  const [commandRan, setCommandRan] = useState(false);
  const [refreshes, setRefreshes] = useState(0);
  const [minecraftStatus, setMinecraftStatus] = useState<'Running' | 'Stopped'>('Running');
  const [toast, setToast] = useState('');
  const notify = (message: string) => { setToast(message); setTimeout(() => setToast(''), 2200); };
  const openDevice = (name: DeviceName) => { setSelectedDevice(name); setTab('Devices'); };
  const runDemoPower = (action: 'Start' | 'Stop' | 'Restart') => {
    setMinecraftStatus(action === 'Stop' ? 'Stopped' : 'Running');
    notify(`${action} simulated locally · no server command sent`);
  };
  return <SafeAreaView style={styles.safe}>
    <StatusBar style={appearance === 'light' ? 'dark' : 'light'} />
    <View style={styles.top}><View><Text style={styles.brand}>Nexus</Text><Text style={styles.topSubtitle}>PERSONAL INFRASTRUCTURE</Text></View><View style={styles.demoPill}><Text style={styles.demoText}>DEMO</Text></View></View>
    <ScrollView contentContainerStyle={styles.content} key={tab}>
      {tab === 'Dashboard' && <>
        <Text style={styles.title}>Dashboard</Text><Card>
          <View style={styles.brandRow}><Image source={require('./assets/icon.png')} style={styles.logo} /><View><Text style={styles.heading}>Your infrastructure,</Text><Text style={styles.heading}>within reach.</Text></View></View>
          <View style={styles.separator} /><View style={styles.row}><Text style={styles.body}>Saved devices</Text><Text style={styles.value}>2</Text></View><View style={styles.separator} /><View style={styles.row}><Text style={styles.body}>Connected terminals</Text><Text style={styles.value}>0</Text></View>
        </Card>
        <Label>DEVICES · SIMULATED</Label><DeviceCard name="NixOS Workstation" detail="Linux desktop · sample" status="Online" onPress={() => openDevice('NixOS Workstation')} /><DeviceCard name="Debian Homelab Server" detail="Debian 13 · sample" status="Online" onPress={() => openDevice('Debian Homelab Server')} />
        <Label>LAST SAMPLE · NOT LIVE</Label><Card><Metric name="CPU" value="24%" amount={24} color={C.cyan} /><Metric name="Memory" value="9.8 / 16 GB" amount={61} color="#8B83F6" /><Metric name="Storage" value="430 / 1 TB" amount={43} color={C.green} /><View style={styles.separator} /><Text style={styles.caption}>Uptime · 12 days, 4 hours 18 minutes</Text><Text style={styles.caption}>Network · ↓ 18.2 Mbps  ↑ 4.6 Mbps</Text></Card>
        <Text style={styles.disclaimer}>Fictional preview values. No home network connection is made.</Text>
      </>}
      {tab === 'Devices' && (selectedDevice
        ? <DeviceDetails name={selectedDevice} onBack={() => setSelectedDevice(null)} onTerminal={() => { setSelectedDevice(null); setTab('Terminal'); notify('SSH is disabled in the preview'); }} />
        : <><Text style={styles.title}>Devices</Text><Text style={styles.subtitle}>Saved host profiles · example data</Text><DeviceCard name="NixOS Workstation" detail="Linux desktop · sample" status="Online" onPress={() => setSelectedDevice('NixOS Workstation')} /><DeviceCard name="Debian Homelab Server" detail="Debian 13 · Minecraft services" status="Online" onPress={() => setSelectedDevice('Debian Homelab Server')} /><Card><Text style={styles.body}>Security</Text><Text style={styles.caption}>Real Nexus verifies and pins SSH host keys. This prototype does not store credentials or connect to devices.</Text></Card></>)}
      {tab === 'Manage' && (manageScreen === 'overview'
        ? <><Text style={styles.title}>Manage</Text><Text style={styles.subtitle}>Local mock screens · no remote actions</Text><Label>HOST ADMINISTRATION</Label><Tool title="System services" detail="Inspect status and recent logs" icon="⚙" onPress={() => setManageScreen('services')} /><Tool title="Files" detail="Browse and transfer over verified SFTP" icon="▧" onPress={() => setManageScreen('files')} /><Tool title="Network diagnostics" detail="Discovery and saved endpoint checks" icon="⌁" onPress={() => setManageScreen('network')} /><Label>GAME SERVER</Label><Tool title="Minecraft services" detail="Vanilla · SkyFactory · sample state" icon="▤" onPress={() => setManageScreen('minecraft')} /><Label>AUTOMATION</Label><Tool title="Command recipes" detail="Review and confirm sample commands" icon="≡" onPress={() => setManageScreen('recipes')} /><Text style={styles.disclaimer}>Every status and action on these screens is fictional preview data.</Text></>
        : <ManageDetails screen={manageScreen} status={minecraftStatus} onBack={() => setManageScreen('overview')} onPower={runDemoPower} onAction={notify} />)}
      {tab === 'Terminal' && <><Text style={styles.title}>Terminal</Text><Text style={styles.subtitle}>Interactive SSH · not connected</Text><Card style={styles.terminal}><Text style={styles.terminalText}>nexus demo shell  ·  sample only</Text><Text style={styles.terminalText}>demo@workstation:~$ {commandRan ? 'uptime' : ''}</Text>{commandRan && <Text style={styles.terminalText}> 14:18:06 up 12 days, 4:18, 2 users, load average: 0.42, 0.38, 0.31</Text>}<Text style={[styles.terminalText, { color: C.green }]}>$ <Text style={{ color: C.muted }}>Tap the example command below</Text></Text></Card><Pressable style={styles.primary} onPress={() => setCommandRan(true)}><Text style={styles.primaryText}>Run sample uptime command</Text></Pressable><Card><Text style={styles.caption}>This simulates terminal output locally. Production SSH uses strict host-key verification and Keychain credentials.</Text></Card></>}
      {tab === 'Settings' && <><Text style={styles.title}>Settings</Text><Label>PREVIEW PREFERENCES</Label><Tool title="Appearance" detail={`System · ${appearance} mode`} icon="◐" /><Tool title="Terminal text size" detail="12 pt · sample setting" icon="A" /><Tool title="App lock" detail="Production uses Face ID or device passcode" icon="▣" /><Card><Text style={styles.body}>Demo privacy</Text><Text style={styles.caption}>The prototype uses bundled examples only. No credentials, private keys, or real device addresses are included.</Text></Card><Pressable style={styles.action} onPress={() => { setRefreshes(refreshes + 1); notify('Preview refreshed'); }}><Text style={styles.actionText}>Refresh preview · {refreshes}</Text></Pressable></>}
    </ScrollView>
    {toast ? <View style={styles.toast}><Text style={styles.toastText}>{toast}</Text></View> : null}
    <View style={styles.nav}>{tabs.map(item => <Pressable key={item.name} onPress={() => setTab(item.name)} style={styles.navItem}><Text style={[styles.navIcon, tab === item.name && styles.active]}>{item.icon}</Text><Text style={[styles.navLabel, tab === item.name && styles.active]}>{item.name}</Text></Pressable>)}</View>
  </SafeAreaView>;
}

function DeviceCard({ name, detail, status, onPress }: { name: string; detail: string; status: string; onPress: () => void }) {
  const { C, styles } = useNexusTheme();
  return <Pressable onPress={onPress}><Card><View style={styles.row}><View style={styles.deviceIcon}><Text style={{ color: C.cyan, fontSize: 20 }}>▤</Text></View><View style={{ flex: 1 }}><Text style={styles.body}>{name}</Text><Text style={styles.caption}>{detail}</Text></View><Status text={status} /></View></Card></Pressable>;
}
function Tool({ title, detail, icon, onPress }: { title: string; detail: string; icon: string; onPress?: () => void }) {
  const { C, styles } = useNexusTheme();
  return <Pressable onPress={onPress} accessibilityRole="button"><Card style={styles.tool}><Text style={styles.toolIcon}>{icon}</Text><View style={{ flex: 1 }}><Text style={styles.body}>{title}</Text><Text style={styles.caption}>{detail}</Text></View><Text style={{ color: C.muted }}>›</Text></Card></Pressable>;
}

function SubpageHeader({ title, onBack }: { title: string; onBack: () => void }) {
  const { styles } = useNexusTheme();
  return <><Pressable onPress={onBack} accessibilityRole="button" style={styles.back}><Text style={styles.backText}>‹  Back</Text></Pressable><Text style={styles.title}>{title}</Text><Text style={styles.demoNotice}>SIMULATED · NO DEVICE CONNECTION</Text></>;
}

function DeviceDetails({ name, onBack, onTerminal }: { name: DeviceName; onBack: () => void; onTerminal: () => void }) {
  const { C, styles } = useNexusTheme();
  const isNixOS = name === 'NixOS Workstation';
  return <>
    <SubpageHeader title={name} onBack={onBack} />
    <Card><View style={styles.row}><View style={{ flex: 1 }}><Text style={styles.body}>{isNixOS ? 'Linux desktop' : 'Debian 13 homelab server'}</Text><Text style={styles.caption}>Example profile · last sample 2 minutes ago</Text></View><Status text="Online sample" /></View></Card>
    <Label>ENDPOINTS · RESERVED EXAMPLES</Label>
    <Card><Text style={styles.body}>{isNixOS ? '192.0.2.21 · LAN example' : '192.0.2.67 · LAN example'}</Text><Text style={styles.caption}>SSH · port 22 · not a real host</Text><View style={styles.separator} /><Text style={styles.body}>{isNixOS ? 'nixos-demo.example.invalid' : 'debian-demo.example.invalid'}</Text><Text style={styles.caption}>Tailscale-style example · no DNS lookup</Text></Card>
    <Label>LAST SAMPLE · FICTIONAL</Label>
    <Card><Metric name="CPU" value={isNixOS ? '24%' : '18%'} amount={isNixOS ? 24 : 18} color={C.cyan} /><Metric name="Memory" value={isNixOS ? '9.8 / 16 GB' : '5.1 / 16 GB'} amount={isNixOS ? 61 : 32} color="#8B83F6" /><Metric name="Root storage" value={isNixOS ? '430 / 1 TB' : '220 / 512 GB'} amount={isNixOS ? 43 : 43} color={C.green} /></Card>
    <Card><Text style={styles.body}>Authentication</Text><Text style={styles.caption}>Ed25519 key · secrets would be held in iOS Keychain in the real app.</Text></Card>
    <Pressable style={styles.primary} onPress={onTerminal} accessibilityRole="button"><Text style={styles.primaryText}>Open terminal preview</Text></Pressable>
  </>;
}

function ManageDetails({ screen, status, onBack, onPower, onAction }: { screen: Exclude<ManageScreen, 'overview'>; status: 'Running' | 'Stopped'; onBack: () => void; onPower: (action: 'Start' | 'Stop' | 'Restart') => void; onAction: (message: string) => void }) {
  const { C, styles } = useNexusTheme();
  const titles: Record<Exclude<ManageScreen, 'overview'>, string> = { services: 'System services', files: 'Files', network: 'Network diagnostics', minecraft: 'Minecraft services', recipes: 'Command recipes' };
  return <>
    <SubpageHeader title={titles[screen]} onBack={onBack} />
    {screen === 'services' && <>
      <Text style={styles.subtitle}>Debian Homelab Server · sample unit list</Text>
      {['minecraft-vanilla.service', 'minecraft-skyfactory.service', 'ssh.service'].map((unit, index) => <Card key={unit}><View style={styles.row}><View style={{ flex: 1 }}><Text style={styles.body}>{unit}</Text><Text style={styles.caption}>{index < 2 ? 'enabled · loaded · sample' : 'active · system service sample'}</Text></View><Status text={index < 2 ? 'Active' : 'Active'} /></View><Text style={styles.caption}>Recent log · Started successfully · 14:22</Text><View style={styles.buttonRow}>{['Start', 'Stop', 'Restart'].map(action => <Pressable key={action} style={styles.action} onPress={() => onAction(`${action} simulated · no service command sent`)}><Text style={styles.actionText}>{action}</Text></Pressable>)}</View></Card>)}
    </>}
    {screen === 'files' && <>
      <Card><Text style={styles.caption}>/home/demo · sample directory</Text>{['📁 minecraft', '📄 server.properties', '📄 start-server.sh', '📄 README.txt'].map((file, i) => <View key={file} style={[styles.fileRow, i > 0 && styles.fileDivider]}><Text style={styles.body}>{file}</Text><Text style={styles.caption}>{i === 0 ? 'folder' : `${i + 2} KB`}</Text></View>)}</Card>
      <View style={styles.buttonRow}><Pressable style={styles.action} onPress={() => onAction('Sample download complete · local preview only')}><Text style={styles.actionText}>Download sample</Text></Pressable><Pressable style={styles.action} onPress={() => onAction('Upload disabled · preview uses no file access')}><Text style={styles.actionText}>Upload</Text></Pressable></View>
      <Text style={styles.caption}>Production file transfers use pinned SSH/SFTP and ask before replacement.</Text>
    </>}
    {screen === 'network' && <>
      <Card><Text style={styles.body}>Saved endpoint checks</Text><View style={styles.fileRow}><Text style={styles.caption}>nixos-demo.example.invalid</Text><Status text="Example only" color={C.amber} /></View><View style={styles.fileDivider} /><Text style={styles.caption}>TCP · 22 ms sample · host identity not checked by a TCP probe</Text></Card>
      <Card><Text style={styles.body}>SSH discovery</Text><Text style={styles.caption}>No real LAN scan. The native app can search local _ssh._tcp announcements after permission is granted.</Text></Card>
      <Pressable style={styles.action} onPress={() => onAction('Sample lookup refreshed · no DNS request sent')}><Text style={styles.actionText}>Refresh sample</Text></Pressable>
    </>}
    {screen === 'minecraft' && <>
      {['Vanilla', 'SkyFactory'].map(world => <Card key={world}><View style={styles.row}><View style={{ flex: 1 }}><Text style={styles.body}>{world}</Text><Text style={styles.caption}>systemd sample · uptime 12 days</Text></View><Status text={status} color={status === 'Running' ? C.green : C.muted} /></View><Text style={styles.caption}>Players · 2 / 20 sample</Text><View style={styles.buttonRow}>{(['Start', 'Stop', 'Restart'] as const).map(action => <Pressable key={action} style={styles.action} onPress={() => onPower(action)}><Text style={styles.actionText}>{action}</Text></Pressable>)}</View></Card>)}
      <Text style={styles.disclaimer}>Buttons change only this local sample state. The native app opens the existing authenticated panel.</Text>
    </>}
    {screen === 'recipes' && <>
      <Card><Text style={styles.body}>Read host uptime</Text><Text style={styles.caption}>Command preview</Text><Text style={styles.code}>uptime</Text><Text style={styles.caption}>Target · Debian Homelab Server · demo user</Text><Pressable style={styles.primary} onPress={() => onAction('Sample output: up 12 days · no command was executed')}><Text style={styles.primaryText}>Run sample recipe</Text></Pressable></Card>
      <Card><Text style={styles.body}>Disk capacity check</Text><Text style={styles.caption}>Command preview</Text><Text style={styles.code}>df -h /</Text><Text style={styles.caption}>Production recipes require explicit target/command confirmation.</Text></Card>
    </>}
  </>;
}

function createStyles(C: ThemeColors) { return StyleSheet.create({
  safe: { flex: 1, backgroundColor: C.bg }, top: { width: '100%', maxWidth: 820, alignSelf: 'center', paddingHorizontal: nexusTokens.spacing.header, paddingTop: 8, paddingBottom: 14, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', borderBottomWidth: 1, borderBottomColor: C.line },
  brand: { color: C.text, fontSize: 22, fontWeight: '700', letterSpacing: 0.2 }, topSubtitle: { color: C.muted, fontSize: 9, fontWeight: '600', letterSpacing: 1.5, marginTop: 3 }, demoPill: { borderWidth: 1, borderColor: C.demoBorder, backgroundColor: C.demoBg, paddingHorizontal: 11, paddingVertical: 5, borderRadius: nexusTokens.radius.pill }, demoText: { color: C.cyan, fontSize: 10, fontWeight: '700', letterSpacing: 1 },
  content: { width: '100%', maxWidth: 760, alignSelf: 'center', paddingHorizontal: nexusTokens.spacing.screen, paddingTop: 20, paddingBottom: 28, gap: nexusTokens.spacing.standard }, title: { color: C.text, fontSize: nexusTokens.type.screenTitle, fontWeight: '700', marginBottom: 3 }, subtitle: { color: C.muted, fontSize: 14, marginTop: -7, marginBottom: 4 }, sectionLabel: { color: C.muted, fontSize: 11, fontWeight: '700', letterSpacing: 1.15, marginTop: nexusTokens.spacing.standard, marginBottom: 1 },
  card: { backgroundColor: C.card, borderColor: C.cardBorder, borderWidth: 1, borderRadius: nexusTokens.radius.card, padding: nexusTokens.spacing.card, gap: nexusTokens.spacing.standard }, brandRow: { flexDirection: 'row', alignItems: 'center', gap: 13 }, logo: { width: 46, height: 46, borderRadius: 13 }, heading: { color: C.text, fontSize: nexusTokens.type.heading, fontWeight: '600' }, separator: { height: 1, backgroundColor: C.line, marginVertical: 2 }, row: { flexDirection: 'row', alignItems: 'center', gap: nexusTokens.spacing.standard }, body: { color: C.text, fontSize: nexusTokens.type.body, fontWeight: '500' }, value: { color: C.muted, fontSize: 14, fontVariant: ['tabular-nums'] }, caption: { color: C.muted, fontSize: nexusTokens.type.caption, lineHeight: 18 },
  status: { flexDirection: 'row', alignItems: 'center', gap: 6 }, dot: { width: 7, height: 7, borderRadius: 7 }, track: { height: 5, backgroundColor: C.raised, borderRadius: 5, overflow: 'hidden' }, fill: { height: '100%', borderRadius: 5 }, metric: { gap: 8 }, deviceIcon: { width: 38, height: 38, borderRadius: 12, backgroundColor: C.deviceIconBg, alignItems: 'center', justifyContent: 'center' },
  disclaimer: { color: C.muted, fontSize: 11, lineHeight: 16, textAlign: 'center', marginHorizontal: 12 }, buttonRow: { flexDirection: 'row', gap: 8 }, action: { flex: 1, borderWidth: 1, borderColor: C.line, borderRadius: 12, paddingVertical: 11, alignItems: 'center', backgroundColor: C.raised }, actionText: { color: C.text, fontSize: 13, fontWeight: '600' }, tool: { flexDirection: 'row', alignItems: 'center' }, toolIcon: { color: C.cyan, fontSize: 20, width: 28, textAlign: 'center' },
  terminal: { backgroundColor: C.terminalBg, minHeight: 180, justifyContent: 'center' }, terminalText: { color: C.terminalText, fontFamily: 'monospace', fontSize: 12, lineHeight: 20 }, primary: { backgroundColor: C.primaryBg, borderRadius: 13, padding: 14, alignItems: 'center' }, primaryText: { color: 'white', fontWeight: '700', fontSize: 14 },
  nav: { flexDirection: 'row', borderTopWidth: 1, borderColor: C.line, backgroundColor: C.navBg, paddingTop: 8, paddingBottom: 5, justifyContent: 'space-around' }, navItem: { flex: 1, alignItems: 'center', gap: 3 }, navIcon: { color: C.muted, fontSize: 20, height: 23 }, navLabel: { color: C.muted, fontSize: 9, fontWeight: '500' }, active: { color: C.cyan, fontWeight: '700' }, toast: { position: 'absolute', bottom: 84, alignSelf: 'center', backgroundColor: C.raised, borderColor: C.line, borderWidth: 1, borderRadius: 12, paddingHorizontal: 16, paddingVertical: 10 }, toastText: { color: C.text, fontSize: 12 }, back: { alignSelf: 'flex-start', minHeight: 36, justifyContent: 'center', paddingRight: 12 }, backText: { color: C.cyan, fontSize: 15, fontWeight: '600' }, demoNotice: { color: C.amber, fontSize: 10, fontWeight: '700', letterSpacing: 1.1, marginTop: -8 }, fileRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: 10, paddingVertical: 9 }, fileDivider: { height: 1, backgroundColor: C.line }, code: { color: C.cyan, backgroundColor: C.codeBg, borderRadius: 10, padding: 12, overflow: 'hidden', fontFamily: 'monospace', fontSize: 14 },
}); }
