// SS-NETWORK extension: self-contained bilingual strings, so upstream .ts files stay untouched.
.pragma library

var zh = {
    title: "SS 组网", label: "SS NETWORK",
    unavailable: "当前平台不支持", off: "未开启", checking: "已开启 · 正在检测节点…",
    online: "已连接 · 节点可达", degraded: "已开启 · 部分节点不可达", unconfigured: "尚未导入配置",
    chipOff: "OFF", chipOn: "ONLINE", chipChecking: "CHECKING", chipDegraded: "DEGRADED",
    connect: "开启组网", disconnect: "断开组网", connecting: "正在切换…",
    nodes: "节点", routes: "分流", stats: "状态",
    homeTcp: "家庭 · TCP", homeUdp: "家庭 · UDP 串流", company: "公司 · TCP/UDP",
    udpOnly: "仅 UDP", unreachable: "不可达", probing: "检测中…", idle: "—",
    home: "家庭", companyRoute: "公司",
    homeDetail: "TCP 走家庭 TCP 节点 · UDP 走家庭 UDP 节点", companyDetail: "TCP、UDP 均走公司节点",
    received: "直连接收", updated: "订阅更新", never: "—",
    directNote: "串流 UDP 在收包线程内直接解密，不经过本地中继。程序退出后组网自动关闭。",
    importConfig: "导入配置…", refresh: "更新订阅", probe: "检测节点",
    emptyTitle: "尚未导入组网配置",
    emptyBody: "导入包含家庭 TCP/UDP 订阅和公司节点的 JSON 配置后，10.0.0.0/24 与 10.1.1.0/24 将经 SS 访问。",
    busyImport: "正在读取配置并更新订阅…", busyRefresh: "正在更新两个家庭订阅…",
    error: "操作失败，请检查配置文件、订阅和网络。",
    fileTitle: "选择 SS 组网配置", fileFilter: "JSON 配置 (*.json)", allFiles: "所有文件 (*)",
    tooltip: "SS 组网：%1", escHint: "Esc 关闭"
}

var en = {
    title: "SS network", label: "SS NETWORK",
    unavailable: "Not available on this platform", off: "Off", checking: "On · checking nodes…",
    online: "Connected · nodes reachable", degraded: "On · some nodes unreachable", unconfigured: "Not configured",
    chipOff: "OFF", chipOn: "ONLINE", chipChecking: "CHECKING", chipDegraded: "DEGRADED",
    connect: "Connect", disconnect: "Disconnect", connecting: "Switching…",
    nodes: "Nodes", routes: "Routes", stats: "Status",
    homeTcp: "Home · TCP", homeUdp: "Home · UDP stream", company: "Company · TCP/UDP",
    udpOnly: "UDP only", unreachable: "Unreachable", probing: "Checking…", idle: "—",
    home: "Home", companyRoute: "Company",
    homeDetail: "TCP via home TCP node · UDP via home UDP node", companyDetail: "TCP and UDP via company node",
    received: "Direct received", updated: "Subscriptions", never: "—",
    directNote: "Stream UDP is decrypted in the receive thread with no local relay. The connection turns off when the app exits.",
    importConfig: "Import…", refresh: "Update", probe: "Test nodes",
    emptyTitle: "No network config yet",
    emptyBody: "Import a JSON config with the home TCP/UDP subscriptions and the company node to route 10.0.0.0/24 and 10.1.1.0/24 through SS.",
    busyImport: "Reading config and updating subscriptions…", busyRefresh: "Updating both home subscriptions…",
    error: "Operation failed. Check the config file, subscriptions and network.",
    fileTitle: "Choose SS network config", fileFilter: "JSON config (*.json)", allFiles: "All files (*)",
    tooltip: "SS network: %1", escHint: "Esc to close"
}

function table(isZh) { return isZh ? zh : en }
