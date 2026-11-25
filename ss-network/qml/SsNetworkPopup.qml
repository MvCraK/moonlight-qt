// SS-NETWORK extension: compact desktop popover anchored under the toolbar button.
// Opaque hard-shadow panel in the app's neo-brutalist style: header + switch,
// optional VPN/TUN coexistence banner, home route selector, active nodes, stats, actions.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts 1.3
import Qt.labs.platform 1.1 as Platform
import SsNetwork 1.0
import "qrc:/gui/theme"

Popup {
    id: popup

    property var tr
    property color onlineColor
    property color warningColor
    property color stateColor
    property string stateText

    readonly property int panelWidth: Math.min(440, (Overlay.overlay ? Overlay.overlay.width : 800) - Theme.spaceLg * 2)

    // Right-align under the button, clamped inside the window by the margins.
    x: parent ? parent.width - width + Theme.shadowOffset : 0
    y: parent ? parent.height + Theme.spaceXs : 0
    width: panelWidth + Theme.shadowOffset
    margins: Theme.spaceSm
    padding: 0
    focus: true
    modal: false
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutsideParent

    onOpened: {
        SsNetwork.refreshNetworkState()
        SsNetwork.probe(false)
        connectButton.forceActiveFocus(Qt.TabFocusReason)
    }

    enter: Transition {
        NumberAnimation { property: "opacity"; from: 0; to: 1; duration: Theme.durFast; easing.type: Theme.easing }
        NumberAnimation { property: "y"; from: popup.y - 6; to: popup.y; duration: Theme.durFast; easing.type: Theme.easing }
    }
    exit: Transition {
        NumberAnimation { property: "opacity"; from: 1; to: 0; duration: Theme.durFast; easing.type: Theme.easing }
    }

    background: Item {}

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + " B"
        var units = ["KB", "MB", "GB", "TB"]
        var value = bytes / 1024
        var i = 0
        while (value >= 1024 && i < units.length - 1) { value /= 1024; i++ }
        return value.toFixed(value >= 100 ? 0 : 1) + " " + units[i]
    }

    function latencyText(node) {
        if (!SsNetwork.enabled) return tr.idle
        if (node.latency === -2) return tr.udpOnly
        if (node.latency === -3) return SsNetwork.probing ? tr.probing : tr.idle
        if (node.latency < 0) return SsNetwork.probing ? tr.probing : tr.unreachable
        return node.latency + " ms"
    }

    function latencyColor(node) {
        if (!SsNetwork.enabled || node.latency === -2 || node.latency === -3) return Theme.textFaint
        if (node.latency < 0) return SsNetwork.probing ? Theme.textFaint : warningColor
        return onlineColor
    }

    function nodeName(role) {
        if (role === "homeTcp") return tr.homeTcp
        if (role === "homeUdp") return tr.homeUdp
        if (role === "homeRelay") return tr.homeRelay
        if (role === "homeRelayTcp") return tr.homeRelayTcp
        if (role === "homeRelayUdp") return tr.homeRelayUdp
        return tr.company
    }

    function formatError() {
        var code = SsNetwork.errorCode || "errGeneric"
        var msg = tr[code] || tr.errGeneric
        if (SsNetwork.errorArg && msg.indexOf("%1") >= 0) {
            msg = msg.arg(SsNetwork.errorArg)
        }
        if (SsNetwork.warning && SsNetwork.warningPrefix && tr[SsNetwork.warningPrefix]) {
            return tr[SsNetwork.warningPrefix].arg(msg)
        }
        return msg
    }

    function vpnBannerText() {
        if (!SsNetwork.enabled) return tr.vpnBannerOff
        if (SsNetwork.hasBypassInterface) return tr.vpnBannerBypass.arg(SsNetwork.bypassInterfaceLabel)
        return tr.vpnBannerNoBypass
    }

    contentItem: Panel {
        id: panel
        implicitWidth: popup.panelWidth
        implicitHeight: body.implicitHeight + Theme.spaceLg * 2
        width: popup.panelWidth
        height: implicitHeight
        fill: Theme.surface
        borderColor: Theme.lineStrong
        accentBarColor: popup.stateColor
        accentBarWidth: Theme.accentBarStrong

        ColumnLayout {
            id: body
            anchors.fill: parent
            anchors.margins: Theme.spaceLg
            spacing: Theme.spaceMd

            // ---- Header: title, live state, connect switch ----
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceMd

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2

                    MicroLabel {
                        text: tr.label
                    }

                    Text {
                        text: tr.title
                        color: Theme.text
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontHeroTitle
                        font.bold: true
                    }

                    Text {
                        Layout.fillWidth: true
                        text: popup.stateText
                        color: SsNetwork.enabled ? popup.stateColor : Theme.textDim
                        font.family: Theme.fontSans
                        font.pointSize: Theme.fontBody + 1
                        font.bold: true
                        elide: Text.ElideRight
                    }
                }

                HardButton {
                    id: connectButton
                    Layout.preferredWidth: 126
                    Layout.preferredHeight: 38
                    primary: !SsNetwork.enabled
                    enabled: SsNetwork.available && SsNetwork.configured && !SsNetwork.busy
                    text: SsNetwork.busyAction === "toggle" ? tr.connecting
                          : (SsNetwork.enabled ? tr.disconnect : tr.connect)
                    onClicked: SsNetwork.toggle()
                    KeyNavigation.tab: importButton
                }
            }

            // ---- System VPN / TUN coexistence notice ----
            Rectangle {
                Layout.fillWidth: true
                visible: SsNetwork.systemVpnActive
                implicitHeight: vpnLabel.implicitHeight + Theme.spaceSm * 2
                color: (SsNetwork.enabled && !SsNetwork.hasBypassInterface) ? "#2B2214" : Theme.ink
                border.width: 1
                border.color: (SsNetwork.enabled && !SsNetwork.hasBypassInterface) ? warningColor : Theme.lineStrong

                Text {
                    id: vpnLabel
                    anchors.fill: parent
                    anchors.margins: Theme.spaceSm
                    text: popup.vpnBannerText()
                    color: (SsNetwork.enabled && !SsNetwork.hasBypassInterface) ? warningColor : Theme.textDim
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontCaption + 1
                    wrapMode: Text.WordWrap
                    lineHeight: 1.25
                }
            }

            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 1
                color: Theme.line
            }

            // ---- Empty state ----
            ColumnLayout {
                Layout.fillWidth: true
                visible: !SsNetwork.configured
                spacing: Theme.spaceSm

                Text {
                    text: tr.emptyTitle
                    color: Theme.text
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontCardTitle
                    font.bold: true
                }
                Text {
                    Layout.fillWidth: true
                    text: tr.emptyBody
                    color: Theme.textDim
                    font.family: Theme.fontSans
                    font.pointSize: Theme.fontBody + 1
                    wrapMode: Text.WordWrap
                    lineHeight: 1.25
                }
            }

            // ---- Home route selector (Direct vs Company Relay) ----
            ColumnLayout {
                Layout.fillWidth: true
                visible: SsNetwork.configured
                spacing: Theme.spaceXs

                MicroLabel { text: tr.homeModeTitle }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spaceSm

                    // Direct (subscriptions)
                    Rectangle {
                        id: directBtn
                        readonly property bool selected: SsNetwork.homeMode === "direct"
                        readonly property bool usable: (SsNetwork.hasDirect || SsNetwork.hasDirectConfig) && !SsNetwork.busy
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        implicitHeight: 48
                        color: selected ? Theme.accentSoft : (directHover.hovered && usable ? Theme.surface2 : Theme.ink)
                        border.width: selected ? 2 : 1
                        border.color: selected ? Theme.accent : (directHover.hovered && usable ? Theme.lineStrong : Theme.line)
                        opacity: usable ? 1.0 : 0.45

                        HoverHandler { id: directHover }
                        MouseArea {
                            anchors.fill: parent
                            enabled: directBtn.usable
                            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                            onClicked: SsNetwork.setHomeMode("direct")
                        }

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.spaceSm
                            anchors.rightMargin: Theme.spaceSm
                            anchors.topMargin: 6
                            anchors.bottomMargin: 6
                            spacing: 1

                            Text {
                                Layout.fillWidth: true
                                text: tr.modeDirect
                                color: directBtn.selected ? Theme.accentStrong : Theme.text
                                font.family: Theme.fontSans
                                font.pointSize: Theme.fontRowTitle
                                font.bold: true
                                elide: Text.ElideRight
                            }
                            Text {
                                Layout.fillWidth: true
                                text: (SsNetwork.hasDirect || SsNetwork.hasDirectConfig) ? tr.modeDirectSub : tr.modeUnconfigured
                                color: Theme.textFaint
                                font.family: Theme.fontSans
                                font.pointSize: Theme.fontCaption
                                elide: Text.ElideRight
                            }
                        }
                    }

                    // Company relay (fixed)
                    Rectangle {
                        id: relayBtn
                        readonly property bool selected: SsNetwork.homeMode === "relay"
                        readonly property bool usable: SsNetwork.hasRelay && !SsNetwork.busy
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        implicitHeight: 48
                        color: selected ? Theme.accentSoft : (relayHover.hovered && usable ? Theme.surface2 : Theme.ink)
                        border.width: selected ? 2 : 1
                        border.color: selected ? Theme.accent : (relayHover.hovered && usable ? Theme.lineStrong : Theme.line)
                        opacity: usable ? 1.0 : 0.45

                        HoverHandler { id: relayHover }
                        MouseArea {
                            anchors.fill: parent
                            enabled: relayBtn.usable
                            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                            onClicked: SsNetwork.setHomeMode("relay")
                        }

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.spaceSm
                            anchors.rightMargin: Theme.spaceSm
                            anchors.topMargin: 6
                            anchors.bottomMargin: 6
                            spacing: 1

                            Text {
                                Layout.fillWidth: true
                                text: tr.modeRelay
                                color: relayBtn.selected ? Theme.accentStrong : Theme.text
                                font.family: Theme.fontSans
                                font.pointSize: Theme.fontRowTitle
                                font.bold: true
                                elide: Text.ElideRight
                            }
                            Text {
                                Layout.fillWidth: true
                                text: SsNetwork.hasRelay ? tr.modeRelaySub : tr.modeUnconfigured
                                color: Theme.textFaint
                                font.family: Theme.fontSans
                                font.pointSize: Theme.fontCaption
                                elide: Text.ElideRight
                            }
                        }
                    }
                }
            }

            // ---- Active nodes ----
            ColumnLayout {
                Layout.fillWidth: true
                visible: SsNetwork.configured
                spacing: Theme.spaceXs

                MicroLabel { text: tr.nodes }

                Repeater {
                    model: SsNetwork.nodes

                    delegate: Rectangle {
                        id: nodeRow
                        required property var modelData
                        Layout.fillWidth: true
                        implicitHeight: 44
                        color: rowHover.hovered ? Theme.surface2 : Theme.ink
                        border.width: 1
                        border.color: rowHover.hovered ? Theme.lineStrong : Theme.line

                        HoverHandler { id: rowHover }

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.spaceMd
                            anchors.rightMargin: Theme.spaceMd
                            spacing: Theme.spaceSm

                            Rectangle {
                                implicitWidth: 8
                                implicitHeight: 8
                                color: popup.latencyColor(nodeRow.modelData)
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 1
                                Text {
                                    Layout.fillWidth: true
                                    text: popup.nodeName(nodeRow.modelData.role)
                                    color: Theme.text
                                    font.family: Theme.fontSans
                                    font.pointSize: Theme.fontRowTitle
                                    font.bold: true
                                    elide: Text.ElideRight
                                }
                                Text {
                                    Layout.fillWidth: true
                                    text: nodeRow.modelData.host + ":" + nodeRow.modelData.port
                                    color: Theme.textFaint
                                    font.family: Theme.fontMono
                                    font.pointSize: Theme.fontCaption
                                    elide: Text.ElideMiddle
                                }
                            }

                            Text {
                                text: popup.latencyText(nodeRow.modelData)
                                color: popup.latencyColor(nodeRow.modelData)
                                font.family: Theme.fontMono
                                font.pointSize: Theme.fontBody
                                font.bold: true
                            }
                        }
                    }
                }
            }

            // ---- Compact 1-row stats strip ----
            RowLayout {
                Layout.fillWidth: true
                visible: SsNetwork.configured
                spacing: Theme.spaceMd

                Text {
                    text: tr.received + " " + popup.formatBytes(SsNetwork.receivedBytes)
                    color: Theme.textDim
                    font.family: Theme.fontMono
                    font.pointSize: Theme.fontCaption + 1
                }
                Item { Layout.fillWidth: true }
                Text {
                    visible: SsNetwork.hasDirectConfig || SsNetwork.updated > 0
                    text: tr.updated + " " + (SsNetwork.updated > 0
                          ? Qt.formatDateTime(new Date(SsNetwork.updated), "MM-dd HH:mm") : tr.never)
                    color: Theme.textDim
                    font.family: Theme.fontMono
                    font.pointSize: Theme.fontCaption + 1
                }
            }

            // ---- Busy / Warning / Error banner ----
            Text {
                Layout.fillWidth: true
                visible: SsNetwork.busyAction === "import" || SsNetwork.busyAction === "refresh" || SsNetwork.failed || SsNetwork.warning
                text: SsNetwork.busyAction === "import" ? tr.busyImport
                      : (SsNetwork.busyAction === "refresh" ? tr.busyRefresh : popup.formatError())
                color: SsNetwork.failed ? Theme.danger : (SsNetwork.warning ? warningColor : Theme.textDim)
                font.family: Theme.fontSans
                font.pointSize: Theme.fontBody
                wrapMode: Text.WordWrap
                lineHeight: 1.25
            }

            // ---- Actions ----
            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: Theme.spaceXs
                spacing: Theme.spaceSm

                HardButton {
                    id: importButton
                    text: tr.importConfig
                    primary: !SsNetwork.configured
                    enabled: SsNetwork.available && !SsNetwork.busy
                    onClicked: fileDialog.open()
                    KeyNavigation.tab: refreshButton.visible ? refreshButton : connectButton
                }
                HardButton {
                    id: refreshButton
                    visible: SsNetwork.configured && SsNetwork.hasDirectConfig
                    text: tr.refresh
                    enabled: !SsNetwork.busy
                    onClicked: SsNetwork.refresh()
                    KeyNavigation.tab: probeButton
                }
                HardButton {
                    id: probeButton
                    visible: SsNetwork.configured
                    text: tr.probe
                    enabled: SsNetwork.enabled && !SsNetwork.probing
                    onClicked: SsNetwork.probe(true)
                    KeyNavigation.tab: connectButton
                }
                Item { Layout.fillWidth: true }
                MicroLabel {
                    text: tr.escHint
                    color: Theme.textFaint
                }
            }
        }
    }

    Platform.FileDialog {
        id: fileDialog
        title: tr.fileTitle
        nameFilters: [tr.fileFilter, tr.allFiles]
        onAccepted: SsNetwork.importConfig(file)
    }
}
