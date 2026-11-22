// SS-NETWORK extension: desktop popover anchored under the toolbar button.
// Opaque hard-shadow panel in the app's neo-brutalist style; the connect switch
// sits in the header, nodes and routes share two columns, actions at the bottom.
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

    readonly property bool wide: (Overlay.overlay ? Overlay.overlay.width : 800) >= 640
    readonly property int panelWidth: wide ? 560 : 340

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
        return role === "homeTcp" ? tr.homeTcp : (role === "homeUdp" ? tr.homeUdp : tr.company)
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
                    Layout.preferredWidth: 132
                    Layout.preferredHeight: 38
                    primary: !SsNetwork.enabled
                    enabled: SsNetwork.available && SsNetwork.configured && !SsNetwork.busy
                    text: SsNetwork.busyAction === "toggle" ? tr.connecting
                          : (SsNetwork.enabled ? tr.disconnect : tr.connect)
                    onClicked: SsNetwork.toggle()
                    KeyNavigation.tab: importButton
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

            // ---- Nodes | routes + stats ----
            GridLayout {
                Layout.fillWidth: true
                visible: SsNetwork.configured
                columns: popup.wide ? 2 : 1
                columnSpacing: Theme.spaceLg
                rowSpacing: Theme.spaceMd

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignTop
                    Layout.preferredWidth: 1
                    spacing: Theme.spaceSm

                    MicroLabel { text: tr.nodes }

                    Repeater {
                        model: SsNetwork.nodes

                        delegate: Rectangle {
                            id: nodeRow
                            required property var modelData
                            Layout.fillWidth: true
                            implicitHeight: 46
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

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignTop
                    Layout.preferredWidth: 1
                    spacing: Theme.spaceSm

                    MicroLabel { text: tr.routes }

                    Repeater {
                        model: [
                            { cidr: "10.0.0.0/24", target: tr.home, detail: tr.homeDetail },
                            { cidr: "10.1.1.0/24", target: tr.companyRoute, detail: tr.companyDetail }
                        ]
                        delegate: ColumnLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            spacing: 2
                            RowLayout {
                                Layout.fillWidth: true
                                Text {
                                    Layout.fillWidth: true
                                    text: modelData.cidr
                                    color: Theme.text
                                    font.family: Theme.fontMono
                                    font.pointSize: Theme.fontRowTitle
                                    font.bold: true
                                }
                                Text {
                                    text: "→ " + modelData.target
                                    color: Theme.accentStrong
                                    font.family: Theme.fontSans
                                    font.pointSize: Theme.fontBody
                                    font.bold: true
                                }
                            }
                            Text {
                                Layout.fillWidth: true
                                text: modelData.detail
                                color: Theme.textDim
                                font.family: Theme.fontSans
                                font.pointSize: Theme.fontCaption + 1
                                wrapMode: Text.WordWrap
                            }
                        }
                    }

                    MicroLabel {
                        Layout.topMargin: Theme.spaceXs
                        text: tr.stats
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        columnSpacing: Theme.spaceSm
                        rowSpacing: 2

                        Text {
                            text: tr.received
                            color: Theme.textDim
                            font.family: Theme.fontSans
                            font.pointSize: Theme.fontBody
                        }
                        Text {
                            Layout.fillWidth: true
                            horizontalAlignment: Text.AlignRight
                            text: popup.formatBytes(SsNetwork.receivedBytes)
                            color: Theme.text
                            font.family: Theme.fontMono
                            font.pointSize: Theme.fontBody
                            font.bold: true
                        }
                        Text {
                            text: tr.updated
                            color: Theme.textDim
                            font.family: Theme.fontSans
                            font.pointSize: Theme.fontBody
                        }
                        Text {
                            Layout.fillWidth: true
                            horizontalAlignment: Text.AlignRight
                            text: SsNetwork.updated > 0
                                  ? Qt.formatDateTime(new Date(SsNetwork.updated), "MM-dd HH:mm") : tr.never
                            color: Theme.text
                            font.family: Theme.fontMono
                            font.pointSize: Theme.fontBody
                            font.bold: true
                        }
                    }
                }
            }

            Text {
                Layout.fillWidth: true
                visible: SsNetwork.configured
                text: tr.directNote
                color: Theme.textFaint
                font.family: Theme.fontSans
                font.pointSize: Theme.fontCaption + 1
                wrapMode: Text.WordWrap
            }

            Text {
                Layout.fillWidth: true
                visible: SsNetwork.busyAction === "import" || SsNetwork.busyAction === "refresh" || SsNetwork.failed
                text: SsNetwork.busyAction === "import" ? tr.busyImport
                      : (SsNetwork.busyAction === "refresh" ? tr.busyRefresh : tr.error)
                color: SsNetwork.failed ? Theme.danger : Theme.textDim
                font.family: Theme.fontSans
                font.pointSize: Theme.fontBody + 1
                wrapMode: Text.WordWrap
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
                    visible: SsNetwork.configured
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
