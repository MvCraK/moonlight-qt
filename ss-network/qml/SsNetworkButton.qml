// SS-NETWORK extension: toolbar entry. Loaded by a single Loader in main.qml.
import QtQuick
import QtQuick.Controls
import StreamingPreferences 1.0
import SsNetwork 1.0
import "qrc:/gui"
import "qrc:/gui/theme"
import "SsStrings.js" as Strings

NavigableToolButton {
    id: button

    readonly property bool zh: StreamingPreferences.language === StreamingPreferences.LANG_ZH_CN ||
                               StreamingPreferences.language === StreamingPreferences.LANG_ZH_TW ||
                               (StreamingPreferences.language === StreamingPreferences.LANG_AUTO &&
                                Qt.locale().name.indexOf("zh") === 0)
    readonly property var tr: Strings.table(zh)

    // Grey = off, lime = connected, amber = a node is unreachable.
    readonly property color onlineColor: Theme.acid
    readonly property color warningColor: "#FFB547"
    readonly property color stateColor: SsNetwork.status === SsNetwork.Degraded ? warningColor
                                       : (SsNetwork.enabled ? onlineColor : Theme.textFaint)
    readonly property string stateText: !SsNetwork.available ? tr.unavailable
                                        : (!SsNetwork.configured ? tr.unconfigured
                                        : (SsNetwork.status === SsNetwork.Checking ? tr.checking
                                        : (SsNetwork.status === SsNetwork.Online ? tr.online
                                        : (SsNetwork.status === SsNetwork.Degraded ? tr.degraded : tr.off))))

    // Read by the Loader in main.qml (Item.visible would depend on the Loader's own visibility).
    readonly property bool shown: SsNetwork.available
    iconSource: "qrc:/ss-network/ss-network.svg"
    icon.color: SsNetwork.enabled ? stateColor
                                  : ((hovered || visualFocus || down || popup.opened) ? Theme.text : Theme.textDim)

    Accessible.name: tr.tooltip.arg(stateText)
    ToolTip.delay: 600
    ToolTip.timeout: 4000
    ToolTip.visible: hovered && !popup.opened
    ToolTip.text: tr.tooltip.arg(stateText)

    onClicked: popup.opened ? popup.close() : popup.open()

    // Square status pip in the icon's corner, like a hardware LED.
    Rectangle {
        visible: SsNetwork.enabled
        width: 8
        height: 8
        x: button.width / 2 + 6
        y: button.height / 2 - 12
        color: button.stateColor
        border.width: 2
        border.color: Theme.ink
        Behavior on color { ColorAnimation { duration: Theme.durFast } }
    }

    // Keeps the pressed look while the panel is open.
    background: Rectangle {
        color: button.down || popup.opened ? Theme.accentSoft
                                           : (button.hovered ? Theme.surface2 : "transparent")
        border.width: button.visualFocus ? 2 : (button.hovered || popup.opened ? 1 : 0)
        border.color: Theme.accent
        Behavior on color { ColorAnimation { duration: Theme.durFast } }
    }

    SsNetworkPopup {
        id: popup
        tr: button.tr
        onlineColor: button.onlineColor
        warningColor: button.warningColor
        stateColor: button.stateColor
        stateText: button.stateText
    }
}
