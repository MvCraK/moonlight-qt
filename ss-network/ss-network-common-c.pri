# SS-NETWORK extension (see ss-network/README.md).
# Included by moonlight-common-c.pro: compiles the socket shim and force-includes
# its redirects into every common-c translation unit (Windows and macOS only).
win32|macx {
    !config_SL {
        INCLUDEPATH += $$PWD/shim
        HEADERS += $$PWD/shim/ss_shim.h
        SOURCES += $$PWD/shim/ss_shim.c
        contains(QMAKE_COMPILER, msvc) {
            QMAKE_CFLAGS += /FI$$shell_quote($$system_path($$PWD/shim/ss_shim.h))
        } else {
            QMAKE_CFLAGS += -include $$shell_quote($$PWD/shim/ss_shim.h)
        }
    }
}
