# SS-NETWORK extension (see ss-network/README.md).
# Included by app/app.pro. Builds the Rust core with cargo, links it, and adds
# the Qt/QML side. On other platforms only the QML/C++ stubs are compiled and
# the toolbar entry stays hidden.
INCLUDEPATH += $$PWD/qt
HEADERS += $$PWD/qt/ssnetwork.h
SOURCES += $$PWD/qt/ssnetwork.cpp
RESOURCES += $$PWD/qml/ss-network.qrc

win32|macx {
    !config_SL {
        DEFINES += SS_NETWORK_ENABLED
        SS_RUST_DIR = $$PWD/rust
        SS_CARGO_DIR = $$OUT_PWD/ss-network-cargo

        win32 {
            contains(QT_ARCH, arm64): SS_TRIPLES = aarch64-pc-windows-msvc
            else: SS_TRIPLES = x86_64-pc-windows-msvc
            SS_LIB = $$SS_CARGO_DIR/$$first(SS_TRIPLES)/release/ss_network.lib
            # Rust std/tokio system dependencies for a static MSVC library.
            LIBS += ws2_32.lib userenv.lib ntdll.lib advapi32.lib bcrypt.lib kernel32.lib synchronization.lib
        }
        macx {
            SS_ARCHS = $$QMAKE_APPLE_DEVICE_ARCHS
            isEmpty(SS_ARCHS): SS_ARCHS = $$QT_ARCH
            SS_TRIPLES =
            for (arch, SS_ARCHS) {
                equals(arch, arm64): SS_TRIPLES += aarch64-apple-darwin
                else: SS_TRIPLES += x86_64-apple-darwin
            }
            SS_LIB = $$SS_CARGO_DIR/libss_network.a
            LIBS += -framework Security -framework CoreFoundation
        }

        ss_rust.target = $$SS_LIB
        ss_rust.depends = FORCE
        ss_rust.commands =
        SS_PARTS =
        for (triple, SS_TRIPLES) {
            # rustup is optional; a failure here just means the target is already present.
            ss_rust.commands += -rustup target add $$triple $$escape_expand(\\n\\t)
            macx: ss_rust.commands += MACOSX_DEPLOYMENT_TARGET=$$QMAKE_MACOSX_DEPLOYMENT_TARGET
            ss_rust.commands += cargo build --release --locked \
                --manifest-path $$shell_quote($$system_path($$SS_RUST_DIR/Cargo.toml)) \
                --target $$triple --target-dir $$shell_quote($$system_path($$SS_CARGO_DIR)) \
                $$escape_expand(\\n\\t)
            SS_PARTS += $$shell_quote($$SS_CARGO_DIR/$$triple/release/libss_network.a)
        }
        macx: ss_rust.commands += lipo -create $$SS_PARTS -output $$shell_quote($$SS_LIB)
        QMAKE_EXTRA_TARGETS += ss_rust
        PRE_TARGETDEPS += $$SS_LIB
        LIBS += $$shell_quote($$SS_LIB)
    }
}
