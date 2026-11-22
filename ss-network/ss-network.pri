# SS-NETWORK extension (see ss-network/README.md).
# Included by app/app.pro. Builds the Rust core with cargo, links it, and adds
# the Qt/QML side. On other platforms only the QML/C++ stubs are compiled and
# the toolbar entry stays hidden.
INCLUDEPATH += $$PWD/qt
HEADERS += $$PWD/qt/ssnetwork.h

config_SL {
    # Steam Link builds against Qt 5.14: header-only stub, no toolbar entry.
    DEFINES += SS_NETWORK_STUB
} else {
    SOURCES += $$PWD/qt/ssnetwork.cpp
    RESOURCES += $$PWD/qml/ss-network.qrc
}

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
            # The app links with -guard:ehcont, but Rust's precompiled std and ring's
            # assembly carry no EH-continuation metadata (stable Rust cannot emit it).
            # The core is built with panic=abort, so no exception ever unwinds through
            # those frames; let the linker accept them.
            QMAKE_LFLAGS += /force:guardehcont
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
            win32 {
                # Clears the MSVC CFLAGS that would leak into ring's C build (see the script).
                ss_rust.commands += $$shell_quote($$system_path($$SS_RUST_DIR/cargo-build.cmd)) $$triple \
                    $$shell_quote($$system_path($$SS_CARGO_DIR)) $$escape_expand(\\n\\t)
            } else {
                # rustup is optional; a failure here just means the target is already present.
                ss_rust.commands += -rustup target add $$triple $$escape_expand(\\n\\t)
                ss_rust.commands += env -u CFLAGS -u CXXFLAGS MACOSX_DEPLOYMENT_TARGET=$$QMAKE_MACOSX_DEPLOYMENT_TARGET \
                    cargo build --release --locked \
                    --manifest-path $$shell_quote($$SS_RUST_DIR/Cargo.toml) \
                    --target $$triple --target-dir $$shell_quote($$SS_CARGO_DIR) $$escape_expand(\\n\\t)
            }
            SS_PARTS += $$shell_quote($$SS_CARGO_DIR/$$triple/release/libss_network.a)
        }
        macx: ss_rust.commands += lipo -create $$SS_PARTS -output $$shell_quote($$SS_LIB)
        QMAKE_EXTRA_TARGETS += ss_rust
        PRE_TARGETDEPS += $$SS_LIB
        LIBS += $$shell_quote($$SS_LIB)
    }
}
