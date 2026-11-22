@echo off
rem SS-NETWORK extension: builds the Rust core for one MSVC target.
rem build-arch.bat exports CFLAGS=/GL and nmake passes the app's own CFLAGS down;
rem cc-rs would compile ring's C code with them (LTCG objects, shared .pdb),
rem which a Rust static library cannot use. Clear them for this step only.
set CFLAGS=
set CXXFLAGS=
rustup target add %1 >nul 2>nul
cargo build --release --locked --manifest-path "%~dp0Cargo.toml" --target %1 --target-dir %2
exit /b %ERRORLEVEL%
