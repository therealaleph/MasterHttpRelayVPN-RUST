@echo off
REM mhrv-rs launcher for Windows.
REM Runs the CLI once to initialize the MITM CA (may trigger a UAC prompt when
REM installing into the Windows trust store), then launches the UI.

setlocal
cd /d "%~dp0"

if not exist "mhrv-rs.exe" (
    echo error: mhrv-rs.exe not found next to this script.
    pause
    exit /b 1
)

echo Initializing MITM CA (a UAC prompt may appear)...
mhrv-rs.exe --install-cert
if errorlevel 1 (
    echo warning: CA install returned non-zero. The UI can still run,
    echo but HTTPS sites may show certificate warnings until the CA is trusted.
)

if not exist "mhrv-rs-ui.exe" (
    echo UI binary not found. Running CLI proxy instead.
    mhrv-rs.exe
    goto :eof
)

echo.
echo Starting mhrv-rs UI...
echo (A new window should open. If nothing appears, the UI crashed — the
echo  error is shown in this terminal below. Take a screenshot of it and
echo  open an issue on github.)
echo.

REM Run in-place (not via `start`) so if the UI dies on launch, its stderr
REM and non-zero exit code are visible in this window. Previously we used
REM `start "" "mhrv-rs-ui.exe"` which returns immediately and swallows any
REM launch-time crash (issue #7).
mhrv-rs-ui.exe
set UI_EXIT=%ERRORLEVEL%
if not "%UI_EXIT%"=="0" (
    echo.
    echo ---------------------------------------------------
    echo UI exited with error code %UI_EXIT%.
    echo.
    echo If this is the first time and you saw "egui_glow requires opengl 2.0+"
    echo or "PainterError" above, your machine doesn't have a usable OpenGL
    echo driver. Retrying once with the DirectX/Vulkan backend...
    echo.
    set MHRV_RENDERER=wgpu
    "%~dp0mhrv-rs-ui.exe"
    set UI_EXIT=%ERRORLEVEL%
    set MHRV_RENDERER=
    if not "%UI_EXIT%"=="0" (
        echo.
        echo ---------------------------------------------------
        echo UI still failed with error code %UI_EXIT% even with the DX/Vulkan
        echo backend. Likely causes:
        echo   - missing or outdated graphics drivers (try updating)
        echo   - running inside RDP or a VM without GPU acceleration
        echo   - antivirus blocking the exe — whitelist the folder and retry
        echo.
        echo You can still use mhrv-rs without the UI. Run the CLI directly:
        echo.
        echo     mhrv-rs.exe
        echo.
        echo Set your config in %%APPDATA%%\mhrv-rs\config\config.json (or
        echo place a config.json next to mhrv-rs.exe in this folder), then
        echo point your browser proxy at 127.0.0.1:8085 (HTTP) or
        echo 127.0.0.1:8086 (SOCKS5). The CLI is the same proxy without
        echo the UI shell, so all functionality is available.
        echo.
        echo Falling back to the CLI now so you can keep using the proxy.
        echo Press Ctrl+C in the CLI window to stop it.
        echo ---------------------------------------------------
        echo.
        mhrv-rs.exe
    )
)

endlocal
