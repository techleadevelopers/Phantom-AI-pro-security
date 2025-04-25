@echo off
chcp 65001 >nul
title Stealth Launcher - Brutal CMD UI

echo.
echo ===== Stealth Launcher =====
echo.

REM --- Lista de stages
set stages=evasion patching payload_execution beaconing persistence cleanup

REM --- Execução de cada stage
for %%S in (%stages%) do (
    echo [*] Executando stage: %%S...
    python -m stealth_launcher.stealth_launcher %%S

    if errorlevel 1 (
        echo [!] Erro na fase: %%S
    ) else (
        echo [+] Fase %%S concluída com sucesso!
    )
    echo.
)

echo.
echo >>>>> Todos os estágios foram completados com sucesso! <<<<<
echo.
pause
