@echo off
rem Trae device identity extractor launcher (double-click, no close-flash)
chcp 65001 >nul
title Trae Device Extractor
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py "%~dp0trae_extract_device.py"
    goto :done
)
where python >nul 2>nul
if %errorlevel%==0 (
    python "%~dp0trae_extract_device.py"
    goto :done
)
echo [X] Python not found on this machine.
echo     Install Python 3 and tick "Add python.exe to PATH":
echo     https://www.python.org/downloads/
goto :done

:done
echo.
echo --------------------------------------------
echo The line above (starting with { ) is the full
echo result. Copy that whole line, send it privately.
echo It contains the ECDSA private key - keep it
echo PRIVATE, never paste into public chats/repos.
echo --------------------------------------------
pause