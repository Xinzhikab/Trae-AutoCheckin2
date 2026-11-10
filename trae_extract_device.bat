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
if exist "%~dp0trae_device_result.json" (
    echo Result saved to trae_device_result.json.
    echo Opening it in Notepad now - copy the whole line inside.
    echo.
    start "" notepad "%~dp0trae_device_result.json"
) else (
    echo No result file was created. Check the line above starting with {,
    echo or run again after starting Trae client once.
)
echo.
echo --------------------------------------------
echo The result is the ONE line that starts with { .
echo It contains the ECDSA private key - keep it
echo PRIVATE, never paste into public chats/repos.
echo Copy it, send it privately.
echo --------------------------------------------
pause