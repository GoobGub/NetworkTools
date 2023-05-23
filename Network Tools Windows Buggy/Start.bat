@echo off
echo Running NetworkTools...
echo.

REM Check if running as administrator
NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo This batch file requires administrator privileges.
    echo Prompting for elevated permissions...
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c %~dp0NetworkTools.py' -Verb RunAs"
    exit /b
)

REM Run the Python script
python NetworkTools.py

echo.
echo NetworkTools execution completed.
echo Press any key to exit.
pause >nul
