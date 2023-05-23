@echo off

REM Install required dependencies
pip install scapy

REM Download and install WinPcap
REM Modify the download URL if needed
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe', 'WinPcap_4_1_3.exe')"
WinPcap_4_1_3.exe /S

REM Display setup completed message
echo.
echo NetworkTools setup completed.
echo Press any key to exit.
pause >nul
