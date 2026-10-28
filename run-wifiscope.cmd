@echo off
setlocal
cd /d "%~dp0"
python -m wifiscope %*
exit /b %errorlevel%
