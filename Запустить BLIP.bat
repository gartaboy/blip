@echo off
chcp 65001 >nul
title BLIP CLI
cd /d "%~dp0"
python menu.py
pause
