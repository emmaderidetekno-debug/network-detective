@echo off
title ST. DERRICKS - Network Intelligence
cd /d "%~dp0"
py stderricks.py
if errorlevel 1 (
 echo Trying python command...
 python stderricks.py
)
if errorlevel 1 pause
