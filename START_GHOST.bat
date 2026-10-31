@echo off
title GHOST - Network Operations Terminal
cd /d "%~dp0"
py ghost.py
if errorlevel 1 (
  echo.
  echo GHOST exited with an error. Check that Python 3 is installed.
  pause
)
