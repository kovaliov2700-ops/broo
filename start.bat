@echo off
chcp 65001 >nul
title PowerApp

cd /d "%~dp0"

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ОШИБКА] Python не найден!
    echo Скачайте: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
echo   PowerApp запускается...
echo   Открой: http://localhost:8000
echo   Логин: admin / admin
echo   Остановка: закройте это окно
echo.

python app.py
