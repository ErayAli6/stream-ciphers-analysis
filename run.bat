@echo off
REM Stream Cipher Demo Runner for Windows
REM Компилира, изпълнява и почиства Java файловете

setlocal enabledelayedexpansion

echo =================================
echo Stream Cipher Demo Runner
echo =================================
echo.

REM Get script directory
set SCRIPT_DIR=%~dp0
set SRC_DIR=%SCRIPT_DIR%src

REM ===== COMPILATION =====
echo [1/3] Компилиране на Java файлове...
cd /d "%SRC_DIR%"
javac *.java
if errorlevel 1 (
    echo [ГРЕШКА] Компилацията се провали
    exit /b 1
)
echo [OK] Компилацията завърши успешно
echo.

REM ===== RUN PROGRAMS =====
echo [2/3] Изпълнение на програмите...
echo.
echo Изберете програма за изпълнение:
echo   1) StreamCipherDemo          - Демонстрации и примери
echo   2) StreamCipherBenchmark     - Performance тестове
echo   3) SecurityAnalysis          - Security анализи
echo   4) AdvancedBenchmark         - Сравнение с Bouncy Castle (изисква библиотека)
echo   5) Всички програми (1, 2, 3) - Последователно изпълнение
echo   6) Изход
echo.

set /p choice="Избор (1-6): "
echo.

if "%choice%"=="1" (
    echo === StreamCipherDemo ===
    java StreamCipherDemo
) else if "%choice%"=="2" (
    echo === StreamCipherBenchmark ===
    java StreamCipherBenchmark
) else if "%choice%"=="3" (
    echo === SecurityAnalysis ===
    java SecurityAnalysis
) else if "%choice%"=="4" (
    echo === AdvancedBenchmark с Bouncy Castle ===
    if exist "..\bcprov-jdk15on-1.70.jar" (
        java -cp ".;..\bcprov-jdk15on-1.70.jar" AdvancedBenchmark
    ) else (
        echo [ГРЕШКА] bcprov-jdk15on-1.70.jar не е намерена в родителската директория
        echo Свалете я от: https://www.bouncycastle.org/latest_releases.html
        exit /b 1
    )
) else if "%choice%"=="5" (
    echo === StreamCipherDemo ===
    java StreamCipherDemo
    echo.
    echo === StreamCipherBenchmark ===
    java StreamCipherBenchmark
    echo.
    echo === SecurityAnalysis ===
    java SecurityAnalysis
) else if "%choice%"=="6" (
    echo Изход без изпълнение.
    goto :cleanup
) else (
    echo [ГРЕШКА] Невалиден избор
    exit /b 1
)

echo.

REM ===== CLEANUP =====
:cleanup
echo [3/3] Почистване на .class файлове...
cd /d "%SRC_DIR%"
del /q *.class 2>nul
if errorlevel 1 (
    echo [ПРЕДУПРЕЖДЕНИЕ] Някои файлове не могат да бъдат изтрити
) else (
    echo [OK] Почистването завърши успешно
)

echo.
echo =================================
echo Готово!
echo =================================

pause
