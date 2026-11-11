@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title PS4 PUP Werkzeug
where python >nul 2>&1 || (echo Python fehlt im PATH. & pause & exit /b 1)
if not exist "%~dp0pup_tool.py" (echo pup_tool.py fehlt neben der BAT. & pause & exit /b 1)

if not "%~1"=="" goto dropped

:menu
cls
echo ==========================================
echo   PS4 PUP Werkzeug
echo ==========================================
echo   1  Container pruefen / auflisten
echo   2  Container in Fragmente trennen
echo   3  Fragment auflisten
echo   4  Fragment entpacken (entschluesselt)
echo   5  Fragment aus Ordner packen
echo   6  Container aus Fragmenten bauen
echo   0  Ende
echo.
set "m="
set /p "m=Auswahl: "
if "%m%"=="0" exit /b 0
echo.
set "p="
set /p "p=Pfad (Datei oder Ordner): "
set "p=%p:"=%"
call :run %m% "%p%"
echo.
pause
goto menu

:dropped
set "p=%~1"
echo Datei: %p%
echo   1 pruefen  2 trennen  3 auflisten  4 entpacken
set "m="
set /p "m=Auswahl: "
call :run %m% "%p%"
echo.
pause
exit /b 0

:run
if "%~1"=="1" ( python "%~dp0pup_tool.py" info "%~2" & goto :eof )
if "%~1"=="2" ( python "%~dp0pup_tool.py" split "%~2" "%~dpn2_fragmente" & goto :eof )
if "%~1"=="3" ( python "%~dp0pup_tool.py" list "%~2" & goto :eof )
if "%~1"=="4" ( python "%~dp0pup_tool.py" extract "%~2" "%~dpn2_dateien" & goto :eof )
if "%~1"=="5" ( python "%~dp0pup_tool.py" pack "%~2" "%~dpn2.neu.pup" & goto :eof )
if "%~1"=="6" ( python "%~dp0pup_tool.py" merge "%~2" "%~dpn2.neu.PUP" & goto :eof )
echo Unbekannte Auswahl.
goto :eof