@echo off
setlocal
cd /d "%~dp0"
title PS4 PUP Werkzeug
where python >nul 2>&1 || (echo Python fehlt im PATH. & pause & exit /b 1)
if not exist "%~dp0pup_werkzeug.py" (echo pup_werkzeug.py fehlt. & pause & exit /b 1)

if not "%~1"=="" goto drop

:menu
cls
echo  1 pruefen      2 liste      3 Container trennen
echo  4 entpacken     5 packen     6 Container bauen
echo  0 Ende
echo.
set "m="
set /p "m=Auswahl: "
if "%m%"=="0" exit /b 0
set "p="
set /p "p=Pfad: "
set "p=%p:"=%"
call :run %m% "%p%"
echo.
pause
goto menu

:drop
set "p=%~1"
echo %p%
echo  1 pruefen  2 liste  4 entpacken
set "m="
set /p "m=Auswahl: "
call :run %m% "%p%"
echo.
pause
exit /b 0

:run
if "%~1"=="1" python "%~dp0pup_werkzeug.py" info "%~2" & goto :eof
if "%~1"=="2" python "%~dp0pup_werkzeug.py" list "%~2" & goto :eof
if "%~1"=="3" python "%~dp0pup_werkzeug.py" split "%~2" "%~dpn2_fragmente" & goto :eof
if "%~1"=="4" python "%~dp0pup_werkzeug.py" extract "%~2" "%~dpn2_dateien" & goto :eof
if "%~1"=="5" python "%~dp0pup_werkzeug.py" pack "%~2" "%~dpn2.neu.PUP" & goto :eof
if "%~1"=="6" python "%~dp0pup_werkzeug.py" merge "%~2" "%~dpn2.neu.PUP" & goto :eof
echo unbekannt
goto :eof