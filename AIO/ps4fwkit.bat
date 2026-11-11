@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title ps4fwkit
set PY=python
where py >nul 2>&1 && set PY=py -3

if "%~1"=="" goto nofile
set "TARGET=%~1"
if exist "%TARGET%\" (set "ISDIR=1") else (set "ISDIR=0")
if "%ISDIR%"=="1" goto dirmenu
goto filemenu

:filemenu
cls
echo ============================================================
echo  ps4fwkit - DATEI: %TARGET%
echo ============================================================
echo  [1] Identifizieren (info)
echo  [2] SLB2/BLS auflisten
echo  [3] SLB2/BLS entpacken
echo  [4] PUP: Info
echo  [5] PUP: Segmente entpacken
echo  [6] PUP: HMAC verifizieren
echo  [7] Hexdump
echo  [8] Strings
echo  [9] Hex-Muster suchen
echo  [A] Entropie-Karte
echo  [B] IMG: Dateisystem bestimmen
echo  [C] IMG: Signaturen carven
echo  [D] SELF-Header
echo  [E] Gegen andere Datei diffen
echo  [F] Angriffsflaeche
echo  [G] Neues Ziel
echo  [Q] Ende
echo ============================================================
set /p CH=Auswahl: 

if /i "%CH%"=="1" %PY% ps4fwkit.py info "%TARGET%" & pause & goto filemenu
if /i "%CH%"=="2" %PY% ps4fwkit.py slb list "%TARGET%" & pause & goto filemenu
if /i "%CH%"=="3" %PY% ps4fwkit.py slb extract "%TARGET%" -o "%~n1_dump" & pause & goto filemenu
if /i "%CH%"=="4" %PY% ps4fwkit.py pup info "%TARGET%" --keys keys.json & pause & goto filemenu
if /i "%CH%"=="5" %PY% ps4fwkit.py pup extract "%TARGET%" -o "%~n1_seg" --keys keys.json & pause & goto filemenu
if /i "%CH%"=="6" %PY% ps4fwkit.py pup verify "%TARGET%" & pause & goto filemenu
if /i "%CH%"=="7" %PY% ps4fwkit.py hex "%TARGET%" --length 512 & pause & goto filemenu
if /i "%CH%"=="8" %PY% ps4fwkit.py strings "%TARGET%" --min 8 & pause & goto filemenu
if /i "%CH%"=="9" set /p PAT=Hex-Muster: & %PY% ps4fwkit.py find "%TARGET%" --pattern "!PAT!" --hex --all & pause & goto filemenu
if /i "%CH%"=="A" %PY% ps4fwkit.py entropy "%TARGET%" & pause & goto filemenu
if /i "%CH%"=="B" %PY% ps4fwkit.py img info "%TARGET%" & pause & goto filemenu
if /i "%CH%"=="C" %PY% ps4fwkit.py img carve "%TARGET%" & pause & goto filemenu
if /i "%CH%"=="D" %PY% ps4fwkit.py self "%TARGET%" & pause & goto filemenu
if /i "%CH%"=="E" set /p OTH=Zweite Datei: & %PY% ps4fwkit.py diff "%TARGET%" "!OTH!" & pause & goto filemenu
if /i "%CH%"=="F" %PY% ps4fwkit.py exploit & pause & goto filemenu
if /i "%CH%"=="G" goto pick
if /i "%CH%"=="Q" exit /b
goto filemenu

:dirmenu
cls
echo ============================================================
echo  ps4fwkit - ORDNER: %TARGET%
echo ============================================================
echo  [1] Inhalt scannen und identifizieren
echo  [2] PUP-Fragmente im Ordner auflisten
echo  [3] Alle PUP-Fragmente entpacken
echo  [4] Alle IMG-Dateien bestimmen
echo  [5] SHA-256 aller Dateien
echo  [6] Angriffsflaeche anzeigen
echo  [7] Ordner oeffnen
echo  [G] Neues Ziel
echo  [Q] Ende
echo ============================================================
set /p CH=Auswahl: 

if /i "%CH%"=="1" %PY% ps4fwkit.py scan "%TARGET%" & pause & goto dirmenu
if /i "%CH%"=="2" (for %%F in ("%TARGET%\*.PUP") do @echo   %%~nxF) & pause & goto dirmenu
if /i "%CH%"=="3" (for %%F in ("%TARGET%\*.PUP") do @(%PY% ps4fwkit.py pup extract "%%F" -o "%%~nF_seg" --keys keys.json)) & pause & goto dirmenu
if /i "%CH%"=="4" (for %%F in ("%TARGET%\*.img") do @(%PY% ps4fwkit.py img info "%%F")) & pause & goto dirmenu
if /i "%CH%"=="5" (for %%F in ("%TARGET%\*") do @certutil -hashfile "%%F" SHA256 ^| findstr /v ":") & pause & goto dirmenu
if /i "%CH%"=="6" %PY% ps4fwkit.py exploit & pause & goto dirmenu
if /i "%CH%"=="7" start "" "%TARGET%" & goto dirmenu
if /i "%CH%"=="G" goto pick
if /i "%CH%"=="Q" exit /b
goto dirmenu

:pick
set /p TARGET=Pfad: 
if not defined TARGET goto pick
if exist "%TARGET%\" (set "ISDIR=1" & goto dirmenu)
set "ISDIR=0"
goto filemenu

:nofile
cls
echo Ziehe eine Datei ODER einen Ordner auf diese .bat.
echo.
set /p TARGET=Pfad: 
if not defined TARGET exit /b
if exist "%TARGET%\" (set "ISDIR=1" & goto dirmenu)
set "ISDIR=0"
goto filemenu