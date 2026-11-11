@echo off
setlocal enabledelayedexpansion
title IMG/SLB/PUP Extractor
color 0B

set "SELF=%~f0"
set "BATDIR=%~dp0"
set "PSF=%TEMP%\imgslb_%RANDOM%%RANDOM%.ps1"
set "IMGSLB_INPUT="
set "RC=0"

if not "%~1"=="" goto :collect
goto :ask

:collect
for %%A in (%*) do (
    set "P=%%~A"
    if defined IMGSLB_INPUT (set "IMGSLB_INPUT=!IMGSLB_INPUT!|!P!") else (set "IMGSLB_INPUT=!P!")
)
set "PSARGS=%*"
goto :run

:ask
echo ============================================================
echo  IMG / SLB / PUP Extractor
echo ============================================================
echo  Datei oder Ordner hierher ziehen, oder Pfad eintippen.
echo  Beenden mit leerer Eingabe.
echo.
set "TARGET="
set /p "TARGET=Pfad: "
if not defined TARGET exit /b 1
set "TARGET=%TARGET:"=%"
for /f "tokens=* delims= " %%B in ("%TARGET%") do set "TARGET=%%B"
if not defined TARGET exit /b 1
set "IMGSLB_INPUT=!TARGET!"
set "PSARGS="

:run
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t=[IO.File]::ReadAllText($env:SELF); $m='::PS1_START'; $i=$t.LastIndexOf($m); if($i -lt 0){Write-Host 'Marker ::PS1_START fehlt.' -ForegroundColor Red; exit 1}; $i=$t.IndexOf([char]10,$i); if($i -lt 0){Write-Host 'Marker ohne Zeilenumbruch.' -ForegroundColor Red; exit 1}; [IO.File]::WriteAllText($env:PSF, $t.Substring($i+1), (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true))"
if errorlevel 1 (set "RC=1" & goto :cleanup)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:PSF,[ref]$null,[ref]$e); if($e.Count -gt 0){ foreach($x in $e){ Write-Host ('  Syntaxfehler ' + $x.Extent.StartLineNumber + ':' + $x.Extent.StartColumnNumber + ' - ' + $x.Message) -ForegroundColor Red }; exit 1 }"
if errorlevel 1 (set "RC=1" & goto :cleanup)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PSF%" %PSARGS%
set "RC=%ERRORLEVEL%"

:cleanup
del "%PSF%" >nul 2>&1
echo.
if "%~1"=="" pause
exit /b %RC%

::PS1_START
#requires -version 5.1
<#
  IMG / SLB / PUP Extractor
  PS4-Firmware: PUP-Entschluesselung, Blocktabellen-Rekonstruktion,
  SLB2, zlib-Scan, LZ4, exFAT/FAT/NTFS/ext/MBR/GPT/ISO/VHD,
  AutoCAD-Slide-Libraries, Hexdump + Entropie + Carving.

  Beispiele:
    extractor.bat "C:\daten\PS4UPDATE2"
    extractor.bat "C:\daten\PS4UPDATE2.PUP"
    extractor.bat "C:\daten\05_system_exfat.img" -List
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$InputPath,
    [string]$OutDir,
    [switch]$List,
    [switch]$Recurse,
    [switch]$Carve,
    [switch]$KeepPartitions,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$script:SevenZip = $null
$script:LogFile  = $null
$script:Count    = 0
$script:Fail     = 0
$script:Files    = 0

# ------------------------------------------------------------------ Helfer

function Find-SevenZip {
    $cands = @()
    if ($env:SEVENZIP) { $cands += $env:SEVENZIP }
    if ($env:BATDIR)   { $cands += (Join-Path $env:BATDIR '7z.exe'); $cands += (Join-Path $env:BATDIR '7za.exe') }
    $cands += "$env:ProgramFiles\7-Zip\7z.exe"
    $cands += "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
    $cands += "$env:LOCALAPPDATA\Programs\7-Zip\7z.exe"
    foreach ($c in $cands) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return (Resolve-Path -LiteralPath $c).Path }
    }
    $cmd = Get-Command 7z.exe, 7za.exe, 7zz.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg
    switch ($Level) {
        'OK'   { Write-Host $line -ForegroundColor Green }
        'WARN' { Write-Host $line -ForegroundColor Yellow }
        'ERR'  { Write-Host $line -ForegroundColor Red }
        'HEAD' { Write-Host $line -ForegroundColor Cyan }
        default { Write-Host $line }
    }
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
}

function Get-SafeName {
    param([string]$Name)
    $n = $Name.Trim()
    if (-not $n) { return 'unnamed' }
    foreach ($c in ([IO.Path]::GetInvalidFileNameChars())) { $n = $n.Replace($c, '_') }
    $n = $n -replace '\s+', '_'
    $n = $n -replace '_+', '_'
    if ($n.Length -gt 90) { $n = $n.Substring(0, 90) }
    $n = $n.Trim('_', '.')
    if (-not $n) { return 'unnamed' }
    return $n
}

function New-OutDir {
    param([string]$Base, [string]$Name)
    $d = Join-Path $Base $Name
    $i = 1
    while ((Test-Path -LiteralPath $d) -and -not $Force) {
        $d = Join-Path $Base ('{0}_{1}' -f $Name, $i)
        $i++
    }
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    return $d
}

function Read-Bytes {
    param([string]$Path, [long]$Offset, [int]$Count)
    if ($Count -le 0) { return ,([byte[]]@()) }
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        if ($Offset -gt 0) { [void]$fs.Seek($Offset, 'Begin') }
        $buf = New-Object byte[] $Count
        $read = $fs.Read($buf, 0, $Count)
        if ($read -le 0) { return ,([byte[]]@()) }
        if ($read -lt $Count) {
            $t = New-Object byte[] $read
            [Array]::Copy($buf, $t, $read)
            return ,$t
        }
        return ,$buf
    } finally { $fs.Dispose() }
}

function Test-Magic {
    param([string]$Path, [long]$Offset, [byte[]]$Magic)
    try { $b = Read-Bytes -Path $Path -Offset $Offset -Count $Magic.Length } catch { return $false }
    if ($b.Length -lt $Magic.Length) { return $false }
    for ($i = 0; $i -lt $Magic.Length; $i++) { if ($b[$i] -ne $Magic[$i]) { return $false } }
    return $true
}

function Get-Entropy {
    param([byte[]]$Data)
    if (-not $Data -or $Data.Length -eq 0) { return 0 }
    $counts = New-Object int[] 256
    foreach ($b in $Data) { $counts[$b]++ }
    $n = [double]$Data.Length
    $e = 0.0
    foreach ($c in $counts) { if ($c -gt 0) { $p = $c / $n; $e -= $p * [Math]::Log($p, 2) } }
    return [Math]::Round($e, 3)
}

function Get-HexProbe {
    param([string]$Path, [int]$Count = 256, [long]$Offset = 0)
    $b = Read-Bytes -Path $Path -Offset $Offset -Count $Count
    if (-not $b -or $b.Length -eq 0) { return '(keine Daten lesbar)' }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $b.Length; $i += 16) {
        $line = '{0:X8}  ' -f ($Offset + $i)
        for ($j = 0; $j -lt 16; $j++) {
            if (($i + $j) -lt $b.Length) { $line += '{0:X2} ' -f $b[$i + $j] } else { $line += '   ' }
        }
        $line += ' |'
        for ($j = 0; $j -lt 16; $j++) {
            if (($i + $j) -lt $b.Length) {
                $c = $b[$i + $j]
                if ($c -ge 32 -and $c -lt 127) { $line += [char]$c } else { $line += '.' }
            }
        }
        $line += '|'
        [void]$sb.AppendLine($line)
    }
    return $sb.ToString()
}

function Write-Probe {
    param([string]$Path, [string]$Dest)
    try {
        $size = [long](Get-Item -LiteralPath $Path).Length
        $whole = [byte[]](Read-Bytes -Path $Path -Offset 0 -Count ([int][Math]::Min($size, [long](64KB))))
        $printable = 0
        foreach ($b in $whole) { if ($b -ge 32 -and $b -lt 127) { $printable++ } }
        $ratio = if ($whole.Length -gt 0) { [Math]::Round(100.0 * $printable / $whole.Length, 1) } else { 0 }
        $hex = Get-HexProbe -Path $Path -Count 256

        Write-Log ('  Groesse: {0:N0} Bytes' -f $size)
        foreach ($r in @(@{ N = 'Anfang'; O = [long]0 }, @{ N = 'Mitte'; O = [long]($size / 2) }, @{ N = 'Ende'; O = [long][Math]::Max(0, $size - 64KB) })) {
            $s = [byte[]](Read-Bytes -Path $Path -Offset $r.O -Count ([int][Math]::Min($size - $r.O, [long](64KB))))
            Write-Log ('  Entropie {0}: {1} Bit/Byte' -f $r.N, (Get-Entropy -Data $s))
        }
        Write-Log ('  Druckbare Zeichen: {0} %' -f $ratio)

        $tbl = Find-BlockTable -Path $Path
        $btxt = 'nein'
        if ($tbl) {
            $btxt = [string]$tbl.Count
            Write-Log ('  Blocktabelle: {0} Bloecke, Tabelle ab 0x{1:X}, Digests ab 0x{2:X}' -f $tbl.Count, $tbl.TableStart, $tbl.DigestStart) 'OK'
            $sum = [long]0
            foreach ($e in $tbl.Entries) { $sum += $e.Size }
            Write-Log ('  Summe der Blockgroessen: {0:N0} Bytes' -f $sum)
            Write-Log '  Das ist eine Tabelle, kein Image - die Daten liegen in Nachbardateien.' 'WARN'
        } else {
            Write-Log '  Kein Blocktabellen-Aufbau erkannt.'
        }

        if ($Dest -and (Test-Path -LiteralPath $Dest)) {
            Set-Content -LiteralPath (Join-Path $Dest 'probe.txt') -Encoding UTF8 -Value @(
                "Datei: $Path", "Groesse: $size", "Druckbar: $ratio %",
                ('Blocktabelle: ' + $btxt), '', $hex)
            Set-Content -LiteralPath (Join-Path $Dest 'hexdump.txt') -Value $hex -Encoding UTF8
        }
        Write-Log '  Hexdump (erste 256 Bytes):' 'WARN'
        Write-Host $hex

        if (-not $tbl -and $size -ge 96) {
            Write-Log '  Hexdump (letzte 96 Bytes):' 'WARN'
            Write-Host (Get-HexProbe -Path $Path -Count 96 -Offset ($size - 96))
        }
    } catch {
        Write-Log ('  Probe: ' + $_.Exception.Message) 'WARN'
    }
}

function Get-FileKind {
    param([string]$Path)
    if (Test-Magic $Path 0 ([byte[]](0x4F, 0x15, 0x3D, 0x1D)))            { return 'pup' }
    if (Test-Magic $Path 0 ([byte[]](0x53, 0x4C, 0x42, 0x32)))            { return 'slb2' }
    if (Test-Magic $Path 0 ([byte[]](0x1F, 0x8B)))                        { return 'gzip' }
    if (Test-Magic $Path 0 ([byte[]](0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00))) { return 'xz' }
    if (Test-Magic $Path 0 ([byte[]](0x42, 0x5A, 0x68)))                  { return 'bzip2' }
    if (Test-Magic $Path 0 ([byte[]](0x50, 0x4B, 0x03, 0x04)))            { return 'zip' }
    if (Test-Magic $Path 0 ([byte[]](0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))) { return '7z' }
    if (Test-Magic $Path 0 ([byte[]](0x52, 0x61, 0x72, 0x21)))            { return 'rar' }
    if (Test-Magic $Path 0x8001 ([Text.Encoding]::ASCII.GetBytes('CD001'))) { return 'iso' }
    if (Test-Magic $Path 0 ([Text.Encoding]::ASCII.GetBytes('vhdxfile')))   { return 'vhdx' }
    $len = [long](Get-Item -LiteralPath $Path).Length
    if ($len -ge 512 -and (Test-Magic $Path ($len - 512) ([Text.Encoding]::ASCII.GetBytes('conectix')))) { return 'vhd' }
    if (Test-Magic $Path 512 ([Text.Encoding]::ASCII.GetBytes('EFI PART'))) { return 'gpt' }
    if (Test-Magic $Path 3 ([Text.Encoding]::ASCII.GetBytes('EXFAT')))      { return 'exfat' }
    if (Test-Magic $Path 0x438 ([byte[]](0x53, 0xEF)))                    { return 'ext' }
    if (Test-Magic $Path 0x1FE ([byte[]](0x55, 0xAA))) {
        if (Test-Magic $Path 3 ([Text.Encoding]::ASCII.GetBytes('NTFS')))     { return 'ntfs' }
        if (Test-Magic $Path 0x52 ([Text.Encoding]::ASCII.GetBytes('FAT32'))) { return 'fat' }
        if (Test-Magic $Path 0x36 ([Text.Encoding]::ASCII.GetBytes('FAT32'))) { return 'fat' }
        if (Test-Magic $Path 0x36 ([Text.Encoding]::ASCII.GetBytes('FAT')))   { return 'fat' }
        $mbr = [byte[]](Read-Bytes -Path $Path -Offset 0x1BE -Count 64)
        if ($mbr.Length -ge 5 -and $mbr[4] -eq 0xEE) { return 'gpt' }
        return 'mbr'
    }
    return 'raw'
}

function Find-Embedded {
    param([string]$Path)
    $b = [byte[]](Read-Bytes -Path $Path -Offset 0 -Count ([int](4MB)))
    $n = [int]$b.Length
    if ($n -lt 2048) { return $null }
    $enc = [Text.Encoding]::GetEncoding(28591)
    $txt = $enc.GetString($b)
    $cands = @(
        @{ Kind = 'pup';   Back = 0;      Pat = [byte[]](0x4F, 0x15, 0x3D, 0x1D); Boot = $false },
        @{ Kind = 'slb2';  Back = 0;      Pat = [byte[]](0x53, 0x4C, 0x42, 0x32); Boot = $false },
        @{ Kind = 'exfat'; Back = 3;      Pat = [byte[]](0x45, 0x58, 0x46, 0x41, 0x54); Boot = $true },
        @{ Kind = 'ntfs';  Back = 3;      Pat = [byte[]](0x4E, 0x54, 0x46, 0x53); Boot = $true },
        @{ Kind = 'fat';   Back = 0x36;   Pat = [byte[]](0x46, 0x41, 0x54, 0x33, 0x32); Boot = $true },
        @{ Kind = 'iso';   Back = 0x8001; Pat = [byte[]](0x43, 0x44, 0x30, 0x30, 0x31); Boot = $false },
        @{ Kind = 'gzip';  Back = 0;      Pat = [byte[]](0x1F, 0x8B, 0x08); Boot = $false }
    )
    $best = $null
    foreach ($c in $cands) {
        $back = [int]$c.Back
        $pat = $enc.GetString($c.Pat)
        $i = 0
        while (($i = $txt.IndexOf($pat, $i, [StringComparison]::Ordinal)) -ge 0) {
            $s = [int]($i - $back)
            $i++
            if ($s -le 0 -or ($s + 0x1FF) -ge $n) { continue }
            if ($c.Boot -and ($b[$s + 0x1FE] -ne 0x55 -or $b[$s + 0x1FF] -ne 0xAA)) { continue }
            if (-not $best -or $s -lt $best.Offset) { $best = [pscustomobject]@{ Kind = $c.Kind; Offset = [long]$s } }
            break
        }
    }
    return $best
}

function Copy-Range {
    param([string]$Path, [long]$Offset, [long]$Length, [string]$Dest)
    $src = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        $out = [IO.File]::Create($Dest)
        try {
            [void]$src.Seek($Offset, 'Begin')
            $buf = New-Object byte[] (1MB)
            $rest = $Length
            while ($rest -gt 0) {
                $want = [int][Math]::Min($buf.Length, $rest)
                $r = $src.Read($buf, 0, $want)
                if ($r -le 0) { break }
                $out.Write($buf, 0, $r)
                $rest -= $r
            }
        } finally { $out.Dispose() }
    } finally { $src.Dispose() }
}

function Invoke-SevenZip {
    param([string]$Archive, [string]$Dest)
    if (-not $script:SevenZip) { Write-Log '  7-Zip nicht gefunden.' 'WARN'; return $false }
    $errFile = Join-Path $env:TEMP ('7zerr_' + [Guid]::NewGuid().ToString('N') + '.txt')
    $argStr = 'x -y -bd -bso0 -bsp0 -o"' + $Dest + '" -- "' + $Archive + '"'
    $code = -1
    try {
        $p = Start-Process -FilePath $script:SevenZip -ArgumentList $argStr -NoNewWindow -Wait -PassThru -RedirectStandardError $errFile
        $code = $p.ExitCode
    } catch {
        Write-Log ('  7-Zip Start fehlgeschlagen: ' + $_.Exception.Message) 'WARN'
    }
    if ($code -eq 0) { Remove-Item $errFile -Force -ErrorAction SilentlyContinue; return $true }
    $err = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
    Remove-Item $errFile -Force -ErrorAction SilentlyContinue
    Write-Log ('  7-Zip ExitCode {0}: {1}' -f $code, (($err -replace '\s+', ' ').Trim())) 'WARN'
    return $false
}

function Invoke-AesDecrypt {
    param([byte[]]$Data, [byte[]]$Key, [byte[]]$Iv)
    if (-not $Data -or $Data.Length -lt 16) { return $null }
    if (-not $Key -or $Key.Length -ne 16 -or -not $Iv -or $Iv.Length -ne 16) { return $null }
    $len = [int]($Data.Length - ($Data.Length % 16))
    if ($len -lt 16) { return $null }
    $a = $null
    try {
        $a = [System.Security.Cryptography.Aes]::Create()
        $a.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $a.Padding = [System.Security.Cryptography.PaddingMode]::None
        $a.KeySize = 128
        $a.Key = $Key
        $a.IV = $Iv
        $dec = $a.CreateDecryptor()
        try { return ,$dec.TransformFinalBlock($Data, 0, $len) } finally { $dec.Dispose() }
    } catch {
        return $null
    } finally {
        if ($a) { $a.Dispose() }
    }
}

# --------------------------------------------------- Dekompressions-Bausteine

function Invoke-InflateRange {
    param([byte[]]$Buf, [int]$Start, [int]$Len)
    if ($Len -lt 6) { return $null }
    $src = $null
    $ds = $null
    try {
        $src = New-Object System.IO.MemoryStream($Buf, ($Start + 2), ($Len - 2), $false)
        $ds = New-Object System.IO.Compression.DeflateStream($src, [IO.Compression.CompressionMode]::Decompress)
        $out = New-Object System.IO.MemoryStream
        $tmp = New-Object byte[] 65536
        while (($r = $ds.Read($tmp, 0, $tmp.Length)) -gt 0) {
            $out.Write($tmp, 0, $r)
            if ($out.Length -gt 8MB) { break }
        }
        if ($out.Length -eq 0) { return $null }
        return ,$out.ToArray()
    } catch {
        return $null
    } finally {
        if ($ds) { $ds.Dispose() }
        if ($src) { $src.Dispose() }
    }
}

function Invoke-InflateRaw {
    param([byte[]]$Buf, [int]$Start, [int]$Len)
    if ($Len -lt 4) { return $null }
    $src = $null
    $ds = $null
    try {
        $src = New-Object System.IO.MemoryStream($Buf, $Start, $Len, $false)
        $ds = New-Object System.IO.Compression.DeflateStream($src, [IO.Compression.CompressionMode]::Decompress)
        $out = New-Object System.IO.MemoryStream
        $tmp = New-Object byte[] 65536
        while (($r = $ds.Read($tmp, 0, $tmp.Length)) -gt 0) {
            $out.Write($tmp, 0, $r)
            if ($out.Length -gt 8MB) { break }
        }
        if ($out.Length -lt 512) { return $null }
        return ,$out.ToArray()
    } catch {
        return $null
    } finally {
        if ($ds) { $ds.Dispose() }
        if ($src) { $src.Dispose() }
    }
}

function Expand-Lz4Block {
    param([byte[]]$In, [int]$Start, [int]$MaxOut)
    $out = New-Object System.IO.MemoryStream
    $i = $Start
    $n = [int]$In.Length
    try {
        while ($i -lt $n) {
            $tok = [int]$In[$i]; $i++
            $lit = [int]($tok -shr 4)
            if ($lit -eq 15) {
                while ($i -lt $n) { $x = [int]$In[$i]; $i++; $lit += $x; if ($x -ne 255) { break } }
            }
            if (($i + $lit) -gt $n) { return $null }
            if ($lit -gt 0) { $out.Write($In, $i, $lit); $i += $lit }
            if ($i -ge $n) { break }
            if (($i + 2) -gt $n) { return $null }
            $off = [int]$In[$i] -bor ([int]$In[$i + 1] -shl 8)
            $i += 2
            if ($off -eq 0 -or $off -gt $out.Length) { return $null }
            $ml = [int]($tok -band 0x0F)
            if ($ml -eq 15) {
                while ($i -lt $n) { $x = [int]$In[$i]; $i++; $ml += $x; if ($x -ne 255) { break } }
            }
            $ml += 4
            $from = [int]$out.Length - $off
            for ($k = 0; $k -lt $ml; $k++) {
                $b = $out.GetBuffer()
                $idx = $from + $k
                if ($idx -ge $out.Length) { $idx = $out.Length - 1 }
                $out.WriteByte($b[$idx])
            }
            if ($out.Length -gt $MaxOut) { break }
        }
    } catch {
        return $null
    }
    if ($out.Length -lt 4096) { return $null }
    return ,$out.ToArray()
}

function Expand-ZlibBlocks {
    param([string]$Path, [string]$Dest)
    try {
        $size = [long](Get-Item -LiteralPath $Path).Length
        if ($size -lt 512) { return $false }
        $buf = [byte[]](Read-Bytes -Path $Path -Offset 0 -Count ([int][Math]::Min($size, [long](128MB))))
        $n = [int]$buf.Length
        if ($n -lt 512) { return $false }

        $enc = [Text.Encoding]::GetEncoding(28591)
        $txt = $enc.GetString($buf)
        $cands = New-Object 'System.Collections.Generic.List[int]'
        $i = 0
        while ($cands.Count -lt 20000) {
            $i = $txt.IndexOf([char]0x78, $i)
            if ($i -lt 0 -or ($i + 1) -ge $n) { break }
            $b1 = [int]$buf[$i + 1]
            if ($b1 -eq 0x01 -or $b1 -eq 0x5E -or $b1 -eq 0x9C -or $b1 -eq 0xDA) { $cands.Add([int]$i) }
            $i++
        }
        if ($cands.Count -eq 0) { return $false }

        $aligned = @($cands | Where-Object { ($_ % 16) -eq 0 })
        $others  = @($cands | Where-Object { ($_ % 16) -ne 0 })
        $ordered = @($aligned) + @($others)

        $bestStart = [int](-1)
        $bestLen = [int]0
        $tries = [int]0
        foreach ($c in $ordered) {
            if ($tries -ge 3000) { break }
            $tries++
            $ci = [int]$c
            $d = Invoke-InflateRange -Buf $buf -Start $ci -Len ([int]($n - $ci))
            if ($d -and $d.Length -gt $bestLen) { $bestLen = [int]$d.Length; $bestStart = $ci }
            if ($bestLen -ge 262144) { break }
        }
        if ($bestStart -lt 0 -or $bestLen -lt 4096) { return $false }

        $ms = New-Object System.IO.MemoryStream
        $p = [int]$bestStart
        $blocks = [int]0
        while ((($p + 16) -lt $n) -and $blocks -lt 200000) {
            if ($buf[$p] -ne 0x78) { break }
            $b1 = [int]$buf[$p + 1]
            if ($b1 -ne 0x01 -and $b1 -ne 0x5E -and $b1 -ne 0x9C -and $b1 -ne 0xDA) { break }
            $data = Invoke-InflateRange -Buf $buf -Start $p -Len ([int]($n - $p))
            if (-not $data) { break }
            $lo = [int]1
            $hi = [int][Math]::Floor(($n - $p) / 16)
            $best = [int](-1)
            while ($lo -le $hi) {
                $mid = [int][Math]::Floor(($lo + $hi) / 2)
                if ($mid -lt 1) { $mid = 1 }
                if (Invoke-InflateRange -Buf $buf -Start $p -Len ([int]($mid * 16))) { $best = [int]($mid * 16); $hi = [int]($mid - 1) }
                else { $lo = [int]($mid + 1) }
            }
            if ($best -lt 16) { $best = [int]16 }
            $ms.Write($data, 0, $data.Length)
            $blocks++
            $p = [int]($p + $best)
            if ($ms.Length -gt 1900MB) { Write-Log '  Groessengrenze erreicht, breche ab.' 'WARN'; break }
        }

        if ($blocks -eq 0 -or $ms.Length -lt 4096) { return $false }
        $raw = $ms.ToArray()
        $tmp = Join-Path $env:TEMP ('zlb_' + [Guid]::NewGuid().ToString('N') + '.bin')
        [IO.File]::WriteAllBytes($tmp, $raw)
        $k = Get-FileKind -Path $tmp
        Write-Log ('  {0} zlib-Bloecke ab 0x{1:X} entpackt -> {2:N0} Bytes, erkannt: {3}' -f $blocks, $bestStart, $raw.Length, $k) 'OK'
        $sub = New-OutDir -Base $Dest -Name 'decompressed'
        $got = Invoke-Container -File $tmp -Dest $sub -Depth 9
        if (-not $got) {
            Copy-Item -LiteralPath $tmp -Destination (Join-Path $Dest 'decompressed.bin') -Force
            Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Log ('  zlib-Scan: ' + $_.Exception.Message) 'WARN'
        return $false
    }
}

function Expand-Other {
    param([string]$Path, [string]$Dest)
    try {
        $size = [long](Get-Item -LiteralPath $Path).Length
        if ($size -lt 4096) { return $false }
        $buf = [byte[]](Read-Bytes -Path $Path -Offset 0 -Count ([int][Math]::Min($size, [long](16MB))))
        $n = [int]$buf.Length
        if ($n -lt 4096) { return $false }

        $variants = New-Object 'System.Collections.Generic.List[object]'

        $lz = Expand-Lz4Block -In $buf -Start 0 -MaxOut 536870912
        if ($lz) { $variants.Add([pscustomobject]@{ Name = 'lz4'; Data = $lz }) }

        $enc = [Text.Encoding]::GetEncoding(28591)
        $txt = $enc.GetString($buf)
        $o = 0
        $tried = 0
        while ($tried -lt 256) {
            $o = $txt.IndexOf([char]0x78, $o)
            if ($o -lt 0 -or ($o + 1) -ge $n) { break }
            $b1 = [int]$buf[$o + 1]
            $o++
            if ($b1 -ne 0x01 -and $b1 -ne 0x9C -and $b1 -ne 0xDA -and $b1 -ne 0x5E) { continue }
            $tried++
            $d = Invoke-InflateRaw -Buf $buf -Start ([int]($o - 1)) -Len ([int]($n - $o + 1))
            if ($d) { $variants.Add([pscustomobject]@{ Name = ('deflate@0x{0:X}' -f ($o - 1)); Data = $d }); break }
        }

        foreach ($v in $variants) {
            $tmp = Join-Path $env:TEMP ('var_' + [Guid]::NewGuid().ToString('N') + '.bin')
            [IO.File]::WriteAllBytes($tmp, $v.Data)
            $k = Get-FileKind -Path $tmp
            if ($k -eq 'raw' -and $v.Data.Length -lt ($n * 2)) { Remove-Item $tmp -Force; continue }
            Write-Log ('  {0}: {1:N0} Bytes, erkannt: {2}' -f $v.Name, $v.Data.Length, $k) 'OK'
            $sub = New-OutDir -Base $Dest -Name ('via_' + ($v.Name -replace '[^a-zA-Z0-9]', '_'))
            $got = Invoke-Container -File $tmp -Dest $sub -Depth 9
            if (-not $got) {
                Copy-Item -LiteralPath $tmp -Destination (Join-Path $Dest (($v.Name -replace '[^a-zA-Z0-9]', '_') + '.bin')) -Force
                Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue
            }
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            return $true
        }
        return $false
    } catch {
        Write-Log ('  Varianten: ' + $_.Exception.Message) 'WARN'
        return $false
    }
}

# ------------------------------------------------------------ Blocktabelle

function Find-BlockTable {
    param([string]$Path)
    try {
        $size = [long](Get-Item -LiteralPath $Path).Length
        if ($size -lt 80) { return $null }
        $maxRead = [long](2MB)
        $base = 0L
        if ($size -gt $maxRead) { $base = $size - $maxRead }
        $buf = [byte[]](Read-Bytes -Path $Path -Offset $base -Count ([int]($size - $base)))
        $n = [int]$buf.Length
        if ($n -lt 80) { return $null }

        foreach ($hdr in @(0, 16, 32, 48, 64)) {
            if ($hdr -ge $n) { break }
            $rest = $n - $hdr
            $hi = [int][Math]::Floor($rest / 40)
            for ($count = $hi; $count -ge 2; $count--) {
                $slack = $rest - ($count * 40)
                if ($slack -gt 4096) { break }
                $ts = [int]($hdr + ($count * 32))
                if (($ts + ($count * 8)) -gt $n) { continue }
                $prev = [long](-1)
                $ok = $true
                $entries = New-Object 'System.Collections.Generic.List[object]'
                for ($i = 0; $i -lt $count; $i++) {
                    $p = $ts + ($i * 8)
                    $o = [long][BitConverter]::ToUInt32($buf, $p)
                    $s = [long][BitConverter]::ToUInt32($buf, $p + 4)
                    if ($s -le 0 -or $s -gt 8388608) { $ok = $false; break }
                    if ($o -le $prev) { $ok = $false; break }
                    $prev = $o
                    $entries.Add([pscustomobject]@{ Offset = $o; Size = $s })
                }
                if (-not $ok) { continue }
                if ($entries[0].Offset -ne 0) { continue }
                return [pscustomobject]@{
                    Count = $count; DigestStart = [long]($base + $hdr)
                    TableStart = [long]($base + $ts); Size = $size; Entries = $entries
                }
            }
        }
        return $null
    } catch {
        return $null
    }
}

function Join-Files {
    param($Files, [string]$Dest, [long]$Max)
    $out = [IO.File]::Create($Dest)
    try {
        foreach ($f in $Files) {
            if ($out.Length -ge $Max) { break }
            $src = $null
            try {
                $src = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
                $src.CopyTo($out)
            } catch { } finally { if ($src) { $src.Dispose() } }
        }
    } finally { $out.Dispose() }
}

function Test-BootSig {
    param([byte[]]$D)
    if (-not $D -or $D.Length -lt 0x60) { return $false }
    if ($D.Length -ge 0x200) {
        if ([Text.Encoding]::ASCII.GetString($D, 3, 5) -eq 'EXFAT')  { return $true }
        if ([Text.Encoding]::ASCII.GetString($D, 3, 4) -eq 'NTFS')   { return $true }
        if ([Text.Encoding]::ASCII.GetString($D, 0x36, 5) -eq 'FAT32') { return $true }
        if ([Text.Encoding]::ASCII.GetString($D, 0x36, 3) -eq 'FAT') { return $true }
        if ($D.Length -ge 0x440 -and $D[0x438] -eq 0x53 -and $D[0x439] -eq 0xEF) { return $true }
        if ($D.Length -ge 0x208 -and [Text.Encoding]::ASCII.GetString($D, 0x200, 8) -eq 'EFI PART') { return $true }
        if ($D[0x1FE] -eq 0x55 -and $D[0x1FF] -eq 0xAA) {
            if ([Text.Encoding]::ASCII.GetString($D, 0x52, 5) -eq 'FAT32') { return $true }
            return $true
        }
    }
    return $false
}

function Get-BlockRead {
    param($Entry, [long]$BlockSize, [long]$Need)
    $size = [long]$Entry.Size
    $pad = [int]($size -band 0xF)
    $raw = ((($size -band (-bnot 0xF)) - $pad) -eq $BlockSize)
    $readLen = if ($raw) { $BlockSize } else { [long]($size -band (-bnot 0xF)) }
    if ($readLen -le 0) { $readLen = $size }
    if (([long]$Entry.Offset + $readLen) -gt $Need) { $readLen = $Need - [long]$Entry.Offset }
    return [pscustomobject]@{ Raw = $raw; ReadLen = $readLen }
}

function Test-Anchor {
    param([string]$Path, [long]$Base, $Table, [long]$BlockSize, [long]$Need)
    try {
        $count = [int]$Table.Count
        $e0 = $Table.Entries[0]
        $r0 = Get-BlockRead -Entry $e0 -BlockSize $BlockSize -Need $Need
        if ($r0.ReadLen -le 8) { return $false }

        $take = [int][Math]::Min($r0.ReadLen, [long]2048)
        $b = [byte[]](Read-Bytes -Path $Path -Offset $Base -Count $take)
        if ($b.Length -lt 0x60) { return $false }

        $d = $null
        if ($r0.Raw) { $d = $b }
        elseif ($b[0] -eq 0x78) { $d = Invoke-InflateRange -Buf $b -Start 0 -Len $b.Length }
        if (-not $d) { return $false }

        $sig = Test-BootSig $d
        if ($sig) { return $true }

        $good = 0
        foreach ($ci in @(1, [int]($count - 1))) {
            if ($ci -lt 1 -or $ci -ge $count) { continue }
            $x = $Table.Entries[$ci]
            $rx = Get-BlockRead -Entry $x -BlockSize $BlockSize -Need $Need
            if ($rx.ReadLen -le 8) { continue }
            $xt = [int][Math]::Min($rx.ReadLen, [long]2048)
            $xb = [byte[]](Read-Bytes -Path $Path -Offset ($Base + [long]$x.Offset) -Count $xt)
            if ($xb.Length -lt 8) { continue }
            if ($rx.Raw) { $good++; continue }
            if ($xb[0] -ne 0x78) { continue }
            $xd = Invoke-InflateRange -Buf $xb -Start 0 -Len $xb.Length
            if ($xd -and $xd.Length -gt 4096) { $good++ }
        }
        return ($good -ge 2 -or ($good -ge 1 -and $count -le 4))
    } catch {
        return $false
    }
}

function Find-PayloadBase {
    param([string]$Path, $Table, [byte[]]$Digests, [long]$Need, [long]$BlockSize)
    try {
        $len = [long](Get-Item -LiteralPath $Path).Length
        if ($len -lt ($Need + 32)) { return $null }
        if ([int]$Table.Count -lt 1) { return $null }
        $maxBase = [long]($len - $Need)

        $chunk = [long](8MB)
        $overlap = 4096
        $pos = [long]0
        $round = 0
        while ($pos -le $maxBase) {
            $take = [int][Math]::Min(($chunk + $overlap), ($len - $pos))
            $buf = [byte[]](Read-Bytes -Path $Path -Offset $pos -Count $take)
            if ($buf.Length -lt 64) { break }
            $n = [int]$buf.Length

            $cands = New-Object 'System.Collections.Generic.List[long]'
            $i = 0
            while (($i = [Array]::IndexOf($buf, [byte]0x78, $i)) -ge 0) {
                if (($i + 1) -lt $n) {
                    $b1 = [int]$buf[$i + 1]
                    if ($b1 -eq 0x01 -or $b1 -eq 0x5E -or $b1 -eq 0x9C -or $b1 -eq 0xDA) {
                        $cands.Add([long]($pos + $i - ($i % 16)))
                    }
                }
                $i++
            }
            $j = 0
            while (($j = [Array]::IndexOf($buf, [byte]0x45, $j)) -ge 0) {
                if (($j + 7) -lt $n -and $buf[$j + 1] -eq 0x58 -and $buf[$j + 2] -eq 0x46 -and $buf[$j + 3] -eq 0x41 -and $buf[$j + 4] -eq 0x54) {
                    $c = [long]($pos + $j - 3)
                    if ($c -ge 0) { $cands.Add([long]($c - ($c % 16))) }
                }
                $j++
            }

            foreach ($c in ($cands | Sort-Object -Unique)) {
                if ($c -lt 0 -or ($c + $Need) -gt $len) { continue }
                if (Test-Anchor -Path $Path -Base $c -Table $Table -BlockSize $BlockSize -Need $Need) {
                    Write-Log ('  Anker gefunden bei 0x{0:X}' -f $c) 'OK'
                    return [long]$c
                }
            }

            $round++
            if (($round % 4) -eq 0) { Write-Log ('    ... 0x{0:X} durchsucht' -f ($pos + $chunk)) }
            if ($pos -ge $maxBase) { break }
            $pos += $chunk
        }
        return $null
    } catch {
        Write-Log ('  Ankersuche: ' + $_.Exception.Message) 'WARN'
        return $null
    }
}

function Find-PayloadSources {
    param([string]$TableFile, [long]$Need)
    $list = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $dir = Split-Path -Parent $TableFile
    $dirs = New-Object 'System.Collections.Generic.List[string]'
    $d = $dir
    for ($i = 0; $i -lt 4; $i++) {
        if (-not $d) { break }
        $dirs.Add($d)
        $d = Split-Path -Parent $d
    }
    $skip = '.txt', '.log', '.csv', '.ps1', '.bat', '.py', '.cmd'
    foreach ($sd in $dirs) {
        $found = 0
        foreach ($f in (Get-ChildItem -LiteralPath $sd -File -ErrorAction SilentlyContinue)) {
            if ($f.FullName -eq $TableFile) { continue }
            if ($skip -contains $f.Extension.ToLowerInvariant()) { continue }
            if ($f.Length -lt $Need) { continue }
            if (-not $seen.Add($f.FullName)) { continue }
            $list.Add([pscustomobject]@{ Path = $f.FullName; Size = [long]$f.Length; IsPup = $false })
            $found++
        }
        if ($found -gt 0) { break }
    }
    foreach ($e in $list) {
        if (Get-PupIndex -Path $e.Path) { $e.IsPup = $true }
    }
    return ,@($list | Sort-Object @{ Expression = 'IsPup'; Descending = $true }, @{ Expression = 'Size'; Descending = $true })
}

# ------------------------------------------------------------------- PUP-Index

function Get-PupIndex {
    param([string]$Path)
    try {
        $size = [long](Get-Item -LiteralPath $Path).Length
        if ($size -lt 0x100) { return $null }
        $hdr = [byte[]](Read-Bytes -Path $Path -Offset 0 -Count 0x20)
        if ($hdr.Length -lt 0x20) { return $null }

        $magicOk    = ([BitConverter]::ToUInt32($hdr, 0) -eq 0x1D3D154F)
        $headerSize = [int][BitConverter]::ToUInt16($hdr, 0x0C)
        $metaSize   = [int][BitConverter]::ToUInt16($hdr, 0x0E)
        $entryCount = [int][BitConverter]::ToUInt16($hdr, 0x18)
        if ($entryCount -lt 1 -or $entryCount -gt 512) { return $null }
        if ($headerSize -lt 0x20 -or $headerSize -gt 0x4000) { return $null }

        # Eintraege stehen direkt hinter dem 0x20-Byte-Kopf
        $tbl = [byte[]](Read-Bytes -Path $Path -Offset 0x20 -Count ([int]($entryCount * 0x20)))
        if ($tbl.Length -lt ($entryCount * 0x20)) { return $null }

        $list = New-Object 'System.Collections.Generic.List[object]'
        $good = 0
        for ($i = 0; $i -lt $entryCount; $i++) {
            $b = $i * 0x20
            $flags = [BitConverter]::ToUInt32($tbl, $b)
            $off   = [long][BitConverter]::ToInt64($tbl, $b + 0x08)
            $cs    = [long][BitConverter]::ToInt64($tbl, $b + 0x10)
            if ($off -lt 0 -or $cs -lt 0) { return $null }
            if ($cs -gt 0 -and ($off + $cs) -gt $size) { return $null }
            if ($cs -gt 0) { $good++ }
            $list.Add([pscustomobject]@{
                Index  = $i
                Id     = [int]($flags -shr 20)
                Info   = (($flags -band 1) -ne 0)
                Enc    = (($flags -band 2) -ne 0)
                Comp   = (($flags -band 8) -ne 0)
                Offset = $off
                CSize  = $cs
            })
        }
        if ($good -lt 1) { return $null }

        # Metadata steht hinter dem Kopf (headerSize), Eintraege a 0x50
        $meta = [byte[]]@()
        $mtake = [long]$entryCount * 0x50
        if ($metaSize -gt 0 -and $metaSize -lt $mtake) { $mtake = $metaSize }
        if ($mtake -gt 0 -and (([long]$headerSize + $mtake) -le $size)) {
            $mb = [byte[]](Read-Bytes -Path $Path -Offset $headerSize -Count ([int]$mtake))
            if ($mb.Length -ge 0x50) { $meta = $mb }
        }
        return [pscustomobject]@{
            Path = $Path; Size = $size; Meta = $meta; Entries = $list
            MagicOk = $magicOk; HeaderSize = $headerSize; EntryCount = $entryCount
        }
    } catch {
        return $null
    }
}

# ---------------------------------------------------- Segment aus Quelle holen

function Expand-BlocksToImage {
    param(
        [string]$Src, [long]$Base, $Table, [byte[]]$Digests, [long]$BlockSize,
        [long]$Need, [string]$OutFile
    )
    $count = [int]$Table.Count
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $out = [IO.File]::Create($OutFile)
    $hitStored = 0
    $hitDec = 0
    $fail = 0
    $full = 0
    $sig0 = $false
    try {
        for ($bi = 0; $bi -lt $count; $bi++) {
            $e = $Table.Entries[$bi]
            $r = Get-BlockRead -Entry $e -BlockSize $BlockSize -Need $Need
            $readLen = $r.ReadLen
            $pad = [int]([long]$e.Size -band 0xF)
            if ($readLen -le 0) { break }

            $stored = [byte[]](Read-Bytes -Path $Src -Offset ($Base + [long]$e.Offset) -Count ([int]$readLen))
            if ($stored.Length -eq 0) { break }

            $di = $bi * 32
            if (($di + 32) -le $Digests.Length) {
                $h = $sha.ComputeHash($stored)
                $same = $true
                for ($q = 0; $q -lt 32; $q++) { if ($h[$q] -ne $Digests[$di + $q]) { $same = $false; break } }
                if ($same) { $hitStored++ }
            }

            $chunk = $null
            if (-not $r.Raw) {
                $pl = [int]($stored.Length - $pad)
                if ($pl -gt 2 -and $stored[0] -eq 0x78) {
                    $ms = $null
                    $dz = $null
                    try {
                        $ms = New-Object System.IO.MemoryStream($stored, 2, ($pl - 2), $false)
                        $dz = New-Object System.IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)
                        $mo = New-Object System.IO.MemoryStream
                        $tb = New-Object byte[] 65536
                        while (($rr = $dz.Read($tb, 0, $tb.Length)) -gt 0) { $mo.Write($tb, 0, $rr) }
                        if ($mo.Length -gt 0) { $chunk = $mo.ToArray() }
                    } catch { $chunk = $null } finally {
                        if ($dz) { $dz.Dispose() }
                        if ($ms) { $ms.Dispose() }
                    }
                }
            }

            if (-not $chunk) {
                $fail++
                $chunk = $stored
            } elseif (($di + 32) -le $Digests.Length) {
                $hd = $sha.ComputeHash($chunk)
                $same = $true
                for ($q = 0; $q -lt 32; $q++) { if ($hd[$q] -ne $Digests[$di + $q]) { $same = $false; break } }
                if ($same) { $hitDec++ }
            }

            if ($chunk.Length -gt 0 -and ($bi -eq ($count - 1) -or $chunk.Length -eq $BlockSize)) { $full++ }
            if ($bi -eq 0) { $sig0 = Test-BootSig $chunk }

            [void]$out.Seek([long]$bi * $BlockSize, 'Begin')
            $out.Write($chunk, 0, $chunk.Length)
            if (($bi % 250) -eq 0) { Write-Log ('    Block {0}/{1}' -f $bi, $count) }
        }
    } finally {
        $out.Dispose()
        $sha.Dispose()
    }
    return [pscustomobject]@{
        Hits = [Math]::Max($hitStored, $hitDec)
        HitStored = $hitStored; HitDec = $hitDec; Fail = $fail; Full = $full
        Sig0 = $sig0; Count = $count
    }
}

function Test-RebuildOk {
    param($Res)
    if (-not $Res) { return $false }
    $lim = [int][Math]::Max(1, [Math]::Floor($Res.Count * 0.02))
    if ($Res.Fail -gt $lim) { return $false }
    if ($Res.Sig0) { return $true }
    $need = [int][Math]::Ceiling($Res.Count * 0.9)
    if ($Res.Full -ge $need) { return $true }
    if ($Res.Hits -ge $need) { return $true }
    return $false
}

function Expand-TableFromPayload {
    param(
        [string]$TableFile, [string]$Dest, $Table, [byte[]]$Digests,
        [long]$BlockSize, [long]$Need, [string]$SourceFile
    )
    $count = [int]$Table.Count
    $leaf = [IO.Path]::GetFileName($TableFile)
    $wantId = -1
    if ($leaf -match 'id([0-9A-Fa-f]{2,4})') { $wantId = [Convert]::ToInt32($Matches[1], 16) }
    $wantIdx = -1
    if ($leaf -match '^(\d+)') { $wantIdx = [int]$Matches[1] - 1 }

    $srcs = New-Object 'System.Collections.Generic.List[object]'
    if ($SourceFile -and (Test-Path -LiteralPath $SourceFile)) {
        $srcs.Add([pscustomobject]@{ Path = $SourceFile; Size = [long](Get-Item -LiteralPath $SourceFile).Length })
    }
    $srcs.Add([pscustomobject]@{ Path = $TableFile; Size = [long]$Table.Size })
    foreach ($s in (Find-PayloadSources -TableFile $TableFile -Need $Need)) {
        if ($s.Path -ne $TableFile -and $s.Path -ne $SourceFile) { $srcs.Add($s) }
    }

    foreach ($s in $srcs) {
        if ($s.Size -lt ($Need + 32)) { continue }
        $pup = Get-PupIndex -Path $s.Path
        if ($pup) {
            Write-Log ('  PUP-Struktur in {0}: {1} Eintraege, header_size 0x{2:X}, metadata_size 0x{3:X}' -f (Split-Path $s.Path -Leaf), $pup.EntryCount, $pup.HeaderSize, $pup.Meta.Length) 'OK'
            if (-not $pup.MagicOk) { Write-Log '  PUP-Magic weicht ab - Struktur wird trotzdem genutzt.' 'WARN' }
        } else {
            $head = [byte[]](Read-Bytes -Path $s.Path -Offset 0 -Count 16)
            $hx = (($head | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
            Write-Log ('  {0}: keine PUP-Struktur (Header {1})' -f (Split-Path $s.Path -Leaf), $hx)
        }

        $bases = New-Object 'System.Collections.Generic.List[object]'
        if ($pup) {
            $lo = [long]($Need * 0.8)
            $hi = [long]($Need * 1.25)
            $data = @($pup.Entries | Where-Object { $_.CSize -gt 0 -and -not $_.Info })
            $tries = New-Object 'System.Collections.Generic.List[object]'
            foreach ($x in $data) {
                $nameHit = (($wantId -ge 0 -and $x.Id -eq $wantId) -or ($wantIdx -eq $x.Index))
                $sizeHit = ($x.CSize -ge $lo -and $x.CSize -le $hi)
                if ($nameHit -and $sizeHit) { $tries.Add([pscustomobject]@{ E = $x; Rank = 0 }) }
                elseif ($sizeHit) { $tries.Add([pscustomobject]@{ E = $x; Rank = 2 }) }
                elseif ($nameHit) { $tries.Add([pscustomobject]@{ E = $x; Rank = 1 }) }
            }
            foreach ($t in ($tries | Sort-Object Rank)) {
                $x = $t.E
                if (($x.Offset + $Need) -gt $pup.Size) { continue }
                if (@($bases | Where-Object { $_.Base -eq $x.Offset }).Count -gt 0) { continue }
                $bases.Add([pscustomobject]@{ Base = [long]$x.Offset; Entry = $x })
                Write-Log ('  Segment {0} (Id 0x{1:X}, {2:N0} Bytes) bei 0x{3:X}' -f $x.Index, $x.Id, $x.CSize, $x.Offset) 'OK'
            }
        }

        if ($s.Path -eq $TableFile) {
            $tblEnd = [long]$Table.DigestStart + ([long]$count * 40)
            if (($tblEnd + $Need) -le $s.Size) {
                $bases.Add([pscustomobject]@{ Base = [long]$tblEnd; Entry = $null })
            }
        }

        if ($bases.Count -eq 0) {
            Write-Log ('  Suche Segmentdaten in {0}' -f (Split-Path $s.Path -Leaf))
            $b = Find-PayloadBase -Path $s.Path -Table $Table -Digests $Digests -Need $Need -BlockSize $BlockSize
            if ($null -ne $b) { $bases.Add([pscustomobject]@{ Base = [long]$b; Entry = $null }) }
        }
        if ($bases.Count -eq 0) { continue }

        foreach ($cand in $bases) {
            $variants = New-Object 'System.Collections.Generic.List[object]'
            $variants.Add([pscustomobject]@{ Src = $s.Path; Base = [long]$cand.Base; Name = 'roh'; Temp = $null })

            if ($cand.Entry -and $cand.Entry.Enc -and $pup -and $pup.Meta.Length -ge (($cand.Entry.Index + 1) * 0x50)) {
                $kb = [byte[]]$pup.Meta[($cand.Entry.Index * 0x50)..(($cand.Entry.Index * 0x50) + 0x0F)]
                $vb = [byte[]]$pup.Meta[(($cand.Entry.Index * 0x50) + 0x10)..(($cand.Entry.Index * 0x50) + 0x1F)]
                $raw = [byte[]](Read-Bytes -Path $s.Path -Offset $cand.Base -Count ([int]$Need))
                $pl = Invoke-AesDecrypt -Data $raw -Key $kb -Iv $vb
                if ($pl) {
                    $tmp = Join-Path $env:TEMP ('dec_' + [Guid]::NewGuid().ToString('N') + '.bin')
                    [IO.File]::WriteAllBytes($tmp, $pl)
                    $variants.Add([pscustomobject]@{ Src = $tmp; Base = [long]0; Name = 'entschluesselt'; Temp = $tmp })
                } else {
                    Write-Log '  Entschluesselung fehlgeschlagen.' 'WARN'
                }
            }

            $done = $false
            foreach ($v in $variants) {
                Write-Log ('  Versuch: {0}, Basis 0x{1:X}' -f $v.Name, $v.Base)
                $tmpImg = Join-Path $env:TEMP ('rb_' + [Guid]::NewGuid().ToString('N') + '.img')
                $res = Expand-BlocksToImage -Src $v.Src -Base $v.Base -Table $Table -Digests $Digests -BlockSize $BlockSize -Need $Need -OutFile $tmpImg
                if ($res) {
                    Write-Log ('  Vollstaendige Bloecke: {0}/{1}, Fehlschlaege: {2}, Bootsektor: {3}, Digest-Treffer: {4}' -f $res.Full, $res.Count, $res.Fail, $res.Sig0, $res.Hits)
                }
                if (Test-RebuildOk $res) {
                    $k = Get-FileKind -Path $tmpImg
                    Write-Log ('  Rekonstruktion erfolgreich: {0}' -f $k) 'OK'
                    $sub = New-OutDir -Base $Dest -Name 'rebuilt'
                    $got = Invoke-Container -File $tmpImg -Dest $sub -Depth 9
                    if (-not $got) {
                        Copy-Item -LiteralPath $tmpImg -Destination (Join-Path $Dest 'rebuilt.img') -Force
                        Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    $done = $true
                } else {
                    Write-Log '  Abnahme verfehlt.' 'WARN'
                }
                Remove-Item $tmpImg -Force -ErrorAction SilentlyContinue
                if ($done) { break }
            }
            foreach ($v in $variants) { if ($v.Temp) { Remove-Item $v.Temp -Force -ErrorAction SilentlyContinue } }
            if ($done) { return $true }
        }
    }
    return $false
}

function Expand-FromTable {
    param([string]$TableFile, [string]$Dest, $Table, [string]$SourceFile)

    $t = $Table
    if (-not $t) { $t = Find-BlockTable -Path $TableFile }
    if (-not $t) { return $false }
    $count = [int]$t.Count
    Write-Log ('  Blocktabelle: {0} Bloecke (Tabelle ab 0x{1:X}, Digests ab 0x{2:X})' -f $count, $t.TableStart, $t.DigestStart) 'OK'

    $dig = [byte[]]@()
    if (($t.DigestStart + ([long]$count * 32)) -le $t.Size) {
        $dig = [byte[]](Read-Bytes -Path $TableFile -Offset $t.DigestStart -Count ([int]($count * 32)))
    }
    if ($dig.Length -ge ($count * 32)) { Write-Log '  Digests vorhanden - werden als Statistik geprueft.' 'OK' }
    else { Write-Log '  Keine Digests lesbar - Abnahme nur ueber Struktur.' 'WARN' }

    $maxSize = [long]0
    foreach ($e in $t.Entries) { if ($e.Size -gt $maxSize) { $maxSize = [long]$e.Size } }
    $bs = [long]4096
    while ($bs -lt $maxSize -and $bs -lt 4MB) { $bs = $bs * 2 }
    $last = $t.Entries[$count - 1]
    $need = [long]$last.Offset + [long]$last.Size
    Write-Log ('  Blockgroesse: {0:N0}, benoetigte Datengroesse: {1:N0} Bytes' -f $bs, $need)

    $csv = foreach ($e in $t.Entries) { '{0};{1}' -f $e.Offset, $e.Size }
    Set-Content -LiteralPath (Join-Path $Dest 'blocks.csv') -Value $csv -Encoding UTF8

    # 1) Nachbardateien zu einer Quelle verketten
    $dir  = Split-Path -Parent $TableFile
    $leaf = [IO.Path]::GetFileName($TableFile)
    $selfPrefix = 0
    if ($leaf -match '^(\d+)') { $selfPrefix = [int]$Matches[1] }

    $pool = New-Object 'System.Collections.Generic.List[object]'
    foreach ($f in (Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
        if ($f.FullName -eq $TableFile) { continue }
        if ($f.Length -lt 80) { continue }
        if ($f.Extension -in '.txt', '.log', '.csv', '.ps1', '.bat', '.py') { continue }
        if (Find-BlockTable -Path $f.FullName) { continue }
        $num = 0
        if ($f.Name -match '^(\d+)') { $num = [int]$Matches[1] }
        $pool.Add([pscustomobject]@{ FullName = $f.FullName; Length = [long]$f.Length; Num = $num })
    }

    if ($pool.Count -gt 0) {
        $orders = New-Object 'System.Collections.Generic.List[object]'
        $orders.Add(@($pool | Sort-Object Num, FullName))
        $after = @($pool | Where-Object { $_.Num -gt $selfPrefix } | Sort-Object Num, FullName)
        if ($after.Count -gt 0) { $orders.Add($after) }

        $oi = 0
        foreach ($ord in $orders) {
            $oi++
            $total = [long]0
            foreach ($m in $ord) { $total += [long]$m.Length }
            if ($total -lt $need) {
                Write-Log ('  Reihenfolge {0}: nur {1:N0} Bytes vorhanden, zu wenig.' -f $oi, $total) 'WARN'
                continue
            }
            Write-Log ('  Reihenfolge {0}: {1} Dateien, {2:N0} Bytes' -f $oi, $ord.Count, $total)

            $tmp = Join-Path $env:TEMP ('cc_' + [Guid]::NewGuid().ToString('N') + '.bin')
            Join-Files -Files $ord -Dest $tmp -Max ([long]2GB)
            $res = Expand-BlocksToImage -Src $tmp -Base ([long]0) -Table $t -Digests $dig -BlockSize $bs -Need $need -OutFile ($tmp + '.img')
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            if ($res) {
                Write-Log ('  Vollstaendige Bloecke: {0}/{1}, Fehlschlaege: {2}, Bootsektor: {3}' -f $res.Full, $res.Count, $res.Fail, $res.Sig0)
            }
            if (Test-RebuildOk $res) {
                $k = Get-FileKind -Path ($tmp + '.img')
                Write-Log ('  Rekonstruktion erfolgreich: {0}' -f $k) 'OK'
                $sub = New-OutDir -Base $Dest -Name 'rebuilt'
                $got = Invoke-Container -File ($tmp + '.img') -Dest $sub -Depth 9
                if (-not $got) {
                    Copy-Item -LiteralPath ($tmp + '.img') -Destination (Join-Path $Dest 'rebuilt.img') -Force
                    Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue
                }
                Remove-Item ($tmp + '.img') -Force -ErrorAction SilentlyContinue
                return $true
            }
            Remove-Item ($tmp + '.img') -Force -ErrorAction SilentlyContinue
            Write-Log '  Abnahme verfehlt - naechste Reihenfolge.' 'WARN'
        }
        Write-Log '  Aus Nachbardateien nicht rekonstruierbar.' 'WARN'
    } else {
        Write-Log '  Keine passenden Datendateien im Ordner.' 'WARN'
    }

    # 2) Segmentdaten aus der PUP bzw. jeder gross genug Quellen holen
    Write-Log '  Versuche Daten aus der PUP zu holen.' 'WARN'
    if (Expand-TableFromPayload -TableFile $TableFile -Dest $Dest -Table $t -Digests $dig -BlockSize $bs -Need $need -SourceFile $SourceFile) { return $true }
    return $false
}

# ---------------------------------------------------------------------- PUP

function Expand-Pup {
    param([string]$Path, [string]$Dest)

    $pup = Get-PupIndex -Path $Path
    if (-not $pup) { return $false }
    $size = $pup.Size
    Write-Log ('  PUP: {0} Eintraege, header_size 0x{1:X}' -f $pup.EntryCount, $pup.HeaderSize)
    if (-not $pup.MagicOk) { Write-Log '  PUP-Magic weicht ab - Struktur wird trotzdem genutzt.' 'WARN' }
    if ($pup.Meta.Length -eq 0) { Write-Log '  Keine Metadata - Entschluesselung nicht moeglich.' 'WARN' }

    $done = 0
    foreach ($e in $pup.Entries) {
        if ($e.Offset -le 0 -or $e.CSize -le 0 -or (($e.Offset + $e.CSize) -gt $size)) { continue }
        $label = 'seg_{0:D3}_id{1:X}' -f $e.Index, $e.Id
        if ($e.Info) { $label += '_tbl' }
        if ($e.Comp) { $label += '_z' }
        $sfx = ''
        if ($e.Enc)  { $label += '_e'; $sfx = ', verschluesselt' }
        if ($e.Comp) { $sfx += ', komprimiert' }
        Write-Log ('  Segment {0}: id 0x{1:X}, {2:N0} Bytes{3}' -f $e.Index, $e.Id, $e.CSize, $sfx)

        $take = [int][Math]::Min($e.CSize, [long](536870912))
        if ($take -lt 16) { continue }
        $payload = [byte[]](Read-Bytes -Path $Path -Offset $e.Offset -Count $take)
        if ($payload.Length -lt 16) { continue }

        if ($e.Enc) {
            if ($pup.Meta.Length -eq 0) { Write-Log '    Keine Metadata vorhanden.' 'WARN'; continue }
            $kb = [byte[]]$pup.Meta[($e.Index * 0x50)..($e.Index * 0x50 + 0x0F)]
            $vb = [byte[]]$pup.Meta[($e.Index * 0x50 + 0x10)..($e.Index * 0x50 + 0x1F)]
            $plain = Invoke-AesDecrypt -Data $payload -Key $kb -Iv $vb
            if (-not $plain) { Write-Log '    Entschluesselung fehlgeschlagen.' 'WARN'; continue }
            $payload = $plain
        }

        $tmp = Join-Path $env:TEMP ('pup_' + [Guid]::NewGuid().ToString('N') + '.bin')
        [IO.File]::WriteAllBytes($tmp, $payload)
        $sub = New-OutDir -Base $Dest -Name $label
        $bt = Find-BlockTable -Path $tmp
        $got = $false
        if ($bt) {
            Write-Log '    Segment enthaelt eine Blocktabelle.' 'OK'
            $got = Expand-FromTable -TableFile $tmp -Dest $sub -Table $bt -SourceFile $Path
        } else {
            $got = Invoke-Container -File $tmp -Dest $sub -Depth 1
        }
        if (-not $got) {
            Copy-Item -LiteralPath $tmp -Destination (Join-Path $Dest ($label + '.bin')) -Force
            Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        $done++
    }
    Write-Log ('  {0} Segmente verarbeitet.' -f $done) 'OK'
    return ($done -gt 0)
}

# --------------------------------------------------------------------- SLB2

function Expand-Slb2 {
    param([string]$Path, [string]$Dest)
    $h = [byte[]](Read-Bytes -Path $Path -Offset 0 -Count 32)
    if ($h.Length -lt 32) { return $false }
    if ([Text.Encoding]::ASCII.GetString($h, 0, 4) -ne 'SLB2') { return $false }

    $count = [int][BitConverter]::ToUInt32($h, 12)
    $size  = [long](Get-Item -LiteralPath $Path).Length
    Write-Log ('  SLB2 mit {0} Eintraegen' -f $count)
    if ($count -eq 0 -or $count -gt 4096) { return $false }

    $tbl = [byte[]](Read-Bytes -Path $Path -Offset 32 -Count ([int]($count * 0x30)))
    if ($tbl.Length -lt 0x30) { return $false }

    $n = 0
    for ($i = 0; $i -lt $count; $i++) {
        $base = $i * 0x30
        if (($base + 0x30) -gt $tbl.Length) { break }
        $sector = [long][BitConverter]::ToUInt32($tbl, $base)
        $fsize  = [long][BitConverter]::ToUInt32($tbl, $base + 4)
        if ($fsize -eq 0) { continue }
        $name = ([Text.Encoding]::ASCII.GetString($tbl, $base + 16, 32)).Trim([char]0, ' ')
        $off = [long]($sector * 512)
        if ($off -ge $size) { continue }
        if (($off + $fsize) -gt $size) { $fsize = [long]($size - $off) }
        if (-not $name) { $name = 'entry_{0:D3}.bin' -f $i }
        $safe = Get-SafeName $name
        $outPath = Join-Path $Dest $safe
        $k = 1
        while (Test-Path -LiteralPath $outPath) { $outPath = Join-Path $Dest ('{0}_{1}' -f $safe, $k); $k++ }
        Copy-Range -Path $Path -Offset $off -Length $fsize -Dest $outPath
        $n++
        $script:Files++
        Write-Log ('  [SLB2] {0} ({1:N0} Bytes)' -f $name, $fsize) 'OK'
        if ($fsize -ge 0x100) {
            $ek = Get-FileKind -Path $outPath
            if ($ek -eq 'pup') {
                $sub = New-OutDir -Base $Dest -Name (Get-SafeName $name)
                if (-not (Invoke-Container -File $outPath -Dest $sub -Depth 2)) {
                    Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue
                }
            } elseif ($ek -eq 'raw') {
                Write-Log '    Fragment ist verschluesselt - mit pup_decrypt entschluesseln, dann hierauf anwenden.' 'WARN'
            }
        }
    }
    return ($n -gt 0)
}

# ------------------------------------------------------------- Slide-Library

function Expand-SlideLibrary {
    param([string]$Path, [string]$Dest)
    $len = [long](Get-Item -LiteralPath $Path).Length
    $fs  = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    $idx = 0
    $bad = 0
    try {
        $pos = [long]0
        while ($pos -lt $len) {
            if (($len - $pos) -lt 64) { break }
            $fs.Position = $pos
            $nameBuf = New-Object byte[] 32
            if ($fs.Read($nameBuf, 0, 32) -ne 32) { break }
            $name  = ([Text.Encoding]::ASCII.GetString($nameBuf)).Trim([char]0, ' ')
            $valid = $name.Length -gt 0
            if ($valid) {
                foreach ($ch in $name.ToCharArray()) {
                    if ([int]$ch -lt 0x20 -or [int]$ch -gt 0x7E) { $valid = $false; break }
                }
            }
            if ($valid) {
                $hdr = New-Object byte[] 32
                if ($fs.Read($hdr, 0, 32) -lt 32 -or $hdr[0] -ne 0x41) { $valid = $false }
            }
            if (-not $valid) {
                $pos++
                $bad++
                if ($bad -gt 8192) { break }
                continue
            }
            $bad = 0
            $start = [long]($fs.Position - 32)
            $end   = [long]0
            $ok    = $true
            $two   = New-Object byte[] 2
            while ($true) {
                if (($fs.Position + 2) -gt $len) { $ok = $false; break }
                if ($fs.Read($two, 0, 2) -ne 2) { $ok = $false; break }
                $op = [int]($two[0] -band 3)
                if ($op -eq 3) { $end = [long]$fs.Position; break }
                if (($fs.Position + 2) -gt $len) { $ok = $false; break }
                [void]$fs.Seek(2, 'Current')
            }
            if (-not $ok -or $end -le $start) { $pos++; continue }
            $idx++
            $safe = Get-SafeName $name
            $outPath = Join-Path $Dest ($safe + '.sld')
            $k = 1
            while (Test-Path -LiteralPath $outPath) {
                $outPath = Join-Path $Dest ('{0}_{1}.sld' -f $safe, $k)
                $k++
            }
            Copy-Range -Path $Path -Offset $start -Length ($end - $start) -Dest $outPath
            $script:Files++
            Write-Log ('  Slide {0} ({1:N0} Bytes)' -f (Split-Path $outPath -Leaf), ($end - $start)) 'OK'
            $pos = $end
        }
    } finally { $fs.Dispose() }
    return ($idx -gt 0)
}

# --------------------------------------------------------------------- exFAT

function Read-ChainBytes {
    param([string]$Path, [long]$First, [long]$Limit)
    $ms = New-Object System.IO.MemoryStream
    $c = $First
    $guard = 0
    while ($c -ge 2 -and $c -lt ($script:XFatClusterCount + 2) -and $guard -lt 100000) {
        $off = [long]$script:XFatHeapBase + (($c - 2) * $script:XFatClusterSize)
        if ($off -ge $script:XFatFileLen) { break }
        $take = [int][Math]::Min($script:XFatClusterSize, ($script:XFatFileLen - $off))
        $b = [byte[]](Read-Bytes -Path $Path -Offset $off -Count $take)
        if ($b.Length -le 0) { break }
        $ms.Write($b, 0, $b.Length)
        if ($Limit -gt 0 -and $ms.Length -ge $Limit) { break }
        if (-not $script:XFatFat) { break }
        $i = [int]($c * 4)
        if (($i + 4) -gt $script:XFatFat.Length) { break }
        $nx = [BitConverter]::ToUInt32($script:XFatFat, $i)
        if ($nx -ge 0xFFFFFFF8 -or $nx -eq $c) { break }
        $c = [long]$nx
        $guard++
    }
    return ,$ms.ToArray()
}

function Expand-ExFat {
    param([string]$Path, [string]$Dest)

    $bs = [byte[]](Read-Bytes -Path $Path -Offset 0 -Count 512)
    if ($bs.Length -lt 512) { return $false }
    if ([Text.Encoding]::ASCII.GetString($bs, 3, 5) -ne 'EXFAT') { return $false }

    $fatOffset   = [long][BitConverter]::ToUInt32($bs, 80)
    $fatLength   = [long][BitConverter]::ToUInt32($bs, 84)
    $heapOffset  = [long][BitConverter]::ToUInt32($bs, 88)
    $clusterCnt  = [long][BitConverter]::ToUInt32($bs, 92)
    $rootCluster = [long][BitConverter]::ToUInt32($bs, 96)
    $bps         = [int][Math]::Pow(2, [int]$bs[108])
    $spc         = [int][Math]::Pow(2, [int]$bs[109])

    if ($bps -lt 512 -or $bps -gt 4096) { return $false }
    if ($spc -lt 1 -or $spc -gt 32768) { return $false }
    if ($clusterCnt -eq 0 -or $rootCluster -lt 2) { return $false }

    $script:XFatClusterSize  = [long]$bps * $spc
    $script:XFatHeapBase     = [long]$heapOffset * $bps
    $script:XFatFileLen      = [long](Get-Item -LiteralPath $Path).Length
    $script:XFatClusterCount = [long]$clusterCnt
    $script:XFatFat          = $null

    $fatBytes = [long]$fatLength * $bps
    if ($fatBytes -gt 0 -and $fatBytes -le 134217728) {
        $f = [byte[]](Read-Bytes -Path $Path -Offset ([long]$fatOffset * $bps) -Count ([int]$fatBytes))
        if ($f.Length -gt 0) { $script:XFatFat = $f }
    }
    if (-not $script:XFatFat) { Write-Log '  FAT nicht ladbar - nehme zusammenhaengende Cluster an.' 'WARN' }
    if ($script:XFatHeapBase -ge $script:XFatFileLen) {
        Write-Log '  Cluster-Heap liegt ausserhalb der Datei - Image ist unvollstaendig.' 'WARN'
    }

    Write-Log ('  exFAT: {0} Byte/Cluster, {1} Cluster' -f $script:XFatClusterSize, $clusterCnt)

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([pscustomobject]@{ Cluster = [long]$rootCluster; Dir = $Dest; Depth = 0 })
    $extracted = 0
    $dirs = 0

    while ($queue.Count -gt 0 -and $extracted -lt 200000) {
        $job = $queue.Dequeue()
        $data = [byte[]](Read-ChainBytes -Path $Path -First $job.Cluster -Limit ([long](32MB)))
        if ($data.Length -lt 32) { continue }

        $i = 0
        while (($i + 32) -le $data.Length) {
            $t = [int]$data[$i]
            if ($t -eq 0x00) { break }
            if ($t -ne 0x85) { $i += 32; continue }

            $secCount = [int]$data[$i + 1]
            $attr     = [int][BitConverter]::ToUInt16($data, $i + 2)
            $stream   = -1
            $nameLen  = 0
            for ($k = 1; $k -le $secCount; $k++) {
                $j = $i + ($k * 32)
                if (($j + 32) -gt $data.Length) { break }
                if ($data[$j] -eq 0xC0) { $stream = $j; $nameLen = [int]$data[$j + 3] }
            }
            if ($stream -lt 0 -or $nameLen -le 0 -or $nameLen -gt 255) { $i += 32 * ($secCount + 1); continue }

            $sb = New-Object System.Text.StringBuilder
            for ($k = 1; $k -le $secCount -and $sb.Length -lt $nameLen; $k++) {
                $j = $i + ($k * 32)
                if (($j + 32) -gt $data.Length) { break }
                if ($data[$j] -ne 0xC1) { continue }
                $chars = [Math]::Min(15, ($nameLen - $sb.Length))
                [void]$sb.Append([Text.Encoding]::Unicode.GetString($data, $j + 2, ($chars * 2)))
            }
            $name  = $sb.ToString()
            $first = [long][BitConverter]::ToUInt32($data, $stream + 20)
            $dataLen = [long][BitConverter]::ToUInt64($data, $stream + 32)
            if ($dataLen -eq 0) { $dataLen = [long][BitConverter]::ToUInt64($data, $stream + 24) }
            $noFat = (($data[$stream + 1]) -band 0x02) -ne 0
            $step  = 32 * ($secCount + 1)

            if (($attr -band 0x08) -ne 0) { $i += $step; continue }

            if (($attr -band 0x10) -ne 0) {
                if ($job.Depth -lt 40 -and $first -ge 2) {
                    $sub = New-OutDir -Base $job.Dir -Name (Get-SafeName $name)
                    $dirs++
                    Write-Log ('  [DIR ] ' + $name) 'OK'
                    $queue.Enqueue([pscustomobject]@{ Cluster = [long]$first; Dir = $sub; Depth = $job.Depth + 1 })
                }
                $i += $step
                continue
            }
            if ($dataLen -eq 0 -or $first -lt 2) { $i += $step; continue }

            $safe = Get-SafeName $name
            $outPath = Join-Path $job.Dir $safe
            $n = 1
            while (Test-Path -LiteralPath $outPath) { $outPath = Join-Path $job.Dir ('{0}_{1}' -f $safe, $n); $n++ }
            $out = [IO.File]::Create($outPath)
            try {
                $remaining = [long]$dataLen
                $c = [long]$first
                $guard = 0
                while ($remaining -gt 0 -and $c -ge 2 -and $guard -lt 4000000) {
                    $off = [long]$script:XFatHeapBase + (($c - 2) * $script:XFatClusterSize)
                    if ($off -ge $script:XFatFileLen) { break }
                    $take = [int][Math]::Min($script:XFatClusterSize, $remaining)
                    if (($off + $take) -gt $script:XFatFileLen) { $take = [int]($script:XFatFileLen - $off) }
                    if ($take -le 0) { break }
                    $b = [byte[]](Read-Bytes -Path $Path -Offset $off -Count $take)
                    if ($b.Length -le 0) { break }
                    $out.Write($b, 0, $b.Length)
                    $remaining -= $b.Length
                    if ($noFat) { $c++ }
                    else {
                        if (-not $script:XFatFat) { break }
                        $fi = [int]($c * 4)
                        if (($fi + 4) -gt $script:XFatFat.Length) { break }
                        $nx = [BitConverter]::ToUInt32($script:XFatFat, $fi)
                        if ($nx -ge 0xFFFFFFF8 -or $nx -eq $c) { break }
                        $c = [long]$nx
                    }
                    $guard++
                }
            } finally { $out.Dispose() }

            $extracted++
            $script:Files++
            Write-Log ('  [FILE] {0} ({1:N0} Bytes)' -f $name, $dataLen)
            $i += $step
        }
    }

    Write-Log ('  exFAT fertig: {0} Dateien, {1} Ordner' -f $extracted, $dirs) 'OK'
    return ($extracted -gt 0)
}

# ------------------------------------------------------------------ Partitionen

function Get-Partitions {
    param([string]$Path, [string]$Kind)
    $parts = @()

    if ($Kind -eq 'gpt') {
        $hdr = [byte[]](Read-Bytes -Path $Path -Offset 512 -Count 92)
        if ($hdr.Length -lt 92) { return @() }
        $entryLba = [long][BitConverter]::ToUInt64($hdr, 72)
        $num      = [int][BitConverter]::ToUInt32($hdr, 80)
        $esz      = [int][BitConverter]::ToUInt32($hdr, 84)
        if ($esz -lt 128 -or $esz -gt 4096) { $esz = 128 }
        if ($num -gt 256) { $num = 256 }
        $tbl = [byte[]](Read-Bytes -Path $Path -Offset ([long]$entryLba * 512) -Count ([int]($num * $esz)))
        if ($tbl.Length -lt 128) { return @() }
        for ($i = 0; $i -lt $num; $i++) {
            $base = $i * $esz
            if (($base + $esz) -gt $tbl.Length) { break }
            $isZero = $true
            for ($j = 0; $j -lt 16; $j++) { if ($tbl[$base + $j] -ne 0) { $isZero = $false; break } }
            if ($isZero) { continue }
            $first = [long][BitConverter]::ToUInt64($tbl, $base + 32)
            $last  = [long][BitConverter]::ToUInt64($tbl, $base + 40)
            if ($last -lt $first) { continue }
            $parts += [pscustomobject]@{
                Index = $i + 1; Type = 'GPT'
                Offset = [long]($first * 512); Length = [long](($last - $first + 1) * 512)
                Label = ('partition{0}' -f ($i + 1))
            }
        }
        return $parts
    }

    $tbl = [byte[]](Read-Bytes -Path $Path -Offset 0x1BE -Count 64)
    if ($tbl.Length -lt 64) { return @() }
    $extBases = New-Object 'System.Collections.Generic.List[long]'

    for ($i = 0; $i -lt 4; $i++) {
        $base = $i * 16
        $type = [int]$tbl[$base + 4]
        if ($type -eq 0) { continue }
        if ($type -eq 0xEE) { return (Get-Partitions -Path $Path -Kind 'gpt') }
        $start = [long][BitConverter]::ToUInt32($tbl, $base + 8)
        $cnt   = [long][BitConverter]::ToUInt32($tbl, $base + 12)
        if ($cnt -eq 0) { continue }
        if ($type -eq 0x05 -or $type -eq 0x0F -or $type -eq 0x85) { $extBases.Add($start); continue }
        $parts += [pscustomobject]@{
            Index = $i + 1; Type = ('0x{0:X2}' -f $type)
            Offset = [long]($start * 512); Length = [long]($cnt * 512)
            Label = ('partition{0}_t{1:X2}' -f ($i + 1), $type)
        }
    }

    $guard = 0
    foreach ($eb in $extBases) {
        $ebr = $eb * 512
        while ($ebr -gt 0 -and $guard -lt 128) {
            $guard++
            $t = [byte[]](Read-Bytes -Path $Path -Offset ($ebr + 0x1BE) -Count 64)
            if ($t.Length -lt 64) { break }
            $ty = [int]$t[4]
            $s  = [long][BitConverter]::ToUInt32($t, 8)
            $c  = [long][BitConverter]::ToUInt32($t, 12)
            if ($ty -ne 0 -and $c -gt 0) {
                $parts += [pscustomobject]@{
                    Index = $parts.Count + 1; Type = ('logical 0x{0:X2}' -f $ty)
                    Offset = [long]($ebr + ($s * 512)); Length = [long]($c * 512)
                    Label = ('logical{0}' -f ($parts.Count + 1))
                }
            }
            $nt = [int]$t[20]
            $ns = [long][BitConverter]::ToUInt32($t, 24)
            if (($nt -eq 0x05 -or $nt -eq 0x0F -or $nt -eq 0x85) -and $ns -gt 0) { $ebr = ($eb + $ns) * 512 }
            else { break }
        }
    }
    return $parts
}

function Mount-And-Copy {
    param([string]$Path, [string]$Dest)
    $img = $null
    try {
        $img = Mount-DiskImage -ImagePath $Path -PassThru -ErrorAction Stop
        $vols = @($img | Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter })
        if ($vols.Count -eq 0) { throw 'Kein Laufwerksbuchstabe vergeben' }
        foreach ($v in $vols) {
            Copy-Item -Path ("{0}:\*" -f $v.DriveLetter) -Destination $Dest -Recurse -Force -ErrorAction SilentlyContinue
        }
        return $true
    } catch {
        Write-Log ('  Mount fehlgeschlagen: ' + $_.Exception.Message) 'WARN'
        return $false
    } finally {
        if ($img) { Dismount-DiskImage -ImagePath $Path -ErrorAction SilentlyContinue }
    }
}

# -------------------------------------------------------------------- Carving

function Invoke-Carve {
    param([string]$Path, [string]$Dest)
    $enc = [Text.Encoding]::GetEncoding(28591)
    $sigs = @(
        @{ Ext = 'jpg'; Pat = [byte[]](0xFF, 0xD8, 0xFF);          Max = 20971520 },
        @{ Ext = 'png'; Pat = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A); Max = 20971520 },
        @{ Ext = 'gif'; Pat = [byte[]](0x47, 0x49, 0x46, 0x38);    Max = 5242880 },
        @{ Ext = 'pdf'; Pat = [byte[]](0x25, 0x50, 0x44, 0x46, 0x2D); Max = 20971520 },
        @{ Ext = 'zip'; Pat = [byte[]](0x50, 0x4B, 0x03, 0x04);    Max = 52428800 },
        @{ Ext = 'ogg'; Pat = [byte[]](0x4F, 0x67, 0x67, 0x53);    Max = 20971520 },
        @{ Ext = 'wav'; Pat = [byte[]](0x52, 0x49, 0x46, 0x46);    Max = 20971520 },
        @{ Ext = 'mp3'; Pat = [byte[]](0x49, 0x44, 0x33);          Max = 20971520 }
    )
    $prep = foreach ($s in $sigs) { [pscustomobject]@{ Ext = $s.Ext; Pat = $enc.GetString($s.Pat); Max = [long]$s.Max } }
    $win  = [long](8MB)
    $size = [long](Get-Item -LiteralPath $Path).Length
    $hits = New-Object 'System.Collections.Generic.List[object]'

    Write-Log '  Carving laeuft...'
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        $buf = New-Object byte[] (8388608 + 8)
        $pos = [long]0
        while ($pos -lt $size -and $hits.Count -lt 20000) {
            [void]$fs.Seek($pos, 'Begin')
            $r = $fs.Read($buf, 0, $buf.Length)
            if ($r -le 0) { break }
            $txt = $enc.GetString($buf, 0, $r)
            foreach ($s in $prep) {
                $i = 0
                while (($i = $txt.IndexOf($s.Pat, $i, [StringComparison]::Ordinal)) -ge 0) {
                    $hits.Add([pscustomobject]@{ Offset = [long]($pos + $i); Ext = $s.Ext; Max = [long]$s.Max })
                    $i++
                }
            }
            $pos += $win
        }
    } finally { $fs.Dispose() }

    $sorted = @($hits | Sort-Object Offset)
    $n = 0
    for ($k = 0; $k -lt $sorted.Count; $k++) {
        $h = $sorted[$k]
        if ($h.Offset -lt 0 -or $h.Offset -ge $size) { continue }
        $nextOff = if (($k + 1) -lt $sorted.Count) { [long]$sorted[$k + 1].Offset } else { $size }
        $l = [long][Math]::Min(($nextOff - $h.Offset), $h.Max)
        if ($l -lt 16) { $l = [long][Math]::Min(16, ($size - $h.Offset)) }
        if ($l -le 0) { continue }
        $n++
        Copy-Range -Path $Path -Offset $h.Offset -Length $l -Dest (Join-Path $Dest ('carved_{0:D5}_{1:x8}.{2}' -f $n, $h.Offset, $h.Ext))
    }
    Write-Log ('  {0} Treffer ausgeschnitten.' -f $n) 'OK'
    return ($n -gt 0)
}

# ------------------------------------------------------------------ Dispatcher

function Expand-Unknown {
    param([string]$File, [string]$Dest, [int]$Depth)
    if ($Depth -lt 4) {
        $pi = Get-PupIndex -Path $File
        if ($pi) {
            Write-Log ('  PUP-Struktur erkannt: {0} Eintraege, header_size 0x{1:X}' -f $pi.EntryCount, $pi.HeaderSize) 'OK'
            if (Expand-Pup -Path $File -Dest $Dest) { return $true }
        }
        $bt = Find-BlockTable -Path $File
        if ($bt) {
            Write-Log '  Datei ist eine Blocktabelle, keine Bilddaten.' 'WARN'
            if (Expand-FromTable -TableFile $File -Dest $Dest -Table $bt -SourceFile $File) { return $true }
        }
        $emb = Find-Embedded -Path $File
        if ($emb) {
            Write-Log ('  Eingebetteter Container: {0} ab Offset 0x{1:X}' -f $emb.Kind, $emb.Offset) 'OK'
            $tmp = Join-Path $env:TEMP ('emb_' + [Guid]::NewGuid().ToString('N') + '.bin')
            Copy-Range -Path $File -Offset $emb.Offset -Length ([long]((Get-Item -LiteralPath $File).Length - $emb.Offset)) -Dest $tmp
            $sub = New-OutDir -Base $Dest -Name ('embedded_{0:x}' -f $emb.Offset)
            $got = Invoke-Container -File $tmp -Dest $sub -Depth ($Depth + 1)
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            if ($got) { return $true }
            Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Expand-ZlibBlocks -Path $File -Dest $Dest) { return $true }
        if (Expand-Other -Path $File -Dest $Dest) { return $true }
    }
    if (Invoke-SevenZip -Archive $File -Dest $Dest) { return $true }
    if ($Carve) { return (Invoke-Carve -Path $File -Dest $Dest) }
    return $false
}

function Invoke-Container {
    param([string]$File, [string]$Dest, [int]$Depth = 0)

    $k = Get-FileKind -Path $File
    switch ($k) {
        'pup'   { if (Expand-Pup -Path $File -Dest $Dest) { return $true }; return (Expand-Unknown -File $File -Dest $Dest -Depth $Depth) }
        'slb2'  { if (Expand-Slb2 -Path $File -Dest $Dest) { return $true }; return (Expand-Unknown -File $File -Dest $Dest -Depth $Depth) }
        'exfat' { if (Expand-ExFat -Path $File -Dest $Dest) { return $true }; return (Expand-Unknown -File $File -Dest $Dest -Depth $Depth) }
        { $_ -in 'fat', 'ntfs', 'ext' } {
            if (Invoke-SevenZip -Archive $File -Dest $Dest) { return $true }
            return (Expand-Unknown -File $File -Dest $Dest -Depth $Depth)
        }
        { $_ -in 'zip', '7z', 'rar', 'gzip', 'xz', 'bzip2' } {
            if (-not (Invoke-SevenZip -Archive $File -Dest $Dest)) { return $false }
            if ($Depth -lt 3) {
                Get-ChildItem -LiteralPath $Dest -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in '.img', '.slb', '.sld', '.bin', '.pup' } |
                    ForEach-Object { Invoke-Target -Path $_.FullName -Depth ($Depth + 1) }
            }
            return $true
        }
        { $_ -in 'iso', 'vhd', 'vhdx' } {
            if (Mount-And-Copy -Path $File -Dest $Dest) { return $true }
            if (Invoke-SevenZip -Archive $File -Dest $Dest) { return $true }
            return (Expand-Unknown -File $File -Dest $Dest -Depth $Depth)
        }
        { $_ -in 'mbr', 'gpt' } {
            $parts = @(Get-Partitions -Path $File -Kind $k)
            if ($parts.Count -eq 0) {
                Write-Log '  Keine Partitionseintraege lesbar.' 'WARN'
                return (Expand-Unknown -File $File -Dest $Dest -Depth $Depth)
            }
            $good = 0
            foreach ($p in $parts) {
                if ($p.Offset -le 0 -or $p.Length -le 0) { continue }
                $pf = Join-Path $Dest ('{0}.bin' -f $p.Label)
                Copy-Range -Path $File -Offset $p.Offset -Length $p.Length -Dest $pf
                $pk = Get-FileKind -Path $pf
                Write-Log ('  Partition {0} ({1}/{2}) -> {3} ({4:N0} Bytes)' -f $p.Index, $p.Type, $pk, (Split-Path $pf -Leaf), $p.Length) 'OK'
                $sub = New-OutDir -Base $Dest -Name ('{0}_files' -f $p.Label)
                $got = Invoke-Container -File $pf -Dest $sub -Depth ($Depth + 1)
                if ($got) { Write-Log ('  Inhalt von Partition {0} extrahiert.' -f $p.Index) 'OK'; $good++ }
                else { Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue }
                if (-not $KeepPartitions) { Remove-Item -LiteralPath $pf -Force -ErrorAction SilentlyContinue }
            }
            if ($good -eq 0 -and $Carve) {
                Write-Log '  Keine Partition auswertbar - Carving auf dem Gesamtimage.' 'WARN'
                return (Invoke-Carve -Path $File -Dest $Dest)
            }
            return ($good -gt 0)
        }
        default { return (Expand-Unknown -File $File -Dest $Dest -Depth $Depth) }
    }
}

function Invoke-Target {
    param([string]$Path, [int]$Depth = 0)

    try { $file = Get-Item -LiteralPath $Path -ErrorAction Stop } catch {
        Write-Log ('Nicht lesbar: ' + $Path) 'ERR'; $script:Fail++; return
    }
    if ($file.Length -eq 0) { Write-Log ('Leer: ' + $file.Name) 'WARN'; return }

    $ext  = $file.Extension.ToLowerInvariant()
    $kind = Get-FileKind -Path $Path
    if ($kind -eq 'raw' -and ($ext -eq '.slb' -or $ext -eq '.sld')) { $kind = 'slb' }
    Write-Log ('{0}  [{1}, {2:N0} Bytes]' -f $file.Name, $kind, $file.Length) 'HEAD'

    $dest = New-OutDir -Base $OutDir -Name (Get-SafeName $file.BaseName)

    if ($List) {
        if ($kind -eq 'raw') {
            $emb = Find-Embedded -Path $Path
            if ($emb) { Write-Log ('  Eingebettet: {0} ab 0x{1:X}' -f $emb.Kind, $emb.Offset) 'OK' }
            else { Write-Log '  Kein bekanntes Format erkannt.' 'WARN' }
        }
        Write-Probe -Path $Path -Dest $dest
        return
    }

    try {
        if ($kind -eq 'slb') {
            if ($ext -eq '.sld') {
                Copy-Item -LiteralPath $Path -Destination (Join-Path $dest $file.Name) -Force
                $script:Count++
                return
            }
            if (Expand-SlideLibrary -Path $Path -Dest $dest) { $script:Count++; return }
            if (Invoke-Container -File $Path -Dest $dest -Depth $Depth) { $script:Count++ }
            else { Write-Probe -Path $Path -Dest $dest; $script:Fail++ }
            return
        }

        if (Invoke-Container -File $Path -Dest $dest -Depth $Depth) { $script:Count++ }
        else {
            if ($kind -eq 'raw') { Write-Probe -Path $Path -Dest $dest }
            $script:Fail++
        }
    } catch {
        Write-Log ('  Fehler: ' + $_.Exception.Message) 'ERR'
        $script:Fail++
    }
}

# ----------------------------------------------------------------------- Main

$script:SevenZip = Find-SevenZip

$paths = @()
if ($env:IMGSLB_INPUT) { $paths = @($env:IMGSLB_INPUT -split '\|' | Where-Object { $_ }) }
if ($paths.Count -eq 0 -and $InputPath) { $paths = $InputPath }
$paths = @($paths | ForEach-Object { $_.Trim().Trim('"').Trim() } | Where-Object { $_ })
if ($paths.Count -eq 0) { Write-Log 'Kein Pfad uebergeben.' 'ERR'; exit 1 }

if (-not $OutDir) {
    $first = Resolve-Path -LiteralPath $paths[0] -ErrorAction SilentlyContinue
    $baseDir = if ($first) {
        $p = $first.Path
        if (Test-Path -LiteralPath $p -PathType Container) { $p } else { Split-Path -Parent $p }
    } else { (Get-Location).Path }
    $OutDir = Join-Path $baseDir '_extracted'
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$script:LogFile = Join-Path $OutDir ('log_{0}_{1}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), ([Guid]::NewGuid().ToString('N').Substring(0,6)))

Write-Log '=== IMG/SLB/PUP Extractor gestartet ===' 'HEAD'
Write-Log ('Ziel: ' + (Resolve-Path -LiteralPath $OutDir).Path)
if ($script:SevenZip) { Write-Log ('7-Zip: ' + $script:SevenZip) }

$targets = @()
foreach ($p in $paths) {
    $rp = Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue
    if (-not $rp) { Write-Log ('Pfad nicht gefunden: ' + $p) 'ERR'; $script:Fail++; continue }
    $item = Get-Item -LiteralPath $rp.Path
    if ($item.PSIsContainer) {
        $exts = '.img', '.slb', '.sld', '.pup', '.bin', '.dec', '.enc'
        if ($Recurse) {
            $targets += @(Get-ChildItem -LiteralPath $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in $exts } | ForEach-Object { $_.FullName })
        } else {
            $targets += @(Get-ChildItem -LiteralPath $item.FullName -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in $exts } | ForEach-Object { $_.FullName })
        }
    } else { $targets += $item.FullName }
}

if ($targets.Count -eq 0) {
    Write-Log 'Keine passenden Dateien gefunden.' 'WARN'
} else {
    foreach ($t in ($targets | Select-Object -Unique)) { Invoke-Target -Path $t }
}

Write-Log '=== Fertig ===' 'HEAD'
Write-Log ('Bearbeitet: {0}   Fehlgeschlagen: {1}   Dateien: {2}' -f $script:Count, $script:Fail, $script:Files)
Write-Log ('Protokoll: ' + $script:LogFile)
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }