# Required Notice: Copyright Matthew Armstrong (https://github.com/The-Dorkknight)
# Licensed under the PolyForm Noncommercial License 1.0.0. No warranty.
<#
  find_lizard_calib.ps1 - gathers the CR-Scan Lizard calibration file(s) that JM Studio / CR Studio
  saved on this Windows machine, so you can copy them out in one go.

  Run AFTER connecting the scanner in JM Studio at least once:
    powershell -ExecutionPolicy Bypass -File find_lizard_calib.ps1 -Serial YOURSERIAL

  Result: Desktop\LIZCAL\LIZCAL_###_<original name> + LIZCAL_000_index.txt, and Desktop\LIZCAL.zip
  Then on Linux:  python3 whoareyousb.py find-calib LIZCAL/   (checks which one holds the camera maths)

  Read-only: it only copies files, never changes or deletes anything.
#>
param(
    [string]$Serial = "",          # printed on the scanner / shown in JM Studio; optional but helps a lot
    [double]$Days = 3,             # only files changed in the last N days (0 = any age)
    [string]$Out = (Join-Path ([Environment]::GetFolderPath("Desktop")) "LIZCAL")
)

$roots = @($env:APPDATA, $env:LOCALAPPDATA, $env:PROGRAMDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)},
           [Environment]::GetFolderPath("MyDocuments")) | Where-Object { $_ -and (Test-Path $_) }
$vendorRx = 'jmstudio|jm studio|jimu|3dmakerpro|creality|crstudio|cr studio|cr-studio|scan'
$nameRx   = 'calib|param|camera|intrin|extrin|stereo|sensor|device'
$skipExt  = '.dll','.exe','.sys','.ttf','.otf','.png','.jpg','.jpeg','.ico','.mui','.cat','.manifest',
            '.nls','.pdb','.lnk','.mp4','.msi','.cab','.tlb','.drv','.ocx','.ax','.qm','.pak','.obj','.stl','.ply'
$since = if ($Days -gt 0) { (Get-Date).AddDays(-$Days) } else { [datetime]::MinValue }
$latin1 = [Text.Encoding]::GetEncoding(28591)
$serialUtf16 = if ($Serial) { ($Serial.ToCharArray() | ForEach-Object { "$_`0" }) -join '' } else { $null }

New-Item -ItemType Directory -Force -Path $Out | Out-Null
Write-Host "Searching: $($roots -join ', ')"
if ($Serial) { Write-Host "Looking inside files for serial '$Serial' (ASCII + UTF-16)" }

$n = 0
$index = @("copied_name`toriginal_path`tbytes`tmodified`treason")
foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.FullName -notmatch '\\(Windows|WinSxS|Microsoft|Packages)\\' -and
        $skipExt -notcontains $_.Extension.ToLower() -and
        $_.Length -ge 32 -and $_.Length -le 50MB -and
        $_.LastWriteTime -ge $since
    } | ForEach-Object {
        $f = $_
        $reasons = @()
        if ($f.Name -match $nameRx) { $reasons += "name" }
        if ($Serial -and $f.Name -like "*$Serial*") { $reasons += "serial-in-name" }
        if ($f.FullName -match $vendorRx) { $reasons += "vendor-folder" }
        if ($Serial -and $f.Length -le 20MB) {
            try {
                $s = $latin1.GetString([IO.File]::ReadAllBytes($f.FullName))
                if ($s.Contains($Serial) -or $s.Contains($serialUtf16)) { $reasons += "serial-in-file" }
            } catch { }
        }
        # keep: anything mentioning the serial, calibration-ish names, or recent files in the vendor's folders
        $keep = ($reasons -contains "serial-in-file") -or ($reasons -contains "serial-in-name") -or
                ($reasons -contains "name" -and $reasons -contains "vendor-folder") -or
                ($reasons -contains "vendor-folder" -and $Days -gt 0)
        if ($keep) {
            $n++
            $dst = "LIZCAL_{0:D3}_{1}" -f $n, $f.Name
            try {
                Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $Out $dst) -ErrorAction Stop
                $index += "$dst`t$($f.FullName)`t$($f.Length)`t$($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))`t$($reasons -join ',')"
                Write-Host ("  {0}  <- {1}  [{2}]" -f $dst, $f.FullName, ($reasons -join ','))
            } catch { $n--; Write-Host "  (skipped, in use: $($f.FullName))" }
        }
    }
}
$index | Set-Content -Path (Join-Path $Out "LIZCAL_000_index.txt") -Encoding UTF8
$zip = "$Out.zip"
if (Test-Path $zip) { Remove-Item $zip }
if ($n -gt 0) { Compress-Archive -Path (Join-Path $Out '*') -DestinationPath $zip }
Write-Host ""
if ($n -gt 0) {
    Write-Host "Copied $n file(s) to $Out and zipped them to $zip"
    Write-Host "Copy LIZCAL.zip to Linux, unzip, then:  python3 whoareyousb.py find-calib LIZCAL/"
} else {
    Write-Host "Nothing found. Connect the scanner in JM Studio first, add -Serial, or try -Days 0."
}
