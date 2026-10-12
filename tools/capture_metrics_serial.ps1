param(
    [string]$Port,
    [int]$BaudRate = 115200,
    [string]$Output = "C:\Users\Administrador\OneDrive\Documentos\Documentos\Things\Proyecto SMB\DUMP\smb-metrics.bin",
    [string]$ProfileOutput = "C:\Users\Administrador\OneDrive\Documentos\Documentos\Things\Proyecto SMB\DUMP\sd-profile.txt"
)

$availablePorts = @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
if ([string]::IsNullOrWhiteSpace($Port)) {
    if ($availablePorts.Count -eq 1) {
        $Port = $availablePorts[0]
        Write-Host "Puerto detectado automáticamente: $Port" -ForegroundColor Cyan
    }
    elseif ($availablePorts.Count -eq 0) {
        throw 'No hay puertos serie disponibles. Conecte el ESP32 por USB y compruebe el Administrador de dispositivos.'
    }
    else {
        throw "Hay varios puertos disponibles: $($availablePorts -join ', '). Ejecute nuevamente indicando -Port COMx."
    }
}
elseif ($availablePorts -notcontains $Port.ToUpperInvariant()) {
    $visible = if ($availablePorts.Count -eq 0) { 'ninguno' } else { $availablePorts -join ', ' }
    throw "El puerto '$Port' no existe. Puertos disponibles: $visible"
}

$serial = [System.IO.Ports.SerialPort]::new($Port, $BaudRate, 'None', 8, 'One')
$serial.NewLine = "`n"
$serial.ReadTimeout = 100
$serial.WriteTimeout = 1000
$serial.DtrEnable = $false
$serial.RtsEnable = $false
$dump = [System.IO.MemoryStream]::new()
$capturing = $false
$expectedBytes = 0
$expectedCrc = $null
$profileLines = [System.Collections.Generic.List[string]]::new()
$profiling = $false
$screenPhase = 0
$screenPhases = @('SCREEN_MAGENTA_1', 'SCREEN_GREEN', 'SCREEN_MAGENTA_2', 'SCREEN_YELLOW')

function Send-Command([string]$Command) {
    $serial.Write("$Command`n")
    Write-Host "-> $Command" -ForegroundColor Cyan
}

function Add-HexLine([string]$Hex) {
    if (($Hex.Length % 2) -ne 0) { throw "Línea hexadecimal de longitud impar" }
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $dump.WriteByte([Convert]::ToByte($Hex.Substring($i, 2), 16))
    }
}

function Save-Dump {
    $fullPath = [System.IO.Path]::GetFullPath($Output)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    $bytes = $dump.ToArray()
    if ($expectedBytes -ne 0 -and $bytes.Length -ne $expectedBytes) {
        throw "Captura incompleta: recibidos=$($bytes.Length), esperados=$expectedBytes"
    }
    [System.IO.File]::WriteAllBytes($fullPath, $bytes)
    if ($null -ne $expectedCrc) {
        [System.IO.File]::WriteAllText("$fullPath.crc32", $expectedCrc)
    }
    Write-Host "Captura guardada: $fullPath ($($bytes.Length) bytes)" -ForegroundColor Green
}

function Save-Profile {
    $fullPath = [System.IO.Path]::GetFullPath($ProfileOutput)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    [System.IO.File]::WriteAllLines($fullPath, $profileLines, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Perfil SD guardado: $fullPath" -ForegroundColor Green
}

function Show-Help {
    Write-Host @"
Teclas (mantenga esta ventana abierta desde antes de arrancar la PS2):
  S  METRICS START             I  METRICS INFO
  F  METRICS FREEZE            D  METRICS DUMP y guardar
  L  inicio de carga del juego R  juego ejecutándose
  V  siguiente pantalla (magenta, verde, magenta, amarillo)
  C  iniciar captura de cinemática (limpia y marca inicio)
  T  marcar stutter visible
  E  terminar y congelar captura de cinemática
  P  marcar gameplay normal    H  mostrar esta ayuda
  B  perfil SD automático (solo con SMB desconectado)
  Q  salir

"@
}

try {
    $serial.Open()
    Write-Host "Puerto $Port abierto a $BaudRate baud. Abrirlo puede reiniciar algunas placas; espere el arranque si ocurre." -ForegroundColor Yellow
    Show-Help
    $running = $true
    while ($running) {
        try {
            $line = $serial.ReadLine().TrimEnd("`r")
            if ($line.StartsWith('METRICS_DUMP_BEGIN ')) {
                $capturing = $true
                $dump.SetLength(0)
                if ($line -match 'bytes=(\d+)') { $expectedBytes = [int]$Matches[1] }
                if ($line -match 'crc32=([0-9A-Fa-f]{8})') { $expectedCrc = $Matches[1].ToUpperInvariant() }
                Write-Host $line -ForegroundColor Magenta
            }
            elseif ($capturing -and $line.StartsWith('METRICS_DATA ')) {
                Add-HexLine $line.Substring(13).Trim()
            }
            elseif ($line.StartsWith('METRICS_DUMP_END ')) {
                $capturing = $false
                Save-Dump
            }
            else {
                Write-Host $line
                if ($line.StartsWith('SD_PROFILE_BEGIN ')) {
                    $profileLines.Clear()
                    $profiling = $true
                }
                if ($profiling) {
                    $profileLines.Add($line)
                    if ($line.StartsWith('SD_PROFILE_END ')) {
                        Save-Profile
                        $profiling = $false
                    }
                }
            }
        }
        catch [System.TimeoutException] { }

        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true).Key
            switch ($key) {
                'S' { Send-Command 'METRICS START' }
                'I' { Send-Command 'METRICS INFO' }
                'F' { Send-Command 'METRICS FREEZE' }
                'D' { Send-Command 'METRICS DUMP' }
                'L' { $screenPhase = 0; Send-Command 'MARK GAME_LOAD_START' }
                'V' {
                    Send-Command "MARK $($screenPhases[$screenPhase % $screenPhases.Count])"
                    $screenPhase++
                }
                'R' { Send-Command 'MARK GAME_RUNNING' }
                'C' {
                    Send-Command 'METRICS START'
                    Send-Command 'MARK CINEMATIC_START'
                }
                'T' { Send-Command 'MARK CINEMATIC_STUTTER' }
                'E' {
                    Send-Command 'MARK CINEMATIC_END'
                    Send-Command 'METRICS FREEZE'
                }
                'P' { Send-Command 'MARK GAMEPLAY' }
                'B' { Send-Command 'SD PROFILE' }
                'H' { Show-Help }
                'Q' { $running = $false }
            }
        }
    }
}
finally {
    $dump.Dispose()
    if ($serial.IsOpen) { $serial.Close() }
    $serial.Dispose()
}
