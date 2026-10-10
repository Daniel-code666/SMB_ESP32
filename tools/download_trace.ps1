param(
    [string]$Address = "169.254.72.77",
    [int]$Port = 5000,
    [string]$Output = "C:\Users\Administrador\OneDrive\Documentos\Documentos\Things\Proyecto SMB\DUMP\smb-trace.bin"
)

$client = [System.Net.Sockets.TcpClient]::new()
try {
    $client.Connect($Address, $Port)
    $stream = $client.GetStream()
    $request = [System.Text.Encoding]::ASCII.GetBytes("TRACE DOWNLOAD`n")
    $stream.Write($request, 0, $request.Length)

    $outputPath = if ([System.IO.Path]::IsPathRooted($Output)) {
    $Output
	} else {
		Join-Path (Get-Location) $Output
	}

	$file = [System.IO.File]::Create($outputPath)
	
    try {
        $buffer = New-Object byte[] 8192
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $file.Write($buffer, 0, $read)
        }
    }
    finally {
        $file.Dispose()
    }
}
finally {
    $client.Dispose()
}

Write-Host "Traza guardada en $Output"
