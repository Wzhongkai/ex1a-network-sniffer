param(
    [Parameter(Mandatory)]
    [string]$Tshark,
    [string]$Dotnet = 'dotnet'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$checks = Join-Path $projectRoot 'tests/Sniffer.Checks/Sniffer.Checks.csproj'
& $Dotnet build $checks -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw 'Could not build the traffic fixture.' }

$extension = Join-Path $projectRoot 'artifacts/extcap/Sniffer.Extcap.exe'
if (-not (Test-Path -LiteralPath $extension)) { throw 'Run scripts/Publish.ps1 first.' }
$env:WIRESHARK_EXTCAP_DIR = Split-Path -Parent $extension
$env:WIRESHARK_CONFIG_DIR = Join-Path $projectRoot 'artifacts/wireshark-test-config'
New-Item -Path $env:WIRESHARK_CONFIG_DIR -ItemType Directory -Force | Out-Null
$loopbackId = [Convert]::ToHexString([Text.Encoding]::UTF8.GetBytes('loopback-v4')).ToLowerInvariant()
$interface = 'sniffer-' + $loopbackId
$preference = 'extcap.' + $interface.Replace('-', '_') + '.pid'
$dll = Join-Path $projectRoot 'tests/Sniffer.Checks/bin/Release/net10.0-windows/Sniffer.Checks.dll'
$dotnetPath = (Get-Command $Dotnet -CommandType Application).Source
$children = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

function Start-Fixture([string]$Arguments) {
    $parameters = @{
        FilePath = $dotnetPath
        ArgumentList = ('"{0}" {1}' -f $dll, $Arguments)
        WindowStyle = 'Hidden'
        PassThru = $true
    }
    $process = Start-Process @parameters
    $children.Add($process)
    return $process
}

for ($run = 1; $run -le 2; $run++) {
    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = $probe.LocalEndpoint.Port
    $probe.Stop()
    $trace = Join-Path $projectRoot "artifacts/extcap-test-$run.pcapng"
    try {
        Start-Fixture "serve 127.0.0.1 $port 3" | Out-Null
        $target = Start-Fixture "client 127.0.0.1 $port 2 4500 /target"
        $control = Start-Fixture "client 127.0.0.1 $port 1 4500 /control"
        & $Tshark -i $interface -f "tcp and port $port" -o "$($preference):$($target.Id)" -a duration:8 -w $trace
        if ($LASTEXITCODE -ne 0) { throw "TShark failed ($LASTEXITCODE)." }
        foreach ($process in $children) {
            if (-not $process.WaitForExit(18000) -or $process.ExitCode -ne 0) {
                throw "Traffic fixture failed: PID $($process.Id)."
            }
        }
        $requests = @(& $Tshark -r $trace -d "tcp.port==$port,http" -Y http.request -T fields -e http.request.uri)
        if ($LASTEXITCODE -ne 0 -or $requests.Count -ne 2 -or '/target/0' -notin $requests -or '/target/1' -notin $requests) {
            throw "Unexpected HTTP requests: $requests"
        }
        Write-Output "PASS run $run, target PID $($target.Id), control PID $($control.Id), requests $($requests -join ', ')."
    }
    finally {
        foreach ($process in $children) {
            if (-not $process.HasExited) { $process.Kill() }
            $process.Dispose()
        }
        $children.Clear()
    }
}
