param(
    [string]$Dotnet = 'dotnet'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

function Publish-SnifferProject {
    param([string]$Project, [string]$Output)
    $projectFile = Join-Path $projectRoot $Project
    $outputDirectory = Join-Path $projectRoot $Output
    $publishArguments = @('publish', $projectFile, '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
        '-p:PublishSingleFile=true', '-p:DebugType=None', '-o', $outputDirectory, '--nologo')
    & $Dotnet @publishArguments
    if ($LASTEXITCODE -ne 0) { throw "Publish failed: $projectFile ($LASTEXITCODE)" }
}

Publish-SnifferProject 'src/Sniffer.Desktop/Sniffer.Desktop.csproj' 'artifacts/release'
Publish-SnifferProject 'src/Sniffer.Extcap/Sniffer.Extcap.csproj' 'artifacts/extcap'

$artifacts = Join-Path $projectRoot 'artifacts'
$licenses = Join-Path $artifacts 'licenses'
New-Item -ItemType Directory -Force -Path $licenses | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'vendor/WinDivert/LICENSE') -Destination (Join-Path $licenses 'WinDivert-LICENSE.txt') -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'vendor/WinDivert/WinDivert-2.2.2-source.zip') -Destination $licenses -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'vendor/第三方组件.md') -Destination $licenses -Force
$assetsFile = Join-Path $projectRoot 'src/Sniffer.Desktop/obj/project.assets.json'
$assets = Get-Content -Raw -LiteralPath $assetsFile | ConvertFrom-Json
$packs = $assets.project.frameworks.'net10.0-windows'.downloadDependencies
foreach ($name in @('Microsoft.NETCore.App.Runtime.win-x64', 'Microsoft.WindowsDesktop.App.Runtime.win-x64')) {
    $pack = $packs | Where-Object { $_.name -eq $name } | Select-Object -First 1
    if (-not $pack) { throw "Runtime pack $name was not resolved." }
    $version = (($pack.version -split ',')[0]).Trim([char[]]'[] ')
    $path = $assets.packageFolders.PSObject.Properties.Name |
        ForEach-Object { Join-Path $_ ($name.ToLowerInvariant() + '/' + $version) } |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $path) { throw "Runtime pack $name $version was not found." }
    Get-ChildItem -LiteralPath $path -File | Where-Object { $_.Name -match '^(LICENSE|THIRD.PARTY.NOTICES)(\.TXT)?$' } |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $licenses "$name-$($_.Name)") -Force }
}

$instructions = Join-Path $artifacts '运行说明.md'
@'
# 实验 1A 网络嗅探器

在 Windows 11 x64 上解压完整 ZIP，保留 release 文件夹中的全部文件，再打开 release/Sniffer.Desktop.exe。

- 离线演示可点「载入演示流量」，再从报文列表上方的「协议筛选」选 HTTP、DNS、TLS 等协议。
- 接口旁的曲线在开始抓包前显示收发速率。「显示设置」可编辑着色规则和 DNS 主机名开关，「连接汇总」查看本机及远端、端口、流量与进程。
- 实时抓包时选好接口，点「以管理员身份捕获」并同意 Windows 提示。实体网卡使用 Windows Packet Monitor。IPv4 回环用 Winsock，IPv6 回环和短连接进程事件使用随包附带的 WinDivert。
- 选择 TLS 报文，点「跟踪所选 TCP 流」并切换到「TLS 记录与证书」。解密 TLS 1.3 时选取该会话对应的 SSLKEYLOGFILE。
- extcap 文件夹用于 Wireshark 的可选 PID 捕获扩展，复制其中的 exe、dll、sys 到个人 extcap 目录，以管理员身份启动 Wireshark。
'@ | Set-Content -LiteralPath $instructions -Encoding utf8

$archive = Join-Path $artifacts 'Sniffer-EX1A-Windows-x64.zip'
$contents = @((Join-Path $artifacts 'release'), (Join-Path $artifacts 'extcap'), $licenses, $instructions)
Compress-Archive -LiteralPath $contents -DestinationPath $archive -Force
Write-Output $archive
