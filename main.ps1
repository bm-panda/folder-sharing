param([string]$ParamPath, [switch]$ElevatedChild, [string]$ResultFile)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function New-Unc([string]$Computer, [string]$ShareName) {
    return "\\" + $Computer + "\" + $ShareName
}

function Grant-NtfsShareAcl([string]$Path, [string]$Perm) {
    $right = if ($Perm -eq "full") { "(OI)(CI)(M)" } else { "(OI)(CI)(RX)" }
    try {
        $r = & icacls $Path /grant "*S-1-1-0:$right" 2>&1
        if ($LASTEXITCODE -eq 0) { return "[NTFS] $Path 已添加 Everyone $right" }
        return "[NTFS][WARN] $Path : $r"
    } catch {
        return "[NTFS][WARN] $Path : $($_.Exception.Message)"
    }
}

function Ensure-ShareEnvironment([bool]$EnableGuest) {
    $out = @()

    # 1) 网络配置文件：公用 -> 专用
    try {
        $pub = @(Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -ne 'Private' })
        if ($pub.Count -eq 0) {
            $out += "[ENV] 网络配置文件均为专用，无需修改"
        } else {
            foreach ($p in $pub) {
                Set-NetConnectionProfile -InterfaceAlias $p.InterfaceAlias -NetworkCategory Private
                $out += "[ENV] 网络 '$($p.Name)'（$($p.InterfaceAlias)）已由$($p.NetworkCategory)改为专用"
            }
        }
    } catch {
        $out += "[ENV][WARN] 网络配置文件处理失败: $($_.Exception.Message)"
    }

    # 2) 防火墙组：网络发现 / 文件和打印机共享（显示名随系统语言，中英候选）
    $groupPairs = @(
        ,@("网络发现", "Network Discovery")
        ,@("文件和打印机共享", "File and Printer Sharing")
    )
    foreach ($pair in $groupPairs) {
        $rules = @()
        $hit = ""
        foreach ($gn in $pair) {
            try {
                $r = @(Get-NetFirewallRule -DisplayGroup $gn -ErrorAction SilentlyContinue)
                if ($r.Count -gt 0) { $rules = $r; $hit = $gn; break }
            } catch {}
        }
        if ($rules.Count -eq 0) {
            $out += "[ENV][WARN] 未找到防火墙组 '$($pair[0])'，请手动检查防火墙"
            continue
        }
        try {
            $off = @($rules | Where-Object { "$($_.Enabled)" -eq "False" })
            if ($off.Count -eq 0) {
                $out += "[ENV] 防火墙组 '$hit' 已启用，无需修改"
            } else {
                $off | Enable-NetFirewallRule
                $out += "[ENV] 防火墙组 '$hit' 已启用 $($off.Count)/$($rules.Count) 条规则"
            }
        } catch {
            $out += "[ENV][WARN] 启用防火墙组 '$hit' 失败: $($_.Exception.Message)"
        }
    }

    # 3) 发现服务：FDResPub / fdPHost
    foreach ($svc in @("FDResPub", "fdPHost")) {
        try {
            $s = Get-Service -Name $svc -ErrorAction Stop
            if ($s.Status -ne "Running") {
                Set-Service -Name $svc -StartupType Automatic
                Start-Service -Name $svc
                $out += "[ENV] 服务 $svc 已启动（自动）"
            } else {
                $out += "[ENV] 服务 $svc 已在运行"
            }
        } catch {
            $out += "[ENV][WARN] 服务 $svc 处理失败: $($_.Exception.Message)"
        }
    }

    # 4) 来宾账户（免密访问开关）
    if ($EnableGuest) {
        try {
            $null = net user guest /active:yes 2>&1
            if ($LASTEXITCODE -eq 0) {
                $out += "[ENV] 来宾(Guest)账户已启用，局域网设备可免密访问"
                $out += "[ENV][提示] 若访问方 Win10/11 提示组策略阻止来宾登录，在对方电脑管理员运行: reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation /v AllowInsecureGuestAuth /t REG_DWORD /d 1 /f"
            } else {
                $out += "[ENV][WARN] 启用来宾账户失败（可能非管理员），请以管理员重试"
            }
        } catch {
            $out += "[ENV][WARN] 启用来宾账户异常: $($_.Exception.Message)"
        }
    } else {
        $out += "[ENV] 免密访问未开启：他机访问时需输入本机账号密码"
    }

    return $out
}

function Write-Envelope([string]$OutPath, [int]$Code, [string]$Msg, $SharePaths, [string]$Summary) {
    $envObj = [ordered]@{ code = $Code; msg = $Msg }
    if ($SharePaths) { $envObj["share_paths"] = @($SharePaths) } else { $envObj["share_paths"] = @() }
    $envObj["summary"] = $Summary
    Write-Utf8NoBom $OutPath ($envObj | ConvertTo-Json -Depth 5)
}

try {
    if (-not $ParamPath -or -not (Test-Path $ParamPath)) { throw "缺少参数文件" }
    $payload = Get-Content $ParamPath -Raw -Encoding UTF8 | ConvertFrom-Json

    $boxEnv = $payload.environment
    $invokeMode = $boxEnv.invoke_mode
    $outputJson = $boxEnv.output_json

    $folders = @()
    if ($payload.data -and $payload.data.folder_paths) { $folders = @($payload.data.folder_paths) }

    $action = "share"
    if ($payload.params -and $payload.params.action) { $action = [string]$payload.params.action }
    $permission = "read"
    if ($payload.params -and $payload.params.permission) { $permission = [string]$payload.params.permission }
    $shareNameInput = ""
    if ($payload.params -and $payload.params.share_name) { $shareNameInput = [string]$payload.params.share_name }
    $guestAccess = $true
    if ($payload.params -and ($payload.params.psobject.Properties.Name -contains "guest_access")) { $guestAccess = [bool]$payload.params.guest_access }

    # 非管理员时 UAC 提权、隐藏子窗口执行，结果经临时文件回传父进程打印（只保留盒子一个终端）
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $self = $PSCommandPath
        $tmpResult = if ($ResultFile) { $ResultFile } else { Join-Path ([IO.Path]::GetTempPath()) ("bmshare_elev_" + [guid]::NewGuid().ToString("N") + ".json") }
        $psi = Start-Process powershell -Verb RunAs -PassThru -Wait -WindowStyle Hidden -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$self`"", "`"$ParamPath`"", "-ElevatedChild", "-ResultFile", "`"$tmpResult`""
        )
        if (Test-Path $tmpResult) {
            try {
                $r = Get-Content $tmpResult -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($r.output) { Write-Host $r.output }
                Remove-Item $tmpResult -Force -ErrorAction SilentlyContinue
                if ($invokeMode -eq "manual") { Read-Host "`n按回车键关闭窗口" | Out-Null }
                exit ([int]$r.code)
            } catch {}
        }
        if ($psi.ExitCode -ne 0) { Write-Host "[错误] 提权进程退出码 $($psi.ExitCode)" }
        if ($invokeMode -eq "manual") { Read-Host "`n按回车键关闭窗口" | Out-Null }
        exit $psi.ExitCode
    }

    $pc = $env:COMPUTERNAME
    $uncList = @()
    $lines = @()
    $failed = 0

    function Get-RealPath([string]$p) {
        $item = Get-Item -LiteralPath $p -Force
        if ($item -is [System.IO.DirectoryInfo]) { return $item.FullName.TrimEnd('\') }
        return $item.Directory.FullName.TrimEnd('\')
    }

    switch ($action) {
        "share" {
            if ($folders.Count -eq 0) { throw "未选择文件夹，请在盒子里选中文件夹后运行，或在启动窗口中选择" }
            foreach ($f in $folders) {
                try {
                    $real = Get-RealPath $f
                    $leaf = Split-Path $real -Leaf
                    $name = if ($shareNameInput) { $shareNameInput } else { $leaf }
                    $name = ($name -replace '[\\/:*?"<>|]', "").Trim().TrimEnd('.')
                    if (-not $name) { $name = "Shared" }

                    $exist = Get-SmbShare -Name $name -ErrorAction SilentlyContinue
                    if ($exist) { Remove-SmbShare -Name $name -Force }

                    $unc = New-Unc $pc $name
                    if ($permission -eq "full") {
                        New-SmbShare -Name $name -Path $real -FullAccess "Everyone" -Description "局域网共享" | Out-Null
                        $lines += "[OK] $real -> $unc（读写）"
                    } else {
                        New-SmbShare -Name $name -Path $real -ReadAccess "Everyone" -Description "局域网共享" | Out-Null
                        $lines += "[OK] $real -> $unc（只读）"
                    }
                    $lines += (Grant-NtfsShareAcl $real $permission)
                    $uncList += $unc
                } catch {
                    $failed++
                    $lines += "[FAIL] $f -> $($_.Exception.Message)"
                }
            }
            if ($uncList.Count -gt 0) { $lines += (Ensure-ShareEnvironment $guestAccess) }
        }
        "unshare" {
            if ($folders.Count -eq 0) { throw "未选择文件夹" }
            foreach ($f in $folders) {
                try {
                    $real = Get-RealPath $f
                    $matched = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Path.TrimEnd('\') -eq $real })
                    if ($matched.Count -eq 0) {
                        $lines += "[SKIP] $real 当前未共享"
                        continue
                    }
                    foreach ($s in $matched) {
                        Remove-SmbShare -Name $s.Name -Force
                        $lines += "[OK] 已取消共享 $real（共享名：$($s.Name)）"
                    }
                } catch {
                    $failed++
                    $lines += "[FAIL] $f -> $($_.Exception.Message)"
                }
            }
        }
        "list" {
            $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*$' })
            if ($shares.Count -eq 0) {
                $lines += "当前没有可见的局域网共享"
            } else {
                $lines += ("{0,-24}{1,-40}路径" -f "共享名", "权限")
                foreach ($s in $shares) {
                    $aces = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)
                    $perm = ($aces | ForEach-Object { "$($_.Name):$($_.AccessRight)" }) -join ", "
                    $lines += ("{0,-24}{1,-40}{2}" -f $s.Name, $perm, $s.Path)
                    $uncList += (New-Unc $pc $s.Name)
                }
            }
        }
        default { throw "未知操作：$action" }
    }

    $summary = $lines -join "`n"

    if ($invokeMode -eq "node" -and $outputJson) {
        if ($failed -gt 0) {
            Write-Envelope $outputJson 1 "有 $failed 项处理失败" $uncList $summary
        } else {
            Write-Envelope $outputJson 0 "ok" $uncList $summary
        }
    }

    if ($ElevatedChild -and $ResultFile) {
        # 提权子进程：结果写临时文件，由父进程（盒子终端）统一打印
        $display = $summary
        if ($action -eq "share" -and $uncList.Count -gt 0 -and $invokeMode -ne "node") {
            $display += "`n`n局域网其他设备可在资源管理器地址栏输入：$(New-Unc $pc '<共享名>') 访问"
        }
        $res = [ordered]@{ code = $failed; output = $display }
        Write-Utf8NoBom $ResultFile ($res | ConvertTo-Json -Depth 3)
    } elseif ($invokeMode -ne "node") {
        Write-Host $summary
        if ($action -eq "share" -and $uncList.Count -gt 0) {
            Write-Host ""
            Write-Host "局域网其他设备可在资源管理器地址栏输入：$(New-Unc $pc '<共享名>') 访问"
        }
        # 已是管理员、无需提权时由本进程直接打印，同样暂停
        if (-not $ElevatedChild -and $invokeMode -eq "manual") { Read-Host "`n按回车键关闭窗口" | Out-Null }
    }
    exit $failed
} catch {
    $msg = $_.Exception.Message
    if ($boxEnv -and $boxEnv.invoke_mode -eq "node" -and $boxEnv.output_json) {
        try { Write-Envelope $boxEnv.output_json 1 $msg @() $msg } catch {}
    }
    if ($ElevatedChild -and $ResultFile) {
        try {
            $res = [ordered]@{ code = 1; output = "[错误] $msg" }
            Write-Utf8NoBom $ResultFile ($res | ConvertTo-Json -Depth 3)
        } catch {}
    } else {
        Write-Host "[错误] $msg"
        if ($invokeMode -eq "manual") { Read-Host "`n按回车键关闭窗口" | Out-Null }
    }
    exit 1
}
