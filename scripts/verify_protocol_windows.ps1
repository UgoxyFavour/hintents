$ErrorActionPreference = "Stop"

$protocol = if ($env:ERST_PROTOCOL_NAME) { $env:ERST_PROTOCOL_NAME } else { "erst" }
$cliPath = if ($args.Length -gt 0 -and $args[0]) { $args[0] } elseif ($env:ERST_CLI_PATH) { $env:ERST_CLI_PATH } else { $null }
$regPath = "HKCU:\Software\Classes\$protocol"
$commandRegPath = "HKCU\Software\Classes\$protocol\shell\open\command"

function Assert-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [scriptblock]$Validator,
        [string]$SuccessMessage,
        [string]$FailureMessage
    )

    try {
        $value = (Get-ItemProperty -Path $Path -Name $Name).$Name
        if (& $Validator $value) {
            Write-Host "[OK] $SuccessMessage"
            return $true
        }

        Write-Error "$FailureMessage. Actual value: $value"
        return $false
    } catch {
        Write-Error "$FailureMessage. $($_.Exception.Message)"
        return $false
    }
}

$allPassed = $true

if (Test-Path $regPath) {
    Write-Host "[OK] Registry key exists at $regPath"
} else {
    Write-Error "Registry key does not exist at $regPath"
    $allPassed = $false
}

$allPassed = (Assert-RegistryValue -Path $regPath -Name "URL Protocol" -Validator { param($v) $null -ne $v } -SuccessMessage "URL Protocol value exists" -FailureMessage "URL Protocol value is missing") -and $allPassed

try {
    $commandOutput = reg query $commandRegPath /ve
    $expectedCommand = if ($cliPath) { "`"$cliPath`" protocol-handler `"%1`"" } else { $null }

    if (($expectedCommand -and $commandOutput -match [regex]::Escape($expectedCommand)) -or (-not $expectedCommand -and $commandOutput -match "protocol-handler" -and $commandOutput -match "%1")) {
        Write-Host "[OK] Open command is correctly configured"
    } else {
        Write-Error "Open command is not correctly configured. Output: $commandOutput"
        $allPassed = $false
    }
} catch {
    Write-Error "Open command is not correctly configured. $($_.Exception.Message)"
    $allPassed = $false
}

if (-not $allPassed) {
    exit 1
}

Write-Host "[OK] Windows protocol registration verification succeeded"
