# LauncherUI.ps1
<#
  Stealth Launcher UI - PowerShell Script
  Executa o Stealth Launcher em stages com barra de progresso visual e console.
#>

# --- UI Functions ---
function Show-ConsoleProgress {
    param(
        [int]$Percent,
        [string]$Activity = "Processando..."
    )
    $icon = if ($Percent -lt 50) { "🔄" } elseif ($Percent -lt 90) { "⏳" } else { "✅" }
    Write-Progress -Activity "$icon $Activity" -Status "$Percent%" -PercentComplete $Percent
}

function Show-GuiProgress {
    param(
        [int]$Percent,
        [string]$Text = "Carregando..."
    )
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    if (-not $global:Form) {
        $global:Form = New-Object System.Windows.Forms.Form
        $global:Form.Text = "Stealth Launcher Control"
        $global:Form.Size = [System.Drawing.Size]::New(400,140)
        $global:Form.StartPosition = 'CenterScreen'
        $global:Bar = New-Object System.Windows.Forms.ProgressBar
        $global:Bar.Location = [System.Drawing.Point]::New(20,50)
        $global:Bar.Size = [System.Drawing.Size]::New(350,25)
        $global:Bar.Minimum = 0; $global:Bar.Maximum = 100
        $global:Form.Controls.Add($global:Bar)
        $global:Lbl = New-Object System.Windows.Forms.Label
        $global:Lbl.Location = [System.Drawing.Point]::New(20,20)
        $global:Lbl.Size = [System.Drawing.Size]::New(350,20)
        $global:Form.Controls.Add($global:Lbl)
        $global:Form.TopMost = $true
        $global:Form.Show() | Out-Null
    }
    $global:Bar.Value = $Percent
    $global:Lbl.Text = $Text
    [System.Windows.Forms.Application]::DoEvents()
}

# --- Core Stage Runner ---
function Invoke-Stage {
    param(
        [string]$StageName,
        [int]$PercentStart,
        [int]$PercentEnd
    )

    Show-ConsoleProgress -Percent $PercentStart -Activity "Launching $StageName"
    Show-GuiProgress -Percent $PercentStart -Text "Executando: $StageName..."

    Write-Host "[*] Fase: $StageName iniciada" -ForegroundColor DarkCyan
    try {
        python -m stealth_launcher.stealth_launcher $StageName
        Write-Host "[+] Fase $StageName concluída" -ForegroundColor Green
    } catch {
        Write-Host "[-] Falha ao executar $StageName" -ForegroundColor Red
    }

    Show-ConsoleProgress -Percent $PercentEnd -Activity "Finalizando $StageName"
    Show-GuiProgress -Percent $PercentEnd -Text "Finalizado: $StageName"
    Start-Sleep -Milliseconds 300
}

# --- Main Execution Flow ---
Clear-Host
Write-Host ">>>>> Stealth Launcher - Iniciando sequenciamento... <<<<<" -ForegroundColor Magenta

$stages = @("evasion", "patching", "payload_execution", "beaconing", "persistence", "cleanup")
$step = [math]::Floor(100 / $stages.Count)

for ($i = 0; $i -lt $stages.Count; $i++) {
    $start = $i * $step
    $end = (($i + 1) * $step) - 1
    Invoke-Stage -StageName $stages[$i] -PercentStart $start -PercentEnd $end
}

# Finalização
if ($global:Form) { 
    $global:Form.Close(); 
    Remove-Variable Form,Bar,Lbl -Scope Global 
}

Write-Host ">>>>> Todos os estágios foram completados com sucesso! <<<<<" -ForegroundColor Cyan
