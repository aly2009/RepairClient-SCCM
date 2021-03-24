# Hide PowerShell Console
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0)
#----------------------------------------------------------------------------------

#Função para gerar logs
function Write-AdvancedLogFile {

    [CmdletBinding()]

    param(

        [Parameter(Mandatory=$True, HelpMessage="Caminho e nome do arquivo de log")]

        [string]$LogFile,

        [Parameter(Mandatory=$True, HelpMessage="Message that will be inserted into the log file")]

        [string]$Message,

        [Parameter(Mandatory=$false, HelpMessage="Component or item related to the log message")]

        [string]$Component

    )

    $Time = Get-Date -Format "HH:mm:ss.ffffff"

    $Date = Get-Date -Format "MM-dd-yyyy"

    $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"`" thread=`"`" file=`"`">"

    If (!(Test-Path -Path $LogFile)) {
        New-Item -Path $LogFile -Force -ItemType File
    }

    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile

}

#Função para verificar se o usuário é Administrador
function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
        return $principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
    } catch {
        throw "Falha em determinar se o usuário tem privilégios elevados. O erro foi: '{0}'." -f $_
    }
}

#Função para verificar se o cliente SCCM está instalado
function SCCMInstalled
{
    if(Get-Service -ServiceName "CcmExec" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue| fl *) {return $true}
    else {return $false}
}

#Função para verificar se o serviço CCMExec está em execução
function VerifyCCMExec
{
    if((Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue).Status -eq "Running") {return $true}
    else {return $false}   
}

#Função para verificar se o SO é Windows 10
function CheckOS
{
    if((Get-WmiObject win32_OperatingSystem).Caption -like "*Windows 10*") {return $true}
    else {return $false}
}

#Função para apagar as chaves de registro do cliente SCCM
function cleanRegistryKey 
{
    param ($path)
    if((Test-Path $path) -eq 'true'){Remove-Item $path -Recurse -Force}
}

#Função para desinstalar o cliente SCCM
function UninstallClient
{
    #Copia o instalador/desinstalador do cliente para a pasta suporte
    $copy = robocopy "\\PXW0SCCM0001\client$" "C:\suporte" "Ccmsetup.exe" /R:1 /W:3 

    #Bloco para verificar se o ccmsetup.exe foi copiado para C:\suporte
    $fileToCheck = "C:\suporte\Ccmsetup.exe" 
    if (Test-Path $fileToCheck -PathType leaf)
    {
        Write-AdvancedLogFile -Message 'Ccmsetup.exe copiado do servidor para C:\suporte com sucesso' -Component 'UninstallClient' -LogFile $LogFile
    }
    else {Write-AdvancedLogFile -Message 'ERRO: Ccmsetup.exe não foi copiado do servidor para C:\suporte' -Component 'UninstallClient' -LogFile $LogFile}

    #Inicia o processo de desinstalação
    $finished = $false

    while($finished -eq $false)
    {
        $outputBox.text = "Iniciando a reparação, o processo pode demorar alguns minutos... `r`n`r`nPor favor aguarde..."

        Try
        {
            Write-AdvancedLogFile -Message 'Iniciando a desinstalação do cliente...' -Component 'UninstallClient' -LogFile $LogFile
            $process = Start-Process -FilePath "c:\suporte\Ccmsetup.exe" -ArgumentList "/uninstall" -PassThru -verb runAs -WindowStyle Hidden -Wait
            
            if($process.ExitCode -eq "0") 
            {
                $erro = $false
                Write-AdvancedLogFile -Message 'Desinstalação realizada com sucesso' -Component 'UninstallClient' -LogFile $LogFile
            }
            else 
            {
                $erro = $true
                Write-AdvancedLogFile -Message 'Erro na desinstalação' -Component 'UninstallClient' -LogFile $LogFile
            }
        } 

        Catch
        {
            $erro = $true 
        }

        Finally
        {
            if($erro -eq $false)
            {
                #Para o serviço se estiver em execução
                if(VerifyCCMExec -eq $true) {Stop-Service -Name "CcmExec" -Force -NoWait -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue}

                #Deleta o arquivo SMSCfg
                $delIni = cmd.exe /c "del /F %windir%\SMSCFG.INI" 

                #Bloco para escrever o log do arquivo SMSCFG.INI
                $fileToCheck = "C:\Windows\SMSCFG.INI" 
                if (Test-Path $fileToCheck -PathType leaf)
                {
                    Write-AdvancedLogFile -Message 'Arquivo SMSCFG.INI não foi apagado' -Component 'UninstallClient' -LogFile $LogFile
                }
                else {Write-AdvancedLogFile -Message 'Arquivo SMSCFG.INI foi apagado' -Component 'UninstallClient' -LogFile $LogFile}


                #Remove o SMS Certificate
                $delCert = cmd.exe /c "certutil.exe -delstore SMS SMS" 
                Write-AdvancedLogFile -Message 'SMS Certificate apagado' -Component 'UninstallClient' -LogFile $LogFile

                #Remove a pastas ccm 
                Remove-Item c:\windows\ccm -Recurse -Force 
           
                #Bloco para escrever o log do diretório C:\Windows\CCM
                $directoryToCheck = "C:\Windows\CCM" 
                if ( Test-Path -Path $directoryToCheck -PathType Container ) 
                {
                    Write-AdvancedLogFile -Message 'O diretório C:\Windows\CCM não foi removido' -Component 'UninstallClient' -LogFile $LogFile
                }
                else {Write-AdvancedLogFile -Message 'O diretório C:\Windows\CCM foi removido' -Component 'UninstallClient' -LogFile $LogFile}

                #Remove a pasta ccmsetup
                Remove-Item c:\windows\ccmsetup -Recurse -Force 

                #Bloco para escrever o log do diretório C:\Windows\ccmsetup
                $directoryToCheck = "C:\Windows\ccmsetup" 
                if ( Test-Path -Path $directoryToCheck -PathType Container ) 
                {
                    Write-AdvancedLogFile -Message 'O diretório C:\Windows\ccmsetup não foi removido' -Component 'UninstallClient' -LogFile $LogFile
                }
                else {Write-AdvancedLogFile -Message 'O diretório C:\Windows\ccmsetup foi removido' -Component 'UninstallClient' -LogFile $LogFile}

                #Limpa as chaves de registro
                cleanRegistryKey -path "HKLM:\SOFTWARE\Microsoft\CCM"
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {Write-AdvancedLogFile -Message 'Erro na limpeza do registro: HKLM:\SOFTWARE\Microsoft\CCM' -Component 'UninstallClient' -LogFile $LogFile}
                else {Write-AdvancedLogFile -Message 'Limpeza do registro realizada com sucesso: HKLM:\SOFTWARE\Microsoft\CCM' -Component 'UninstallClient' -LogFile $LogFile}

                cleanRegistryKey -path "HKLM:\SOFTWARE\Microsoft\CCMSetup"
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCMSetup') {Write-AdvancedLogFile -Message 'Erro na limpeza do registro: HKLM:\SOFTWARE\Microsoft\CCMSetup' -Component 'UninstallClient' -LogFile $LogFile}
                else {Write-AdvancedLogFile -Message 'Limpeza do registro realizada com sucesso: HKLM:\SOFTWARE\Microsoft\CCMSetup' -Component 'UninstallClient' -LogFile $LogFile}

                cleanRegistryKey -path "HKLM:\SOFTWARE\Microsoft\SMS"
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\SMS') {Write-AdvancedLogFile -Message 'Erro na limpeza do registro: HKLM:\SOFTWARE\Microsoft\SMS' -Component 'UninstallClient' -LogFile $LogFile}
                else {Write-AdvancedLogFile -Message 'Limpeza do registro realizada com sucesso: HKLM:\SOFTWARE\Microsoft\SMS' -Component 'UninstallClient' -LogFile $LogFile}

            }

            $finished = $true
        }
    }

    return $erro
}


#Função para instalar o cliente SCCM
function InstallClient
{  
    $finished = $false

    while($finished -eq $false)
    {
        $outputBox.text = "Limpeza dos arquivos danificados realizada com sucesso... `r`n`r`nIniciando a reinstalação do cliente SCCM..."
    
        #Inicia o processo de instalação
        Try{
            Write-AdvancedLogFile -Message 'Iniciando a instalação do cliente...' -Component 'InstallClient' -LogFile $LogFile
            $process = Start-Process -FilePath "c:\suporte\Ccmsetup.exe" -PassThru -Verb runAs -WindowStyle Hidden -Wait

            if($process.ExitCode -eq "0") 
            {
                $erro = $false
                Write-AdvancedLogFile -Message 'Instalação executada com sucesso' -Component 'InstallClient' -LogFile $LogFile
            }

            else 
            {
                $erro = $true
                Write-AdvancedLogFile -Message 'Erro na instalação' -Component 'InstallClient' -LogFile $LogFile
            }
        } 

        Catch
        {
            $erro = $true 
        }

        Finally
        {
            $finished = $true
        }
    }

return $erro

}


#Função Reparar
function RepairClient
{
    $LogFile = "C:\suporte\" + "$(Get-Date -Format "ddMMyyyy")" + "_ReparadorClienteSCCM.log"

    #Verifica se o SO é Windows 10
    Write-AdvancedLogFile -Message 'Reparação iniciada' -Component 'RepairClient' -LogFile $LogFile

    if(CheckOS -eq $true)
    {
        Write-AdvancedLogFile -Message 'Verificação da versão do SO OK' -Component 'CheckOS' -LogFile $LogFile

        if(Test-IsAdmin -eq $true) 
        {
            Write-AdvancedLogFile -Message 'Verificação de perfil Admin OK' -Component 'Test-IsAdmin' -LogFile $LogFile

            $Button.Enabled = $false

            #Verifica se o cliente SCCM está instalado
            if (sccmInstalled -eq $true)
            {
                Write-AdvancedLogFile -Message 'Verificação do cliente SCCM instalado OK' -Component 'sccmInstalled' -LogFile $LogFile

                #Verifica se o serviço CCMExec está em execução, se estiver então para
                if (VerifyCCMExec -eq $true) 
                {
                    Write-AdvancedLogFile -Message 'Serviço CCMExec em execução. Parando o serviço...' -Component 'VerifyCCMExec' -LogFile $LogFile
                    Stop-Service -Name CcmExec -NoWait -Force
                    if (VerifyCCMExec -eq $false) {Write-AdvancedLogFile -Message 'O serviço CCMExec foi parado com sucesso' -Component 'VerifyCCMExec' -LogFile $LogFile} 
                }
            }

            $a = UninstallClient
            $b = InstallClient

            if(($a -eq $false) -and ($b -eq $false))
            {
                $outputBox.text = "Reparação realizada com sucesso."
                Alert   
                Write-AdvancedLogFile -Message 'A reparação foi realizada com sucesso' -Component 'RepairClient' -LogFile $LogFile
            }

            else 
            {
                $outputBox.text = "ERRO! A reparação do cliente SCCM não pôde ser realizada."
                $Button.Text = "Reiniciar"
                Write-AdvancedLogFile -Message 'ERRO na reparação!!!' -Component 'RepairClient' -LogFile $LogFile
            }

                $Button.Enabled = $true 
        }

        else 
        {
            Write-AdvancedLogFile -Message 'O reparador não foi executado com perfil de administrador.' -Component 'RepairClient' -LogFile $LogFile
            $outputBox.text = "É necessário executar como administrador."
            $Button.Enabled = $false
        }

    }

    else 
        {
            Write-AdvancedLogFile -Message 'Versão do SO incompatível com o Reparador' -Component 'CheckOS' -LogFile $LogFile
            $outputBox.text = "O reparador só é compatível com o Windows 10."
        }
}


#-------------------------------Formulário com a função para confirmar a instalação-------------------------------------------
Function Alert
{
# Cria um formulário e configura seus parâmetros
    $ConfirmForm = New-Object Windows.Forms.Form
    $Form1.Topmost = $false
    $ConfirmForm.Activate()
    $ConfirmForm.Focus() # Foco no formulário de alerta
    $ConfirmForm.BringToFront()
    $ConfirmForm.Focused
    $ConfirmForm.TopLevel = $true # Traz o formulário para frente
    $ConfirmForm.Size = New-Object Drawing.Size @(350,120)
    $ConfirmForm.StartPosition = "CenterScreen"
    $ConfirmForm.Text = "Processo concluído"
    $ConfirmForm.StartPosition = "CenterScreen"# Move o formulário para o centro da tela
    $ConfirmForm.Topmost = $true #Configura o alerta para abrir na frente de todas as janelas
    $ConfirmForm.MaximizeBox = $false #Impede o usuário de maximizar a janela
    $ConfirmForm.MinimizeBox = $False #Impede o usuário de minimizar a janela
    $ConfirmForm.WindowState = "Normal" # Maximized, Minimized, Normal
    $ConfirmForm.SizeGripStyle = "Hide" # Auto, Hide, Show
    $ConfirmForm.ShowInTaskbar = $False
    $ConfirmForm.FormBorderStyle = "Fixed3D" #Deixa as bordas fixas
    $msg = "O cliente SCCM foi reparado com sucesso."

# Altera o ícone do formulário
    #$ConfirmForm.Icon = $Icon 

# Escreve a mensagem
    $msgLabel = New-Object System.Windows.Forms.Label
    $msgLabel.Location = New-Object System.Drawing.Size(0,14)
    $msgLabel.Size = New-Object System.Drawing.Size(350,30)
    $msgLabel.Font = New-Object System.Drawing.Font("Segoe UI",10,[System.drawing.FontStyle]::Bold)
    $msgLabel.TextAlign = "TopCenter" 
    $msgLabel.Text = "Reparação concluída com sucesso."
    $ConfirmForm.Controls.Add($msgLabel)

    $handler_button_cancel_Click= 
    { 
        $Form1.Close() 
    }

# Utiliza as teclas ENTER e ESC pressionadas
    $ConfirmForm.KeyPreview = $True

    $ConfirmForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") 
    {
        # se "escape", sair
        $handler_button_cancel_Click
    }
    })

# OK BUTTON
    $button_cancel = New-Object Windows.Forms.Button
    $button_cancel.text = "OK"
    $button_cancel.Location = New-Object Drawing.Point 142,45
    $button_cancel.Size = New-Object System.Drawing.Size(66,24)
    $button_cancel.Font = New-Object System.Drawing.Font("Segoe UI",9,[System.drawing.FontStyle]::Regular)
    $button_cancel.DialogResult = [System.Windows.Forms.DialogResult]::No
    $button_cancel.add_click($handler_button_cancel_Click) #Fecha o aplicativo
    
# Adiciona controles ao formulário
    $ConfirmForm.controls.add($button_cancel) 
    
# Mostra o formulário e coloca o foco nele
    $ConfirmForm.Add_Shown({$ConfirmForm.Activate()})
    $ConfirmForm.ShowDialog()
}

#------------------------------------Formulário principal------------------------------------------------
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

$Form1 = New-Object System.Windows.Forms.Form
$Form1.ClientSize = New-Object System.Drawing.Size(400, 140)
$Form1.Text = "Reparador"
$Form1.StartPosition = "CenterScreen"
$Form1.SizeGripStyle = "Hide" # Auto, Hide, Show
$Form1.FormBorderStyle = "Fixed3D"
$form1.topmost = $true

# Altera o ícone do formulário
#$str = (Get-Item $PSCommandPath ).DirectoryName #ícone no diretório atual
#$str = "C:\Temp\" #ícone no c:\temp
#$strIcon = $str + "\ico.ico"
#$Icon = New-Object system.drawing.icon ($strIcon)
#$form1.Icon = $Icon

# Painel do formulário para exibir os resultados
$outputBox = New-Object System.Windows.Forms.TextBox  
$outputBox.Size = New-Object System.Drawing.Size(230,60)
$outputBox.Location = New-Object System.Drawing.Size(25,50)
$outputBox.Font = New-Object System.Drawing.Font("Segoe UI",8,[System.drawing.FontStyle]::Regular) #Bold/Italic/Regular/Underline
$outputBox.MultiLine = $True 
$outputBox.ReadOnly= $True
$outputBox.TabStop = $false
$Form1.Controls.Add($outputBox)

#Botão reparar
$Button = New-Object System.Windows.Forms.Button
$Button.Location = New-Object System.Drawing.Point(280, 68.5)
$Button.Size = New-Object System.Drawing.Size(95, 23)
$Button.Text = "Iniciar"
$Button.add_Click({
    RepairClient
})
$Form1.Controls.Add($Button)

#Label com o titulo 
$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(100, 10)
$label2.Size = New-Object System.Drawing.Size(200, 25)
$label2.Text = "Reparador Cliente SCCM"
$label2.Font = New-Object System.Drawing.Font("Segoe UI",12,[System.drawing.FontStyle]::Bold)
$Form1.Controls.Add($label2)

[void]$form1.showdialog()



