##REPARADOR CLIENTE SCCM##
##VERSÃO 1.4##

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

    If (!(Test-Path -Path $LogFile)) { New-Item -Path $LogFile -Force -ItemType File }

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

#Função para parar qualquer processo de instalação ou desinstalação do cliente SCCM
function stopAllProcesses 
{
    
    $contador = 0
    while( Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue ) {
       #se tenta parar o serviço 10x e não consegue, gera log e sai do loop
       if($contador -eq 10){
         Write-AdvancedLogFile -Message 'Processo ccmsetup não pode ser encerrado após 10 tentativas' -Component 'stopAllProcesses' -LogFile $LogFile
         break
       }
       
       Stop-Process -Name "ccmsetup" -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
       Write-AdvancedLogFile -Message 'Processo ccmsetup encerrado' -Component 'stopAllProcesses' -LogFile $LogFile
       Start-Sleep -Seconds 5 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
       $contador++
    }
       

    $contador = 0
    while((Get-Process -Name "ccmexec" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue)) {
       #se tenta parar o serviço 10x e não consegue, gera log e sai do loop
       if($contador -eq 10){
         Write-AdvancedLogFile -Message 'Processo ccmexec não pode ser encerrado após 10 tentativas' -Component 'stopAllProcesses' -LogFile $LogFile
         break
       }

       Stop-Process -Name "CcmExec" -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
       Write-AdvancedLogFile -Message 'Processo ccmexec encerrado' -Component 'stopAllProcesses' -LogFile $LogFile
       Start-Sleep -Seconds 5 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
       $contador++
    }
    
    $contador = 0
    while((Get-Process -Name "rundll32" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue)) {
       #se tenta parar o serviço 10x e não consegue, gera log e sai do loop
       if($contador -eq 10){
         Write-AdvancedLogFile -Message 'Processo rundll32 não pode ser encerrado após 10 tentativas' -Component 'stopAllProcesses' -LogFile $LogFile
         break
       }
       Stop-Process -Name "rundll32" -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
       Write-AdvancedLogFile -Message 'Processo rundll32 encerrado' -Component 'stopAllProcesses' -LogFile $LogFile
       Start-Sleep -Seconds 5 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
       $contador++
    }
    
    $contador = 0
    while((Get-Process -Name "msiexec" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue)) {
       #se tenta parar o serviço 10x e não consegue, gera log e sai do loop
       if($contador -eq 10){
         Write-AdvancedLogFile -Message 'Processo msiexec não pode ser encerrado após 10 tentativas' -Component 'stopAllProcesses' -LogFile $LogFile
         break
       }
       Stop-Process -Name "msiexec" -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
       Write-AdvancedLogFile -Message 'Processo msiexec encerrado' -Component 'stopAllProcesses' -LogFile $LogFile
       Start-Sleep -Seconds 5 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
       $contador++
    }
    
      
    return $true
}

#Função para registrar o MSI engine
function registerMSI 
{
    cmd.exe /c "C:\Windows\system32\msiexec.exe /unregister"
    cmd.exe /c "C:\Windows\system32\msiexec.exe /regserver"
    return $true
}

#Função para verificar o WMI
Function Test-WMI 
{
        $wmiOK = $true

        #Bloco para verificar a consistência do repositório WMI
        $result = winmgmt /verifyrepository
        switch -wildcard ($result) {
            "*inconsistent*" { $wmiOK = $false } # English
            "*not consistent*"  { $wmiOK = $false } # English
            "*inkonsekvent*" { $wmiOK = $false } # Swedish
            "*epÃ¤yhtenÃ¤inen*" { $wmiOK = $false } # Finnish
            "*inkonsistent*" { $wmiOK = $false } # German
            "*inconsistente*" { $wmiOK = $false } # Português
            "*não consistente*" { $wmiOK = $false } # Português
        }

        #Verifica as classes ccm_client e sms_client do WMI
        Try {Get-WmiObject  -Namespace "root\ccm" -class ccm_client -ErrorAction Stop -InformationAction Stop -WarningAction Stop}
        Catch {$wmiOK = $false}

        Try {Get-WmiObject  -Namespace "root\ccm" -class sms_client -ErrorAction Stop -InformationAction Stop -WarningAction Stop}
        Catch {$wmiOK = $false}

        Try {
            if ($PowerShellVersion -ge 6) { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
            else { Get-WmiObject Win32_ComputerSystem -ErrorAction Stop }
        } Catch {
            Write-AdvancedLogFile -Message 'Falha ao conectar na classe WMI win32_ComputerSystem' -Component 'Test-WMI' -LogFile $LogFile       
            $wmiOK = $false
        } Finally {
            if ($wmiOK -eq $true) 
            {
                Write-AdvancedLogFile -Message 'Base WMI íntegra' -Component 'Test-WMI' -LogFile $LogFile
                write-host "Base WMI íntegra"
            }
            else 
            {
                Write-AdvancedLogFile -Message 'Base WMI corrompida' -Component 'Test-WMI' -LogFile $LogFile
                write-host "Base WMI corrompida"
            }
        }

        if($wmiOK -eq $true) {$wmiOK = $true}
        else {$wmiOK = $false}

        return $wmiOK
}

#Função para reparar a base WMI
function repairWMI
{
    if((Get-Service -Name "Winmgmt" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue).Status -eq "Running") 
    {
        Stop-Service -Name Winmgmt -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
    }
    Write-AdvancedLogFile -Message 'Serviço Winmgmt parado' -Component 'repairWMI' -LogFile $LogFile
    
    Write-AdvancedLogFile -Message 'Iniciando a reparação do WMI...' -Component 'repairWMI' -LogFile $LogFile

    cmd.exe /c "SC config winmgmt start= disabled"
    Push-Location C:\Windows\System32\wbem

    $directoryToCheck = "C:\Windows\System32\wbem\repository_old" 
    if ( Test-Path -Path $directoryToCheck -PathType Container ) 
    {
        Remove-Item $directoryToCheck -Recurse -Force                
    }

    Copy-Item -Path "C:\Windows\System32\wbem\repository" -Destination "C:\Windows\System32\wbem\repository_old" -Force -Recurse

    #Bloco para verificar se o repository_old foi copiado
    $fileToCheck = "C:\Windows\System32\wbem\repository_old" 
    if (Test-Path $fileToCheck -PathType container)
    {
        Write-AdvancedLogFile -Message 'Cópia do diretório repository criada: C:\Windows\System32\wbem\repository_old' -Component 'repairWMI' -LogFile $LogFile
    }
    else {Write-AdvancedLogFile -Message 'ERRO: A cópia do diretório repository_old não foi realizada' -Component 'repairWMI' -LogFile $LogFile}

    cmd.exe /c "%windir%\system32\wbem\winmgmt /resyncperf"

    if((Get-Service -Name "Winmgmt" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue).Status -eq "Running") 
    {
        Stop-Service -Name Winmgmt -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
    }
    Write-AdvancedLogFile -Message 'Serviço Winmgmt parado' -Component 'repairWMI' -LogFile $LogFile

    #Bloco de registro das dll's
    $outputBox.text = "Reparando o WMI, o processo pode demorar alguns minutos... `r`n`r`nRegistrando as dll's..."
    $outputBox.Refresh()
    registerDllWMI

    #Bloco de registro dos arquivos .mof e .mfl
    $outputBox.text = "Reparando o WMI, o processo pode demorar alguns minutos... `r`n`r`nRegistrando os arquivos .mof e .mfl..."
    $outputBox.Refresh()
    registerMOFWMI

    if((Get-Service -Name "Winmgmt" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue).Status -eq "Stopped") 
    {
        Start-Service -Name Winmgmt -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue 
    }

    cmd.exe /c "%windir%\system32\wbem\wmiprvse /regserver"

    cmd.exe /c "sc config winmgmt start= auto"

    if((Get-Service -Name "Winmgmt" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue).Status -eq "Stopped") 
    {
        Start-Service -Name Winmgmt -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue 
    }
    Write-AdvancedLogFile -Message 'Serviço Winmgmt iniciado' -Component 'repairWMI' -LogFile $LogFile

    #winmgmt /resetrepository
    #Write-AdvancedLogFile -Message 'Reset do repositório WMI realizado' -Component 'repairWMI' -LogFile $LogFile

    return $true
}

#Função para verificar se o cliente SCCM está instalado
function SCCMInstalled
{
    if(Get-Service -ServiceName "CcmExec" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue| format-list *) {return $true}
    else {return $false}
}

#Função para verificar se o serviço CCMExec está em execução
function VerifyCCMExec
{
    if((Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue).Status -eq "Running") {return $true}
    else {return $false}   
}

#Função para registrar as DLLs do WMI
function registerDllWMI
{
    Write-AdvancedLogFile -Message 'Registrando as dlls...' -Component 'registerWMI' -LogFile $LogFile  
    regsvr32 /s %systemroot%\system32\scecli.dll
    regsvr32 /s %systemroot%\system32\userenv.dll  
    Push-Location C:\Windows\System32\wbem
    $dlls = cmd.exe /c "dir /b *.dll"
    $total = $dlls.Count 
    $i = 0
    foreach ($dll in $dlls)
    {
        regsvr32 $dll /s  
        Write-AdvancedLogFile -Message "Dll $dll registrada" -Component 'registerWMI' -LogFile $LogFile
        $i++ 
        $percent = ($i/$total)*100
        $percent = [math]::Round($percent)
        $outputBox.text = "Registrando as dll's, o processo pode demorar alguns minutos... `r`n`r`n$percent% concluído"
        $outputBox.Refresh()   
    }

    Write-AdvancedLogFile -Message 'Registro das DLLs realizado' -Component 'registerWMI' -LogFile $LogFile
}

#Função para registrar os arquivos .mof/.mfl do WMI
function registerMOFWMI
{
    Write-AdvancedLogFile -Message 'Registrando os arquivos .mof/.mfl...' -Component 'registerDllWMI' -LogFile $LogFile
    Push-Location C:\Windows\System32\wbem
    $mofs = cmd.exe /c "dir /s /b *.mof *.mfl" 
    $total = $mofs.Count
    $i = 0
    foreach ($mof in $mofs)
    {
        mofcomp $mof 
        Write-AdvancedLogFile -Message "Arquivo $mof registrado" -Component 'registerMOFWMI' -LogFile $LogFile
        $i++ 
        $percent = ($i/$total)*100
        $percent = [math]::Round($percent)
        $outputBox.text = "Registrando os arquivos .mof/.mfl, o processo pode demorar alguns minutos... `r`n`r`n$percent% concluído"   
        $outputBox.Refresh()
    }

    Write-AdvancedLogFile -Message 'Registro dos arquivos .mof/.mfl realizado' -Component 'registerMOFWMI' -LogFile $LogFile
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
    $outputBox.text = "Iniciando a desinstalação do cliente SCCM..."
    $outputBox.Refresh()

    #Copia o instalador/desinstalador do cliente para a pasta suporte
    #$copyCcmSetup = cmd.exe /c 'robocopy "\\PXW0SCCM0001\client$" "C:\suporte" "Ccmsetup.exe" /R:1 /W:3' 
    Invoke-WebRequest http://pxw0sccm0001/CCM_CLIENT/ccmsetup.exe -OutFile C:\suporte\ccmsetup.exe 
   
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
                $contador = 0
                while (VerifyCCMExec -eq $true) {
                   if($contador -eq 10){
                      Write-AdvancedLogFile -Message 'Falha ao parar serviço ccmexec ao tentar 10x' -Component 'UninstallClient' -LogFile $LogFile
                      break
                   }
                   Stop-Service -Name "CcmExec" -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
                   Start-Sleep -Seconds 5 
                   $contador++
                   
                }


                #Deleta o arquivo SMSCfg
                if(Test-Path "%windir%\SMSCFG.INI" ){ Remove-Item -Path "%windir%\SMSCFG.INI" -Force }

                #Bloco para escrever o log do arquivo SMSCFG.INI
                $fileToCheck = "C:\Windows\SMSCFG.INI" 
                if (Test-Path $fileToCheck -PathType leaf)
                {
                    Write-AdvancedLogFile -Message 'Arquivo SMSCFG.INI não foi apagado' -Component 'UninstallClient' -LogFile $LogFile
                }
                else {Write-AdvancedLogFile -Message 'Arquivo SMSCFG.INI foi apagado' -Component 'UninstallClient' -LogFile $LogFile}


                #Remove o SMS Certificate
                $removeCert = cmd.exe /c "certutil.exe -delstore SMS SMS" 
                Write-AdvancedLogFile -Message 'SMS Certificate apagado' -Component 'UninstallClient' -LogFile $LogFile

                #Remove a pasta ccm 
                if ( Test-Path "c:\windows\ccm" ) {
                    #para o serviço wmi, assim consigo excluir todos os arquivos dentro da pasta
                    Stop-Service -Name Winmgmt -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
                    Remove-Item c:\windows\ccm -Recurse -Force

                    #inicia serviço novamente
                    Start-Service -Name Winmgmt -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
                }
           
                #Bloco para escrever o log do diretório C:\Windows\CCM
                $directoryToCheck = "C:\Windows\CCM" 
                if ( Test-Path -Path $directoryToCheck -PathType Container ) 
                {
                    Write-AdvancedLogFile -Message 'O diretório C:\Windows\CCM não foi removido' -Component 'UninstallClient' -LogFile $LogFile
                }
                else {Write-AdvancedLogFile -Message 'O diretório C:\Windows\CCM foi removido' -Component 'UninstallClient' -LogFile $LogFile}

                #Remove a pasta ccmsetup
                if ( Test-Path "c:\windows\ccmsetup" ) {Remove-Item c:\windows\ccmsetup -Recurse -Force}

                #Bloco para escrever o log do diretório C:\Windows\ccmsetup
                $directoryToCheck = "C:\Windows\ccmsetup" 
                if ( Test-Path -Path $directoryToCheck -PathType Container ) 
                {
                    Write-AdvancedLogFile -Message 'O diretório C:\Windows\ccmsetup não foi removido' -Component 'UninstallClient' -LogFile $LogFile
                }
                else {Write-AdvancedLogFile -Message 'O diretório C:\Windows\ccmsetup foi removido' -Component 'UninstallClient' -LogFile $LogFile}

                #Limpa as chaves de registro
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') { cleanRegistryKey -path "HKLM:\SOFTWARE\Microsoft\CCM" }
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {
                    Write-AdvancedLogFile -Message 'Erro na limpeza do registro: HKLM:\SOFTWARE\Microsoft\CCM' -Component 'UninstallClient' -LogFile $LogFile
                }else {
                    Write-AdvancedLogFile -Message 'Limpeza do registro realizada com sucesso: HKLM:\SOFTWARE\Microsoft\CCM' -Component 'UninstallClient' -LogFile $LogFile
                }

                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCMSetup') { cleanRegistryKey -path "HKLM:\SOFTWARE\Microsoft\CCMSetup" }
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCMSetup') {
                    Write-AdvancedLogFile -Message 'Erro na limpeza do registro: HKLM:\SOFTWARE\Microsoft\CCMSetup' -Component 'UninstallClient' -LogFile $LogFile
                }else {
                    Write-AdvancedLogFile -Message 'Limpeza do registro realizada com sucesso: HKLM:\SOFTWARE\Microsoft\CCMSetup' -Component 'UninstallClient' -LogFile $LogFile
                }


                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\SMS') { cleanRegistryKey -path "HKLM:\SOFTWARE\Microsoft\SMS" }
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\SMS') {
                    Write-AdvancedLogFile -Message 'Erro na limpeza do registro: HKLM:\SOFTWARE\Microsoft\SMS' -Component 'UninstallClient' -LogFile $LogFile
                }else {
                    Write-AdvancedLogFile -Message 'Limpeza do registro realizada com sucesso: HKLM:\SOFTWARE\Microsoft\SMS' -Component 'UninstallClient' -LogFile $LogFile
                }

                
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates') { cleanRegistryKey -path "HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates" }
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates') {
                   Write-AdvancedLogFile -Message 'Erro na limpeza do registro: HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates' -Component 'UninstallClient' -LogFile $LogFile
                }else {
                   Write-AdvancedLogFile -Message 'Limpeza do registro realizada com sucesso: HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates' -Component 'UninstallClient' -LogFile $LogFile
                }

                #Remoção do Namespace CCM do WMI
                Write-AdvancedLogFile -Message 'Remoção do Namespace ccm do WMI' -Component 'wmiRemoveCCM' -LogFile $LogFile
                $comando = "/Namespace:\\root path __Namespace where Name=""ccm"" delete"
                $removeNamespaceWMI = cmd.exe /c "wmic $comando"

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
        $outputBox.Refresh()
    
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
        Write-AdvancedLogFile -Message 'Verificação da versão do SO realizada' -Component 'CheckOS' -LogFile $LogFile

        if(Test-IsAdmin -eq $true) 
        {
            Write-AdvancedLogFile -Message 'Verificação de perfil Administrador realizada' -Component 'Test-IsAdmin' -LogFile $LogFile

            $Button.Enabled = $false
            $outputBox.text = "Iniciando a reparação, o processo pode demorar alguns minutos... `r`n`r`nPor favor aguarde..."
            $outputBox.Refresh()

            #Para todos os processos relacionados ao cliente SCCM
            if(stopAllProcesses -eq $true) {Write-AdvancedLogFile -Message 'Processos relacionados ao cliente SCCM encerrados com sucesso' -Component 'stopAllProcesses' -LogFile $LogFile}
            else {Write-AdvancedLogFile -Message 'Erro na execução da função stopAllProcesses' -Component 'stopAllProcesses' -LogFile $LogFile}

            #Registra o MSI engine
            if(registerMSI -eq $true) {Write-AdvancedLogFile -Message 'Registro do MSI engine realizado' -Component 'registerMSI' -LogFile $LogFile}
            else {Write-AdvancedLogFile -Message 'Erro na execução da função registerMSI' -Component 'registerMSI' -LogFile $LogFile}

            #Verifica se o cliente SCCM está instalado
            if (sccmInstalled -eq $true)
            {
                Write-AdvancedLogFile -Message 'Cliente SCCM já instalado' -Component 'sccmInstalled' -LogFile $LogFile

                #Verifica se o serviço CCMExec está em execução, se estiver então para
                $contador = 0
                while (VerifyCCMExec -eq $true) 
                {
                    Write-AdvancedLogFile -Message 'Serviço CCMExec em execução. Parando o serviço...' -Component 'VerifyCCMExec' -LogFile $LogFile
                    Stop-Service -Name CcmExec -Force
                    Start-Sleep -Seconds 10
                    

                    if (VerifyCCMExec -eq $false) {
                       Write-AdvancedLogFile -Message 'O serviço CCMExec foi parado com sucesso' -Component 'VerifyCCMExec' -LogFile $LogFile
                    }else{
                       Write-AdvancedLogFile -Message 'Não foi possível parar o serviço CCMExec ...tentando novamente...' -Component 'VerifyCCMExec' -LogFile $LogFile
                       if($contador -eq 10){
                         Write-AdvancedLogFile -Message 'Não foi possível parar o serviço CCMExec após 10 tentativas' -Component 'VerifyCCMExec' -LogFile $LogFile
                         break
                       }                      
                    }
                    $contador++
                }
            }


            #Faz a verificação do WMI
            Write-AdvancedLogFile -Message 'Iniciando a verificação do WMI...' -Component 'Test-WMI' -LogFile $LogFile
            $wmiOK = Test-WMI
            if($wmiOK -eq $false) 
            { 
                $outputBox.text = "Reparando o WMI, o processo pode demorar alguns minutos... `r`n`r`nPor favor aguarde..."
                $outputBox.Refresh()
                $repaired = repairWMI  
                if($repaired -eq $true) 
                {
                    Write-AdvancedLogFile -Message 'Reparação do WMI realizada' -Component 'repairWMI' -LogFile $LogFile
                    $outputBox.text = "Reparação do WMI realizada com sucesso."
                    $outputBox.Refresh()
                }
                else
                {
                    Write-AdvancedLogFile -Message 'ERRO na execução da função repairWMI' -Component 'repairWMI' -LogFile $LogFile
                }           
            }

            #Inicia a desinstalação do cliente
            $a = UninstallClient

            #Inicia a instalação do cliente
            $b = InstallClient

            if(($a -eq $false) -and ($b -eq $false))
            {
                $outputBox.text = "Reparação realizada com sucesso."
                $outputBox.Refresh()
                Alert   
                Write-AdvancedLogFile -Message 'A reparação foi realizada com sucesso' -Component 'RepairClient' -LogFile $LogFile
            }

            else 
            {
                $outputBox.text = "ERRO! A reparação do cliente SCCM não pôde ser realizada."
                $outputBox.Refresh()
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
    #$msg = "O cliente SCCM foi reparado com sucesso."

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
#$form1.Activate()
#$Form1.Focus() #Foco no formulário principal
#$form1.Focused 
$Form1.Text = "Reparador"
$Form1.StartPosition = "CenterScreen"
$Form1.SizeGripStyle = "Hide" # Auto, Hide, Show
$Form1.FormBorderStyle = "Fixed3D"
$form1.topmost = $true
$form1.MaximizeBox = $false #Impede o usuário de maximizar a janela
$form1.MinimizeBox = $False #Impede o usuário de minimizar a janela
#$Form1.ShowInTaskbar = $True

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



