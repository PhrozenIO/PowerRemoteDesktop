# cd .\Projects\PowerRemoteDesktop\; IEX (Get-Content .\TestServer.ps1 -Raw -Encoding UTF8)

Write-Output "⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️"
Write-Output "⚠️ Only use this script for testing the application NOT in production ⚠️"
Write-Output "⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️"

Invoke-Expression -Command (Get-Content "PowerRemoteDesktop_Server\PowerRemoteDesktop_Server.psm1" -Raw)

$password = "Jade@123@Pwd"
$encodedCertificate = "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"

Write-Host "Scenarios"
Write-Host "---------------"
Write-Host "1. Classic (Secure Password)"
Write-Host "2. Classic (Plain-text password)"
Write-Host "3. Classic Default Certificate"
Write-Host "4. TLS v1.3"
Write-Host "5. Verbosity Disabled, View Only, Prevent computer to sleep"
Write-Host "6. Receive clipboard only"
Write-Host "7. Send clipboard only"
Write-Host "8. Clipboard synchronization disabled"

Write-Host ""

[int]$scenario = Read-Host "Please choose scenario (default: 1)"

switch ($scenario)
{
    2 
    { 
        Invoke-RemoteDesktopViewer -Password $password -EncodedCertificate $encodedCertificate
    } 

    3 
    {
        Invoke-RemoteDesktopViewer -Password $password
    }

    4 
    {
        Write-Host "⚡Check that TLSv1.3 is working."
        Write-Host "⚡Check that certificate file is correctly loaded and used."

        Invoke-RemoteDesktopViewer -Password $password -CertificateFile "c:\temp\phrozen.p12" -UseTLSv1_3
    }

    5 
    {
        Write-Host "⚡Check that verbosity is disabled."
        Write-Host "⚡Check that remote viewer can't control mouse and keyboard."
        Write-Host "⚡Check that computer wont go to sleep."

        Invoke-RemoteDesktopViewer -Password $password -CertificateFile "c:\temp\phrozen.p12" -DisableVerbosity -ViewOnly -PreventComputerToSleep
    }

    6 
    {
        Write-Host "⚡Check if server is only authorized to receive remote clipboard."

        Invoke-RemoteDesktopViewer -Password $password -EncodedCertificate $encodedCertificate -Clipboard "Receive"
    }

    7 
    {
        Write-Host "⚡Check if server is only authorized to send local clipboard."

        Invoke-RemoteDesktopViewer -Password $password -EncodedCertificate $encodedCertificate -Clipboard "Send"
    }

    8 
    {
        Write-Host "⚡Check if clipboard synchronization is completely disabled."

        Invoke-RemoteDesktopViewer -Password $password -EncodedCertificate $encodedCertificate -Clipboard "Disabled"
    }

    default 
    { 
        Invoke-RemoteDesktopServer -SecurePassword (ConvertTo-SecureString -String $password -AsPlainText -Force) -EncodedCertificate $encodedCertificate
    }
}