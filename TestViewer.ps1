# cd .\Projects\PowerRemoteDesktop\; IEX (Get-Content .\TestViewer.ps1 -Raw -Encoding UTF8)

Write-Output "⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️"
Write-Output "⚠️ Only use this script for testing the application NOT in production ⚠️"
Write-Output "⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️"

Invoke-Expression -Command (Get-Content "PowerRemoteDesktop_Viewer\PowerRemoteDesktop_Viewer.psm1" -Raw)

# Different Scenarios

$remoteHost = "127.0.0.1"
$password = "Jade@123@Pwd"

Write-Host "Scenarios"
Write-Host "---------------"
Write-Host "1. Classic (Secure Password)"
Write-Host "2. Classic (Plain-text password) + LogonUI"
Write-Host "3. Always On Top, Disable Verbosity"
Write-Host "4. TLS v1.3"
Write-Host "5. Clipboard Receive"
Write-Host "6. Clipboard Send"
Write-Host "7. Clipboard Disabled"
Write-Host "8. Image Quality Really Bad"
Write-Host "9. Image Quality Bad"
Write-Host "10. Image Quality High"
Write-Host "11. Resize 10%"
Write-Host "12. Resize 80%, Packet Size 16KiB, BlockSize 128x128"
Write-Host "13. Bad Password"

Write-Host ""

[int]$scenario = Read-Host "Please choose scenario (default: 1)"

switch ($scenario)
{
    2 
    { 
        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -LogonUI
    }  

    3 
    { 
        Write-Host "⚡Check that verbosity is not shown."
        Write-Host "⚡Check that virtual desktop form is above all windows."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -DisableVerbosity -AlwaysOnTop 
    }

    4 
    { 
        Write-Host "⚡Check that TLSv1.3 is working."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -UseTLSv1_3 
    }

    5 
    { 
        Write-Host "⚡Check if viewer is only authorized to receive remote clipboard."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -Clipboard "Receive"
    }

    6 
    { 
        Write-Host "⚡Check if viewer is only authorized to send local clipboard."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -Clipboard "Send" 
    }

    7 
    { 
        Write-Host "⚡Check if clipboard synchronization is completely disabled."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -Clipboard "Disabled" 
    }

    8 
    { 
        Write-Host "⚡Check if image quality is really low."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -ImageCompressionQuality 0 
    }

    9 
    { 
        Write-Host "⚡Check if image quality is not really good."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -ImageCompressionQuality 30 
    }

    10 
    { 
        Write-Host "⚡Check if image quality is really good."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -ImageCompressionQuality 100 
    }

    11 
    { 
        Write-Host "⚡Check if desktop image is reduced by 10%."
        Write-Host "⚡Check if resize quality is bad."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -Resize -ResizeRatio 90
    }

    12 
    { 
        Write-Host "⚡Check if desktop image is reduced by 20%."
        Write-Host "⚡Control block size."
        Write-Host "⚡Control packet size."

        Invoke-RemoteDesktopViewer -Password $password -ServerAddress $remoteHost -Resize -ResizeRatio 80 -PacketSize "Size16384" -BlockSize "Size128"
    }

    13 
    {
        Write-Host "⚡Be sure that authentication fails with remote server." 
        
        Invoke-RemoteDesktopViewer -Password "bad@Bad123!Bad" -ServerAddress $remoteHost
    }

    default 
    { 
        Invoke-RemoteDesktopViewer -SecurePassword (ConvertTo-SecureString -String $password -AsPlainText -Force) -ServerAddress $remoteHost 
    }
}