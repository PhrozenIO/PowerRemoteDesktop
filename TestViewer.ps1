Write-Output "This script is used during development phase. Never run this script under a production environment."

Invoke-Expression -Command (Get-Content "PowerRemoteDesktop_Viewer\PowerRemoteDesktop_Viewer.psm1" -Raw)

Invoke-RemoteDesktopViewer -Password "Jade"