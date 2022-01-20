Write-Output "This script is used during development phase. Never run this script under a production environment."

Invoke-Expression -Command (Get-Content "PowerRemoteDesktop_Viewer\PowerRemoteDesktop_Viewer.psm1" -Raw)

#Invoke-RemoteDesktopViewer -SecurePassword (ConvertTo-SecureString -String "Jade@123@Pwd" -AsPlainText -Force) -ServerAddress "127.0.0.1" 
Invoke-RemoteDesktopViewer -SecurePassword (ConvertTo-SecureString -String "Jade@123@Pwd" -AsPlainText -Force) -ServerAddress "172.31.115.183"