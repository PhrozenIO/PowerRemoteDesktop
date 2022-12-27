<p align="center">
  <img src="Assets/iconv2-1.png" width="384"/>
</p>

# Power Remote Desktop

<img src="Assets/prdp-banner.png" width="100%"/>

Welcome to **Power Remote Desktop** for remote desktop access in pure PowerShell! This module offers a unique solution for remotely controlling one or multiple screens using only PowerShell. Unlike other remote desktop tools that rely on external protocols and software, our module utilizes its own  remote desktop protocol.

The module consists of both a client and a server component, both of which are written entirely in PowerShell. Our protocol provides secure, encrypted communication using TLS and offers both challenge-based password authentication and certificate-based authentication.

In addition to providing full mouse and keyboard control over the remote desktop, our module also replicates the mouse cursor icon for the viewer, synchronizes the clipboard between the local and remote systems, and more. Despite the limitations of PowerShell, we have implemented techniques to optimize network traffic and improve the streaming experience, resulting in a smooth and efficient remote desktop experience.

At the time of writing, this is the only known entirely PowerShell-based remote desktop application. We hope you find it useful and we welcome any feedback or suggestions you may have.

Tested on:

* **Windows 10**
* **Windows 11**

Current version: **4.0.0 Stable**

## Performance

For a better streaming performance and overall experience, we recommend using PowerShell 7 instead of PowerShell 5.

You can install PowerShell 7 for Windows [here](https://docs.microsoft.com/fr-fr/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2)

---

## Highlighted Features

<img src="Assets/image31.png" width="100%"/>

* Remote Desktop Streaming: This feature allows you to stream the desktop of the remote computer to your own device. The streaming supports HDPI and scaling, providing a high-quality display on various screens and resolutions.
* Remote Control: With this feature, you can control the mouse (including moves, clicks, and wheel) and keyboard of the remote computer as if you were sitting in front of it.
* Secure: To protect the privacy and security of your remote desktop sessions, the module uses TLSv1.2 or 1.3 to encrypt the network traffic. Access to the server is granted through a challenge-based authentication mechanism that requires a user-defined complex password.
* Network Traffic Encryption: The module supports encrypting the network traffic using either a default X509 certificate (which requires administrator privileges) or your own custom X509 certificate.
* Server Certificate Fingerprint Validation: To ensure the authenticity of the server, the module allows you to validate the fingerprint of the server certificate and optionally persist this validation between sessions.
* Clipboard Synchronization: This feature allows you to synchronize the clipboard text between the viewer (your device) and the server (the remote computer). You can easily copy and paste text between the two systems.
* Mouse Cursor Icon Synchronization: The module also synchronizes the state of the mouse cursor icon between the viewer (virtual desktop) and the server, providing a more seamless and intuitive remote desktop experience.
* Multi-Screen Support: If the remote computer has more than one desktop screen, you can choose which screen to capture and stream to your device.
* View Only Mode: This feature allows you to disable remote control abilities and simply view the screen of the remote computer. It can be useful for demonstrations or presentations.
* Session Concurrency: Multiple viewers can connect to a single server at the same time, allowing multiple users to collaborate on the same remote desktop.
* Sleep Mode Prevention: To ensure that the remote desktop remains active and responsive, the module prevents the remote computer from entering sleep mode while it is waiting for viewers to connect.
* Streaming Optimization: To improve the streaming speed, the module only sends updated pieces of the desktop to the viewer, reducing the amount of data transmitted over the network.

---

## Setup everything in less than a minute (Fast Setup)

````powershell
Install-Module -Name PowerRemoteDesktop_Server

Invoke-RemoteDesktopServer -CertificateFile "<certificate_location>"
````

If you want to avoid using your own certificate and prefer not to go through the process of creating one, you can remove the 'CertificateFile' option and run PowerShell as an administrator instead.

````powershell
Install-Module -Name PowerRemoteDesktop_Viewer

Invoke-RemoteDesktopViewer -ServerAddress "<ip_address>" -Password "<the_one_displayed_on_server>"
````

Thats it 😉

---

## Detailed Installation and Instructions

There are several ways to use this PowerShell application. The recommended method is to install both the server and viewer components using the PowerShell Gallery. Alternatively, you can install them as modules or import them as scripts manually. Choose the method that best fits your needs and preferences.

### Install as a PowerShell Module from PowerShell Gallery (**Recommended**)

You can install Power Remote Desktop from the PowerShell Gallery, which is similar to Aptitude for Debian or Brew for MacOS. To do so, run the following commands: 

```powershell
Install-Module -Name PowerRemoteDesktop_Server

Install-Module -Name PowerRemoteDesktop_Viewer
```

`AllowPrerelease` is mandatory when current version is marked as a *Prerelease*

When you run the command, you may see the following warning in your command prompt:

```
Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its
InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from
'PSGallery'?
```

Type 'Y' to confirm and proceed with the installation. When the installation is complete, both modules should be available. You can verify this by running the following command: 

```powershell
Get-Module -ListAvailable
```

Example Output:

```
PS C:\Users\Phrozen\Desktop> Get-Module -ListAvailable


    Directory: C:\Users\Phrozen\Documents\WindowsPowerShell\Modules


ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.0      PowerRemoteDesktop_Server           Invoke-RemoteDesktopServer
Manifest   1.0.0      PowerRemoteDesktop_Viewer           Invoke-RemoteDesktopViewer

<..snip..>
```

If the modules are not showing up, try running the following commands and then check again: 

```powershell
Import-Module PowerRemoteDesktop_Server

Import-Module PowerRemoteDesktop_Viewer
```

### Install as a PowerShell Module (Manually / Unmanaged)

In order for a module to be available, it must be located in a registered module path. You can view the registered module paths by running the following command: 

```powershell
Write-Output $env:PSModulePath
```

Example Output:

```
C:\Users\Phrozen\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
```

Clone PowerRemoteDesktop repository or download a Github release package.

```
git clone https://github.com/DarkCoderSc/PowerRemoteDesktop.git
```

Copy both *PowerRemoteDesktop_Viewer* and *PowerRemoteDesktop_Server* folders to desired module path 

Example: 

```
C:\Users\<USER>\Documents\WindowsPowerShell\Modules
```

Both modules should now be available, you can verify using the command:

```powershell
Get-Module -ListAvailable
```

Example Output:

```
PS C:\Users\Phrozen\Desktop> Get-Module -ListAvailable


    Directory: C:\Users\Phrozen\Documents\WindowsPowerShell\Modules


ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.0      PowerRemoteDesktop_Server           Invoke-RemoteDesktopServer
Manifest   1.0.0      PowerRemoteDesktop_Viewer           Invoke-RemoteDesktopViewer

<..snip..>
```

If you don't see them, run the following commands and check back.

```powershell
Import-Module PowerRemoteDesktop_Server

Import-Module PowerRemoteDesktop_Viewer
```

Notice: Manifest files are optional (`*.psd1`) and can be removed.

### As a PowerShell Script

It is not mandatory to install this application as a PowerShell module (Even if file extension is `*.psm1`)

You can also load it as a PowerShell Script. Multiple methods exists including:

Invoking Commands Using:

```powershell
IEX (Get-Content .\PowerRemoteDesktop_[Server/Viewer].psm1 -Raw)
```

Loading script from a remote location: 

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/PowerRemoteDesktop_[Server/Viewer].psm1')
```

etc...

## Usage

### Client

`PowerRemoteDesktop_Viewer.psm1` needs to be imported / or installed on local machine.

#### Available Module Functions

```powershell
Invoke-RemoteDesktopViewer
Get-TrustedServers
Remove-TrustedServer
Clear-TrustedServers 
```

#### Invoke-RemoteDesktopViewer

Create a new remote desktop session with a Power Remote Desktop Server.

##### ⚙️ Supported Options:

| Parameter               | Type             | Default    | Description  |
|-------------------------|------------------|------------|--------------|
| ServerAddress           | String           | 127.0.0.1  | Remote server host or address  |
| ServerPort              | Integer          | 2801       | Port number for the remote server |
| SecurePassword          | SecureString     | None       | SecureString object containing the password used for authenticating with the remote server (recommended) |
| Password                | String           | None       | Plain-text password used for authenticating with the remote server (not recommended; use SecurePassword instead)) |
| DisableVerbosity        | Switch           | False      | If specified, the program will suppress verbosity messages |
| UseTLSv1_3              | Switch           | False      | If specified, the program will use TLS v1.3 instead of TLS v1.2 for encryption (recommended if both systems support it) |
| Clipboard               | Enum             | Both       | Specify the clipboard synchronization mode (options include 'Both', 'Disabled', 'Send', and 'Receive'; see below for more detail) |
| ImageCompressionQuality | Integer (0-100)  | 75         | JPEG compression level ranging from 0 (lowest quality) to 100 (highest quality) |
| Resize                  | Switch           | False      | If specified, the remote desktop will be resized according to the 'ResizeRatio' option |
| ResizeRatio             | Integer (30-99)  | 90         | Used in conjunction with the 'Resize' option, specify the resize ratio as a percentage |
| AlwaysOnTop             | Switch           | False      | If specified, the virtual desktop window will be displayed above all other windows |
| PacketSize              | Enum             | Size9216   | Specify the network packet size for streams. Choose a size that is appropriate for your network constraints. |
| BlockSize               | Enum             | Size64     | Specify the size of the screen grid blocks. Choose a size that is appropriate for the remote screen size and the computer's resources (such as CPU and network capabilities) |
| LogonUI                 | Switch           | False      | Request the server to open the LogonUI/Winlogon desktop instead of the default user desktop (requires SYSTEM privilege in the active session) |

##### Clipboard Mode Enum Properties

| Value             | Description                                        | 
|-------------------|----------------------------------------------------|
| Disabled          | Clipboard synchronization is disabled on both the viewer and server sides |
| Receive           | Only incoming clipboard data is allowed                |
| Send              | Only outgoing clipboard data is allowed                 |
| Both              | Clipboard synchronization is allowed on both the viewer and server sides  |

##### PacketSize Mode Enum Properties

| Value             | Description         | 
|-------------------|---------------------|
| Size1024          | 1024 Bytes (1KiB)   |
| Size2048          | 2048 Bytes (2KiB)   |
| Size4096          | 4096 Bytes (4KiB)   |
| Size8192          | 8192 Bytes (8KiB)   |
| Size9216          | 9216 Bytes (9KiB)   |
| Size12288         | 12288 Bytes (12KiB) |
| Size16384         | 16384 Bytes (16KiB) |

##### BlockSize Mode Enum Properties

| Value             | Description      | 
|-------------------|------------------|
| Size32            | 32x32            |
| Size64            | 64x64            |
| Size96            | 96x96            |
| Size128           | 128x128          |
| Size256           | 256x256          |
| Size512           | 512x512          |

##### ⚠️ Important Notices

It is recommended to use SecurePassword instead of a plain-text password, even if the plain-text password is being converted to a SecureString

#### Example

Open a new remote desktop session to '127.0.0.1:2801' using the password 'urCompl3xP@ssw0rd'

```powershell
Invoke-RemoteDesktopViewer -ServerAddress "127.0.0.1" -ServerPort 2801 -SecurePassword (ConvertTo-SecureString -String "urCompl3xP@ssw0rd" -AsPlainText -Force)
```

#### Enumerate Trusted Servers

When connecting to a new remote server for the first time, the viewer will ask if you want to trust the server's fingerprint. If you select the option to 'Always' trust this fingerprint, it will be saved in the local user registry. You can revoke the trust for this fingerprint at any time using the appropriate function.

```powershell
Get-TrustedServers
```

Example output:

````
PS C:\Users\Phrozen\Desktop\Projects\PowerRemoteDesktop> Get-TrustedServers

Detail                           Fingerprint
------                           -----------
@{FirstSeen=18/01/2022 19:40:24} D9F4637463445D6BB9F3EFBF08E06BE4C27035AF
@{FirstSeen=20/01/2022 15:52:33} 3FCBBFB37CF6A9C225F7F582F14AC4A4181BED53
@{FirstSeen=20/01/2022 16:32:14} EA88AADA402864D1864542F7F2A3C49E56F473B0
@{FirstSeen=21/01/2022 12:24:18} 3441CE337A59FC827466FC954F2530C76A3F8FE4
````

### Permanently Delete a Trusted Server

```powershell
Remove-TrustedServer -Fingerprint "<target_ingerprint>"
```

### Permanently Delete all Trusted Servers (Purge)

```powershell
Clear-TrustedServers
```

---

### Server

`PowerRemoteDesktop_Server.psm1` needs to be imported / or installed on local machine.

#### Available Module Functions

```powershell
Invoke-RemoteDesktopServer
```

##### ⚙️ Supported Options:
 
| Parameter              | Type             | Default    | Description  |
|------------------------|------------------|------------|--------------|
| ServerAddress          | String           | 0.0.0.0    | IP address representing the local machine's IP address |
| ServerPort             | Integer          | 2801       | The port number on which to listen for incoming connections |
| SecurePassword         | SecureString     | None       | SecureString object containing the password used for authenticating remote viewers (recommended) |
| Password               | String           | None       | Plain-text password used for authenticating remote viewers (not recommended; use SecurePassword instead) |
| DisableVerbosity       | Switch           | False      | If specified, the program will suppress verbosity messages |
| UseTLSv1_3             | Switch           | False      | If specified, the program will use TLS v1.3 instead of TLS v1.2 for encryption (recommended if both systems support it) |
| Clipboard              | Enum             | Both       | Specify the clipboard synchronization mode (options include 'Both', 'Disabled', 'Send', and 'Receive'; see below for more detail) |
| CertificateFile        | String           | None       | A file containing valid certificate information (x509) that includes the private key  |
| EncodedCertificate     | String           | None       | A base64-encoded representation of the entire certificate file, including the private key |
| ViewOnly               | Switch           | False      | If specified, the remote viewer will only be able to view the desktop and will not have access to the mouse or keyboard |
| PreventComputerToSleep | Switch           | False      | If specified, this option will prevent the computer from entering sleep mode while the server is active and waiting for new connections |
| CertificatePassword    | SecureString     | None       | Specify the password used to access a password-protected x509 certificate provided by the user | 

##### Server Address Examples

| Value             | Description                                                              | 
|-------------------|--------------------------------------------------------------------------|
| 127.0.0.1         | Only listen for connections from the localhost (usually for debugging purposes) |
| 0.0.0.0           | Listen for connections on all network interfaces, including the local network and the internet                       |

##### Clipboard Mode Enum Properties

| Value             | Description                                        | 
|-------------------|----------------------------------------------------|
| Disabled          | Clipboard synchronization is disabled on both the viewer and server sides |
| Receive           | Only incoming clipboard data is allowed                |
| Send              | Only outgoing clipboard data is allowed                 |
| Both              | Clipboard synchronization is allowed on both the viewer and server sides  |

##### ⚠️ Important Notices

1. It is recommended to use SecurePassword instead of a plain-text password, even if the plain-text password is being converted to a SecureString.
2. If you do not specify a custom certificate using 'CertificateFile' or 'EncodedCertificate', a default self-signed certificate will be generated and installed on the local machine (if one does not already exist). This requires administrator privileges. To run the server with a non-privileged account, you must provide your own certificate location.
3. If you do not specify a SecurePassword or Password, a random, complex password will be generated and displayed in the terminal (this password is temporary).

##### Examples

```powershell
Invoke-RemoteDesktopServer -ListenAddress "0.0.0.0" -ListenPort 2801 -SecurePassword (ConvertTo-SecureString -String "urCompl3xP@ssw0rd" -AsPlainText -Force)

Invoke-RemoteDesktopServer -ListenAddress "0.0.0.0" -ListenPort 2801 -SecurePassword (ConvertTo-SecureString -String "urCompl3xP@ssw0rd" -AsPlainText -Force) -CertificateFile "c:\certs\phrozen.p12"
```

#### How to capture LogonUI

As of version 4.0.0, it is possible to capture the LogonUI/Winlogon (UAC Prompt, Windows Login Window, CTRL+ALT+DEL, etc.). 

However, in order to capture the LogonUI, the server must be run under the context of 'NT AUTHORITY/System' in the current active session. 

There are multiple methods for spawning a process as the SYSTEM user in the active session (e.g., PsExec, Process Hacker), but for simplicity I recommend using my PowerRunAsSystem project (available on GitHub and installable through the PowerShell Gallery).

````powershell
Install-Module -Name PowerRunAsSystem
````

Then run bellow command as Administrator.

```powershell
Invoke-InteractiveSystemPowerShell
```

A new PowerShell terminal should appear on your desktop as **NT AUTHORITY/System**

If you follow the steps above, a new PowerShell terminal should appear on your desktop running as the 'NT AUTHORITY/System' user.

From this terminal, you can run the Power Remote Desktop server command and enable the 'LogonUI' option for future Power Remote Desktop viewer connections. 

It's worth noting that if you don't use your own X509 certificate, you will need administrator privileges to create a new server. However, you can easily create your own X509 certificate using tools such as the OpenSSL command line tool.

##### Generate your Certificate

```
openssl req -x509 -sha512 -nodes -days 365 -newkey rsa:4096 -keyout phrozen.key -out phrozen.crt
```

Then export the new certificate (**must include private key**).

```
openssl pkcs12 -export -out phrozen.p12 -inkey phrozen.key -in phrozen.crt
```

##### Integrate to server as a file

Use `CertificateFile`. Example: `c:\tlscert\phrozen.crt`

##### Integrate to server as a base64 representation

Encode an existing certificate using PowerShell

```powershell
[convert]::ToBase64String((Get-Content -path "c:\tlscert\phrozen.crt" -Encoding byte))
```
or on Linux / Mac systems

```
base64 -i /tmp/phrozen.p12
```

You can then pass the output base64 certificate file to parameter `EncodedCertificate` (One line)

## Changelog

### 11 January 2022 (1.0.1 Beta 2)

* Desktop images are now transported in raw bytes instead of base64 string thus slightly improving performances.
* Protocol has drastically changed. It is smoother to read and less prone to errors.
* TLS v1.3 option added (Might not be supported by some systems).
* Several code optimization, refactoring and fixes.
* Password complexity check implemented to avoid lazy passwords.
* Possibility to disable verbose.
* Server & Viewer version synchronization. Same version must be used between the two.

### 12 January 2022 (1.0.2 Beta 3)

* HDPI is completely supported.

### 12 January 2022 (1.0.3 Beta 4)

* Possibility to change desktop image quality.
* Possibility to choose which screen to capture if multiple screens (Monitors) are present on remote machine.

#### Multi Screen Selection

![Multi Screen Example](Assets/multi-screen.png)

### 14 January 2022 (1.0.4 Beta 5)

* Password is stored as SecureString on Viewer. I don't see the point of implementing SecureString sever-side, if you do see the point, please change my mind.
* Server Fingerprint Validation. 
* Possibility to trust a server for current PowerShell Instance or persistantly using a local storage.
* Possibility to manage trusted servers (List, Remove, Remove All)

#### Fingerprint Validation

![Server Fingerprint Validation](Assets/server-fingerprint-validation.png)

### 18 January 2022 (1.0.5 Beta 6)

* Multiple code improvements to support incoming / outgoing events.
* Global cursor state synchronization implemented (Now virtual desktop mouse cursor is the same as remote server).
* Password Generator algorithm fixed.
* Virtual keyboard `]` and `)` correctly sent and interpreted.
* Clipboard synchronization Viewer <-> Server added.
* Server support a new option to only show desktop (Mouse moves, clicks, wheel and keyboard control is disabled in this mode).

### 21 January 2022 (1.0.6)

* TransportMode option removed.
* Desktop streaming performance / speed increased.

### 28 January 2022 (2.0.0)

* Protocol was completely revisited, protocol is now more stable and modular.
* Session concurrency is now supported, multiple viewers can connect at the same time to a server.
* Possibility to stop the server using CTRL+C
* Image quality is now requested by viewer.
* Desktop resize is now made server-side.
* Desktop resize can now be forced and requested by viewer.
* Center virtual desktop glitch fixed.
* Handshake calls (auth + session / worker negociation) will now timeout to avoid possible dead locks.
* Virtual Desktop Form can now be set always on top of other forms.
* Server finally use secure string to handle password-authentication.

### 9 February 2022 (3.0.0)

* Prevent computer to sleep in server side.
* Motion Update now supported in its very first version to increase desktop streaming speed.
* Mouse move works as expected in certain circumstances.
* Keyboard simulation improved.
* Various Optimization and fixes.

### 10 February 2022 (3.1.0)

* Code refactoring and improvement.
* Desktop streaming improvement to gain few more FPS.
* Support password-protected external x509 Certificates.

### 10 March 2022 (4.0.0)

* Huge desktop streaming optimization, FPS rate increased by 65% (even more if tuning BlockSize)
* Desktop resize is now made viewer-side and automatically to simplify the code and efficiency.
* FastResize option is not required anymore.
* Various code optimization / fix.
* WIN Keyboard Key supported.
* Virtual Desktop window opens above the terminal.
* Server now support LogonUI / Winlogon (Beta)

### List of ideas and TODO

* 🟢 Mutual Authentication for SSL/TLS (Client Certificate)                
* 🟠 Interrupt sessions when local resolution has changed.
* 🔴 LogonUI Support.

🟢 = Easy
🟠 = Medium
🔴 = Hard

# Disclaimer

🇺🇸 All source code and projects shared on this Github account by Jean-Pierre LESUEUR and his company, PHROZEN SAS, are provided "as is" without warranty of any kind, either expressed or implied. The user of this code assumes all responsibility for any issues or legal liabilities that may arise from the use, misuse, or distribution of this code. The user of this code also agrees to release Jean-Pierre LESUEUR and PHROZEN SAS from any and all liability for any damages or losses that may result from the use, misuse, or distribution of this code.

By using this code, the user agrees to indemnify and hold Jean-Pierre LESUEUR and PHROZEN SAS harmless from any and all claims, liabilities, costs, and expenses arising from the use, misuse, or distribution of this code. The user also agrees not to hold Jean-Pierre LESUEUR or PHROZEN SAS responsible for any errors or omissions in the code, and to take full responsibility for ensuring that the code meets the user's needs.

This disclaimer is subject to change without notice, and the user is responsible for checking for updates. If the user does not agree to the terms of this disclaimer, they should not use this code.

---

🇫🇷 Tout les codes sources et les projets partagés sur ce compte Github par Jean-Pierre LESUEUR et sa société, PHROZEN SAS, sont fournis "tels quels" sans aucune garantie, expresse ou implicite. L'utilisateur de ce code assume toute responsabilité pour les problèmes ou les responsabilités juridiques qui pourraient résulter de l'utilisation, de l'utilisation abusive ou de la diffusion de ce code. L'utilisateur de ce code accepte également de libérer Jean-Pierre LESUEUR et PHROZEN SAS de toute responsabilité pour tous dommages ou pertes pouvant résulter de l'utilisation, de l'utilisation abusive ou de la diffusion de ce code.

En utilisant ce code, l'utilisateur accepte de garantir et de dégager Jean-Pierre LESUEUR et PHROZEN SAS de toutes réclamations, responsabilités, coûts et dépenses résultant de l'utilisation, de l'utilisation abusive ou de la diffusion de ce code. L'utilisateur accepte également de ne pas tenir Jean-Pierre LESUEUR ou PHROZEN SAS responsable des erreurs ou omissions dans le code et de prendre l'entière responsabilité de s'assurer que le code répond aux besoins de l'utilisateur.

Cette clause de non-responsabilité est sujette à modification sans préavis et l'utilisateur est responsable de vérifier les mises à jour. Si l'utilisateur n'accepte pas les termes de cette clause de non-responsabilité, il ne doit pas utiliser ce code.

---

Made with ❤️ in 🇫🇷
