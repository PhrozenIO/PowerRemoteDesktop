<p align="center">
  <img src="Assets/icon.png"/>
</p>

# PowerRemoteDesktop

<img src="Assets/demo.png" width="100%"/>

*Power Remote Desktop* is a fully functional Remote Desktop Application entirely coded in PowerShell.

It doesn't rely on any existing Remote Desktop Application or Protocol to function. A serious advantage of this application is its nature (PowerShell) and its ease of use and installation.

This project demonstrate why PowerShell contains the word *Power*. It is unfortunately often an underestimated programming language that is not only resumed to running commands or being a more fancy replacement to the old Windows command-line interpreter (cmd).

Tested on:

* Windows 10 - PowerShell Version: 5.1.19041.1320
* Windows 11 - PowerShell Version: 5.1.22000.282

## Features

https://user-images.githubusercontent.com/2520298/150001915-0982fb1c-a729-4b21-b22c-a58e201bfe27.mp4

* Remote Desktop Streaming with support of HDPI and Scaling.
* Remote Control: Mouse (Moves, Clicks, Wheel) and Key Strokes (Keyboard)
* **Secure**: Network traffic is encrypted using TLSv1.2 or 1.3. Access to server is granted via a challenge-based authentication mechanism (using user defined complex password).
* Network traffic encryption is using whether a default X509 Certificate (Requires Administrator) or your custom X509 Certificate.
* Server certificate fingerprint validation supported and optionally persistent between sessions.
* Clipboard text synchronization between Viewer and Server.
* Mouse cursor icon state is synchronized between Viewer (Virtual Desktop) and Server.
* Multi-Screen (Monitor) support. If remote computer have more than one desktop screen, you can choose which desktop screen to capture.
* View Only mode for demonstration. You can disable remote control abilities and just show your screen to remote peer.

## What is still beta

Version 1.0.5 Beta 6 is the last beta before final version.

No more features will be added in 1.x version, just optimization and bug fix.

## Installation

You will find multiple ways to use this PowerShell Applications. Recommended method would be to install both Server and Viewer using the PowerShell Gallery but you can also do it manually as an installed module or imported script.

### Install as a PowerShell Module from PowerShell Gallery (Recommended)

You can install Power Remote Desktop from PowerShell Gallery. See PowerShell Gallery as the 'equivalent' of Aptitude for Debian or Brew for MacOS.

Run the following commands:

`Install-Module -Name PowerRemoteDesktop_Server -AllowPrerelease`

`Install-Module -Name PowerRemoteDesktop_Viewer -AllowPrerelease`

`AllowPrerelease` is mandatory when current version is marked as a *Prerelease*

Your command prompt will show the following warning:

```
Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its
InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from
'PSGallery'?
```

Answer `Y` to proceed installation.

Both modules should now be available, you can verify using the command:

`Get-Module -ListAvailable`

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

`Import-Module PowerRemoteDesktop_Server`

`Import-Module PowerRemoteDesktop_Viewer`

### Install as a PowerShell Module (Manually / Unmanaged)

To be available, the module must first be present in a registered module path.

You can list module paths with following command:

`Write-Output $env:PSModulePath`

Example Output:

```
C:\Users\Phrozen\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
```

Clone PowerRemoteDesktop repository or download a Github release package.

`git clone https://github.com/DarkCoderSc/PowerRemoteDesktop.git`

Copy both *PowerRemoteDesktop_Viewer* and *PowerRemoteDesktop_Server* folders to desired module path (Ex: `C:\Users\<USER>\Documents\WindowsPowerShell\Modules`)

Both modules should now be available, you can verify using the command:

`Get-Module -ListAvailable`

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

`Import-Module PowerRemoteDesktop_Server`

`Import-Module PowerRemoteDesktop_Viewer`

Notice: Manifest files are optional (`*.psd1`) and can be removed.

### As a PowerShell Script

It is not mandatory to install this application as a PowerShell module (Even if file extension is `*.psm1`)

You can also load it as a PowerShell Script. Multiple methods exists including:

* Invoking Commands Using: `IEX (Get-Content .\PowerRemoteDesktop_Viewer.psm1 -Raw)` and `IEX (Get-Content .\PowerRemoteDesktop_[Server/Viewer].psm1 -Raw)`
* Loading script from a remote location: `IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/PowerRemoteDesktop_[Server/Viewer].psm1)`

etc...

## Usage

### Client

`PowerRemoteDesktop_Viewer.psm1` module first need to be imported / installed on current PowerShell session.

Call `Invoke-RemoteDesktopViewer`

Supported options:

* `ServerAddress` (Default: `127.0.0.1`): Remote server host/address.
* `ServerPort` (Default: `2801`): Remote server port.
* `Password` (Mandatory): Password used for server authentication.
* `DisableVerbosity` (Default: None): If this switch is present, verbosity will be hidden from console.
* `TLSv1_3` (Default: None): If this switch is present, viewer will use TLS v1.3 instead of TLS v1.2. Use this option only if both viewer and server support TLS v1.3.
* `Clipboard` (Default: `Both`): Define clipboard synchronization rules:
    * `Disabled`: Completely disable clipboard synchronization.
    * `Receive`: Update local clipboard with remote clipboard only.
    * `Send`: Send local clipboard to remote peer.
    * `Both`: Clipboards are fully synchronized between Viewer and Server.

#### Example

`Invoke-RemoteDesktopViewer -ServerAddress "127.0.0.1" -ServerPort 2801 -Password "Jade"`

### Server

`PowerRemoteDesktop_Server.psm1` module first need to be imported / installed on current PowerShell session.

Call `Invoke-RemoteDesktopServer`

Supported options:

* `ListenAddress` (Default: `0.0.0.0`): Define in which interface to listen for new viewer.
    * `0.0.0.0` : All interfaces
    * `127.0.0.1`: Localhost interface
    * `x.x.x.x`: Specific interface (Replace `x` with a valid network address)
* `ListenPort` (Default: `2801`): Define in which port to listen for new viewer.
* `Password` (**Mandatory**): Define password used during authentication process.
* `CertificateFile` (Default: **None**): A valid X509 Certificate (With Private Key) File. If set, this parameter is prioritize.
* `EncodedCertificate` (Default: **None**): A valid X509 Certificate (With Private Key) encoded as a Base64 String.
* `TLSv1_3` (Default: None): If this switch is present, server will use TLS v1.3 instead of TLS v1.2. Use this option only if both viewer and server support TLS v1.3.
* `DisableVerbosity` (Default: None): If this switch is present, verbosity will be hidden from console.
* `ImageQuality` (Default: `100`): JPEG Compression level from 0 to 100. 0 = Lowest quality, 100 = Highest quality.      
* `Clipboard` (Default: `Both`): Define clipboard synchronization rules:
    * `Disabled`: Completely disable clipboard synchronization.
    * `Receive`: Update local clipboard with remote clipboard only.
    * `Send`: Send local clipboard to remote peer.
    * `Both`: Clipboards are fully synchronized between Viewer and Server.
* `ViewOnly` (Default: None): If this switch is present, viewer wont be able to take the control of mouse (moves, clicks, wheel) and keyboard. Useful for view session only.

If no certificate option is set, then a default X509 Certificate is generated and installed on local machine (Requires Administrative Privilege)

##### Example

`Invoke-RemoteDesktopServer -ListenAddress "0.0.0.0" -ListenPort 2801 -Password "Jade"`

`Invoke-RemoteDesktopServer -ListenAddress "0.0.0.0" -ListenPort 2801 -Password "Jade" -CertificateFile "c:\certs\phrozen.p12"`

#### Generate and pass your own X509 Certificate

Passing your own X509 Certificate is very useful if you want to avoid running your PowerShell Instance as Administrator.

You can easily create your own X509 Certificate using OpenSSL Command Line Tool.

##### Generate your Certificate

`openssl req -x509 -sha512 -nodes -days 365 -newkey rsa:4096 -keyout phrozen.key -out phrozen.crt`

Then export the new certificate with Private Key Included.

`openssl pkcs12 -export -out phrozen.p12 -inkey phrozen.key -in phrozen.crt`

##### Use it as file

Pass the certificate file to parameter `CertificateFile`.

##### Use it as Encoded Base64 String

First encode your certificate file as base64 string.

`base64 -i phrozen.p12`

Then pass the encoded string to parameter `EncodedCertificate`.

### List trusted servers

It is now possible to persistantly trust server using a local storage (Windows User Registry Hive)

`Get-TrustedServers`

Example output:

````
PS C:\Users\Phrozen\Desktop\Projects\PowerRemoteDesktop> Get-TrustedServers

Detail                           Fingerprint
------                           -----------
@{FirstSeen=14/01/2022 11:06:16} EA88AADA402864D1864542F7F2A3C49E56F473B0
````

### Delete trusted server (Permanently)

`Remove-TrustedServer`

### Delete all trusted servers (Permanently)

`Clear-TrustedServers`

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

### List of ideas and TODO

* 🟢 Support Password Protected external Certificates.
* 🟢 Mutual Authentication for SSL/TLS (Client Certificate).                     
* 🟠 Listen for local/remote screen resolution update event.
* 🔴 Motion Update for Desktop Streaming (Only send and update changing parts of desktop).

🟢 = Easy
🟠 = Medium
🔴 = Hard

# Disclaimer

We are doing our best to prepare the content of this app. However, PHROZEN SASU and / or
Jean-Pierre LESUEUR cannot warranty the expressions and suggestions of the contents,
as well as its accuracy. In addition, to the extent permitted by the law, 
PHROZEN SASU and / or Jean-Pierre LESUEUR shall not be responsible for any losses
and/or damages due to the usage of the information on our app.

By using our app, you hereby consent to our disclaimer and agree to its terms.

Any links contained in our app may lead to external sites are provided for
convenience only. Any information or statements that appeared in these sites
or app are not sponsored, endorsed, or otherwise approved by PHROZEN SASU and / or
Jean-Pierre LESUEUR. For these external sites, PHROZEN SASU and / or Jean-Pierre LESUEUR
cannot be held liable for the availability of, or the content located on or through it.
Plus, any losses or damages occurred from using these contents or the internet
generally.

