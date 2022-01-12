<p align="center">
  <img src="icon.png"/>
</p>

# PowerRemoteDesktop

<img src="Screenshot 2022-01-07 at 16.43.53.png" width="100%"/>

*Power Remote Desktop* is a fully functional Remote Desktop Application entirely coded in PowerShell.

It doesn't rely on any existing Remote Desktop Application or Protocol to function. A serious advantage of this application is its nature (PowerShell) and its ease of use and installation.

This project demonstrate why PowerShell contains the word *Power*. It is unfortunately often an underestimated programming language that is not only resumed to running commands or being a more fancy replacement to the old Windows Terminal (cmd).

Tested on:

* Windows 10 - PowerShell Version: 5.1.19041.1320
* Windows 11 - PowerShell Version: 5.1.22000.282

## Features

* Captures Remote Desktop Image with support of HDPI (Beta).
* Supports Mouse Click (Left, Right, Middle), Mouse Moves and Mouse Wheel.
* Supports Keystrokes Simulation (Sending remote key strokes) and few useful shortcuts.
* Traffic is encrypted by default using TLSv1.2 and optionnally using TLSv1.3 (TLS 1.3 might not be possible on older systems).
* Challenge-Based Password Authentication to protect access to server.
* Support custom SSL/TLS Certificate (File or Encoded in base64). If not specified, a default one is generated and installed on local machine (requires Administrator privileges)

## What is still beta

I consider this version as stable but I want to do more tests and have more feedback.

I also want to implement few additional features before releasing the version 1.

## Extended Installation (For Viewer and/or Server)

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

* `ServerAddress`: Remote Server Address.
* `ServerPort`: Remote Server Port.
* `DisableInputControl`: If set to $true, this option disable control events on form (Mouse Clicks, Moves and Keyboard). This option is generally to true during development when connecting to local machine to avoid funny things.
* `Password`: Password used during server authentication.
* `DisableVerbosity`: Disable verbosity (not recommended)
* `TLSv1_3`: Define whether or not client must use SSL/TLS v1.3 to communicate with remote server.

#### Example

`Invoke-RemoteDesktopViewer -ServerAddress "127.0.0.1" -ServerPort 2801 -Password "Jade"`

### Server

`PowerRemoteDesktop_Server.psm1` module first need to be imported / installed on current PowerShell session.

Call `Invoke-RemoteDesktopServer`

Supported options:

* `ListenAddress`: Define in which interface to listen for new viewer.
* `ListenPort`: Define in which port to listen for new viewer.
* `Password`: Define password used during authentication process.
* `CertificateFile`: A valid X509 Certificate (With Private Key) File. If set, this parameter is prioritize.
* `EncodedCertificate`: A valid X509 Certificate (With Private Key) encoded as a Base64 String.
* `TransportMode`: (Raw or Base64) Tell server how to send desktop image to remote viewer. Best method is Raw Bytes but I decided to keep the Base64 transport method as an alternative.
* `TLSv1_3`: Define whether or not TLS v1.3 must be used for communication with Viewer.
* `DisableVerbosity`: Disable verbosity (not recommended)

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

## Changelog

### 11 January 2021

* Desktop images are now transported in raw bytes instead of base64 string thus slightly improving performances. Base64 Transport Method is still available through an option but disabled by default.
* Protocol has drastically changed. It is smoother to read and less prone to errors.
* TLS v1.3 option added (Might not be supported by some systems).
* Several code optimization, refactoring and fixes.
* Password complexity check implemented to avoid lazy passwords.
* Possibility to disable verbose.
* Server & Viewer version synchronization. Same version must be used between the two.

# Disclaimer

We are doing our best to prepare the content of this app. However, PHROZEN SASU cannot
warranty the expressions and suggestions of the contents, as well as its accuracy.
In addition, to the extent permitted by the law, PHROZEN SASU shall not be responsible
for any losses and/or damages due to the usage of the information on our app.

By using our app, you hereby consent to our disclaimer and agree to its terms.

Any links contained in our app may lead to external sites are provided for
convenience only. Any information or statements that appeared in these sites
or app are not sponsored, endorsed, or otherwise approved by PHROZEN SASU.
For these external sites, SubSeven Legacy cannot be held liable for the
availability of, or the content located on or through it.
Plus, any losses or damages occurred from using these contents or the internet
generally.

