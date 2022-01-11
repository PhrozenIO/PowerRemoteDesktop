<p align="center">
  <img src="icon.png"/>
</p>

# PowerRemoteDesktop

<img src="Screenshot 2022-01-07 at 16.43.53.png" width="100%"/>

As the name suggests, Power Remote Desktop is a Remote Desktop application entirely coded in PowerShell.

It does not rely in any existing remote desktop application / protocol to function. It is a remote desktop application completely coded from scratch.

Even the Viewer part (Including the GUI) is coded in PowerShell with the help of WinForms API.

Tested on:

* Windows 10 - PowerShell Version: 5.1.19041.1320
* Windows 11 - PowerShell Version: 5.1.22000.282

## Changelog

### 11 January 2021

* Desktop images are now transported in raw bytes instead of base64 string thus slightly improving performances. Base64 Transport Method is still available through an option but disabled by default.
* Protocol has drastically changed. It is smoother to read and less prone to errors.
* TLS v1.3 option added (Might not be supported by some systems).
* Several code optimization, refactoring and fixes.
* Password complexity check implemented to avoid lazy passwords.
* Possibility to disable verbose.
* Server & Viewer version synchronization. Same version must be used between the two.

## Features

* Captures Remote Desktop Image with support of HDPI.
* Supports Mouse Click (Left, Right, Middle), Mouse Moves and Mouse Wheel.
* Supports Keystrokes Simulation (Sending remote key strokes) and few useful shortcuts.
* Traffic is encrypted by default using TLSv1.2 and optionnally using TLSv1.3 (TLS 1.3 might not be possible on older systems).
* Challenge-Based Password Authentication to protect access to server.
* Support custom SSL/TLS Certificate (File or Encoded in base64). If not specified, a default one is generated and installed on local machine (requires Administrator privileges)

## What is still beta

I consider this version as stable but I want to do more tests and have more feedback.

I also want to implement few additional features before releasing the version 1.

## Extended TODO List

```
* [EASY] Do a deep investigation about SecureString and if it applies to current project (to protect password)                    
* [EASY] Support Password Protected external Certificates.
* [EASY] Server Fingerprint Authentication.
* [EASY] Mutual Authentication for SSL/TLS (Client Certificate).        
* [EASY] Synchronize Cursor State.                
* [EASY] Synchronize Clipboard. 
* [MEDIUM] Keep-Alive system to implement Read / Write Timeout.
* [MEDIUM] Improve Virtual Keyboard.    
* [MEDIUM] Server Concurrency.
* [MEDIUM] Listen for local/remote screen resolution update event.
* [MEDIUM] Multiple Monitor Support.
* [MEDIUM] Improve HDPI Scaling / Quality.
* [MEDIUM+] Motion Update for Desktop Streaming (Only send and update changing parts of desktop).
```

## Installation (For Viewer and/or Server)

You can use this script both as a PowerShell Module or Raw Script (Pasted, from Encoded Base64 String, DownloadString(...) etc...).

### As a Module

Choose a registered PowerShell Module location (see echo $env:PSModulePath)

Create a folder called PowerRemoteDesktop_[Viewer/Server] and place the PowerRemoteDesktop_[Viewer/Server].psm1 file inside the new folder.

Open a new PowerShell Window and enter Import-Module PowerRemoteDesktop_[Viewer/Server]

The module should be imported with available functions:

* `Invoke-RemoteDesktopViewer` in the case of `PowerRemoteDesktop_Viewer.psm1`
* `Invoke-RemoteDesktopServer` in the case of `PowerRemoteDesktop_Server.psm1`

### As a Raw Script

You can import both scripts alternatively by:

* Pasting the whole code to a new PowerShell window
* `IEX (Get-Content .\PowerRemoteDesktop_[Viewer/Server].psm1 -Raw)`
* Importing a Base64 encoded version of the code through IEX/Invoke-Expression
* Remote Location through DownloadString(...) then IEX/Invoke-Expression
* Your imagination

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

