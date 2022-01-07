# PowerRemoteDesktop

As the name suggests, Power Remote Desktop is a Remote Desktop application entirely coded in PowerShell.

It does not rely in any existing remote desktop application / protocol to function. It is a remote desktop application completely coded from scratch.

Even the Viewer part (Including the GUI) is coded in PowerShell with the help of WinForms API.

⚠️ This project is actually in its very beginning. Do not use it under a production environment until version is marked as final / stable version.

## Features

* Captures Remote Desktop Image with support of HDPI.
* Supports Mouse Click (Left, Right, Middle), Mouse Moves and Mouse Wheel.
* Supports Keystrokes Simulation (Sending remote key strokes) and few useful shortcuts.
* Traffic is encrypted using TLSv1.2. Soon to support an additional option of TLSv1.3 (Optionnaly).
* Challenge-Based Password Authentication to protect access to server.
* Support custom SSL/TLS Certificate (File or Encoded in base64). If not specified, a default one is generated and installed on local machine (requires Administrator privileges)

## What is really beta

Server client acquirement system is temporary, it works perectly fine (if nothing interfer with normal handshake). I will implement in final version the real client handler system in a separated thread to avoid possible and very rare dead locks.

I will also implement a Read / Write Timeout system followed by a Keep-Alive system to detect ghost connections and avoid again rare dead locks.

I will also improve comments and logging (verbose / normal text) and try to support cursor state monitor (to display the remote cursor state on viewer).

## Extended TODO List

```
* [EASY] Add option for TLS v1.3.        
* [EASY] Version Synchronization.
* [EASY] Support Password Protected external Certificates.
* [EASY] Server Fingerprint Authentication.
* [EASY] Mutual Authentication for SSL/TLS (Client Certificate).
* [EASY] Improve Error Control Flow.        
* [EASY] Synchronize Cursor State.
* [EASY] Improve Comments.
* [EASY] Better detail on Verbose with possibility to disable verbose.
* [EASY] Synchronize Clipboard. 
* [EASY] Handle new client acceptation on a separated Runspace to avoid locks which could cause DoS of the Service.
         This will be naturally fixed when I will implement my final version of client Connection Handler system.

* [MEDIUM] Keep-Alive system to implement Read / Write Timeout.
* [MEDIUM] Improve Virtual Keyboard.
* [MEDIUM] Avoid Base64 for Desktop Steaming (Only if 100% Stable).
           It sounds obvious that writing RAW Bytes using Stream.Write is 100% stable but strangely locally
           it worked like a charm but while testing remotely, it sometimes acted funny. I will investigate about
           this issue and re-implement my other technique. 

* [MEDIUM] Server Concurrency.
* [MEDIUM] Listen for local/remote screen resolution update event.
* [MEDIUM] Multiple Monitor Support.
* [MEDIUM] Improve HDPI Scaling / Quality.
* [MEDIUM+] Motion Update for Desktop Streaming (Only send and update changing parts of desktop).
```

