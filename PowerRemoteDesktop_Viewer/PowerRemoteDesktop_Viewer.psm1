<#-------------------------------------------------------------------------------

    Power Remote Desktop
    
    In loving memory of my father. 
    Thanks for all you've done.
    you will remain in my heart forever.

    .Developer
        Jean-Pierre LESUEUR (@DarkCoderSc)
        https://www.twitter.com/darkcodersc
        https://github.com/DarkCoderSc
        www.phrozen.io
        jplesueur@phrozen.io
        PHROZEN

    .License
        Apache License
        Version 2.0, January 2004
        http://www.apache.org/licenses/

    .Disclaimer
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
        
-------------------------------------------------------------------------------#>

Add-Type -Assembly System.Windows.Forms

Add-Type @"
    using System;    
    using System.Runtime.InteropServices;

    public static class User32 
    {
        [DllImport("User32.dll")] 
        public static extern bool SetProcessDPIAware();   
    }    
"@

$global:PowerRemoteDesktopVersion = "4.0.0"

$global:HostSyncHash = [HashTable]::Synchronized(@{
    host = $host
    ClipboardText = (Get-Clipboard -Raw)
})

$global:EphemeralTrustedServers = @()

$global:LocalStoragePath = "HKCU:\SOFTWARE\PowerRemoteDesktop_Viewer"
$global:LocalStoragePath_TrustedServers = -join($global:LocalStoragePath, "\TrustedServers")

enum ClipboardMode {
    Disabled = 1
    Receive = 2
    Send = 3
    Both = 4
}

enum ProtocolCommand {
    Success = 1
    Fail = 2
    RequestSession = 3
    AttachToSession = 4
    BadRequest = 5
    ResourceFound = 6
    ResourceNotFound = 7
    LogonUIAccessDenied = 8
    LogonUIWrongSession = 9
}

enum WorkerKind {
    Desktop = 1
    Events = 2
}

enum BlockSize {
    Size32 = 32
    Size64 = 64
    Size96 = 96
    Size128 = 128
    Size256 = 256
    Size512 = 512
}

enum PacketSize {
    Size1024 = 1024
    Size2048 = 2048
    Size4096 = 4096
    Size8192 = 8192
    Size9216 = 9216
    Size12288 = 12288
    Size16384 = 16384
}

function Write-Banner 
{
    <#
        .SYNOPSIS
            Output cool information about current PowerShell module to terminal.
    #>

    Write-Host ""
    Write-Host "Power Remote Desktop - Version " -NoNewLine
    Write-Host $global:PowerRemoteDesktopVersion -ForegroundColor Cyan
    Write-Host "Jean-Pierre LESUEUR (" -NoNewLine
    Write-Host "@DarkCoderSc" -NoNewLine -ForegroundColor Green
    Write-Host ") " -NoNewLine
    Write-Host "#" -NoNewLine -ForegroundColor Blue
    Write-Host "#" -NoNewLine -ForegroundColor White
    Write-Host "#" -ForegroundColor Red
    Write-Host "https://" -NoNewLine -ForegroundColor Green
    Write-Host "www.github.com/darkcodersc"
    Write-Host "https://" -NoNewLine -ForegroundColor Green
    Write-Host "www.phrozen.io" 
    Write-Host ""
    Write-Host "License: Apache License (Version 2.0, January 2004)"
    Write-Host "https://" -NoNewLine -ForegroundColor Green
    Write-Host "www.apache.org/licenses/"
    Write-Host ""
}

function Get-BooleanAnswer
{
    <#
        .SYNOPSIS
            As user to make a boolean choice. Return True if Y and False if N.
    #>
    while ($true)
    {
        $choice = Read-Host "[Y] Yes  [N] No  (Default is ""N"")"
        if (-not $choice)
        {
            $choice = "N"
        }

        switch ($choice)
        {
            "Y"
            {
                return $true
            }

            "N"
            {
                return $false
            }

            default
            {
                Write-Host "Invalid Answer, available options are ""Y , N""" -ForegroundColor Red
            }
        }
    }    
}

function New-RegistryStorage
{
    <#
        .SYNOPSIS
            Create required registry keys for storing persistent data between viewer 
            sessions.

        .DESCRIPTION
            Users doesn't share this storage. If you really wish to, replace HKCU by HKLM (Requires Admin Privilege)
    #>

    try
    {
        if (-not (Test-Path -Path $global:LocalStoragePath))
        {
            Write-Verbose "Create local storage root at ""${global:LocalStoragePath}""..."

            New-Item -Path $global:LocalStoragePath
        }

        if (-not (Test-Path -Path $global:LocalStoragePath_TrustedServers))
        {   
            Write-Verbose "Create local storage child: ""${global:LocalStoragePath}""..."

            New-Item -Path $global:LocalStoragePath_TrustedServers
        }
    }
    catch
    {
        Write-Verbose "Could not write server fingerprint to local storage with error: ""$($_)"""
    }
}

function Write-ServerFingerprintToLocalStorage
{
    <#
        .SYNOPSIS
            Write a trusted server certificate fingerprint to our local storage.

        .PARAMETER Fingerprint
            Type: String
            Default: None
            Description: Fingerprint to store in local storage.
    #>
    param (
        [Parameter(Mandatory=$True)]
        [string] $Fingerprint
    )

    New-RegistryStorage

    # Value is stored as a JSON Object to be easily upgraded and extended in future.
    $value = New-Object -TypeName PSCustomObject -Property @{
        FirstSeen = (Get-Date).ToString()
    }

    New-ItemProperty -Path $global:LocalStoragePath_TrustedServers -Name $Fingerprint -PropertyType "String" -Value ($value | ConvertTo-Json -Compress)  -ErrorAction Ignore    
}

function Remove-TrustedServer
{
    <#
        .SYNOPSIS
            Remove trusted server from local storage.

        .PARAMETER Fingerprint
            Type: String
            Default: None
            Description: Fingerprint to remove from local storage.
    #>
    param (
        [Parameter(Mandatory=$True)]
        [string] $Fingerprint
    )

    if (-not (Test-ServerFingerprintFromLocalStorage -Fingerprint $Fingerprint))
    {
        throw "Could not find fingerprint on trusted server list."
    }

    Write-Host "You are about to permanently delete trusted server -> """ -NoNewline
    Write-Host $Fingerprint -NoNewLine -ForegroundColor Green
    Write-Host """"

    Write-Host "Are you sure ?"

    if (Get-BooleanAnswer)
    {
        Remove-ItemProperty -Path $global:LocalStoragePath_TrustedServers -Name $Fingerprint

        Write-Host "Server successfully untrusted."
    }    
}

function Get-TrustedServers
{
    <#
        .SYNOPSIS
            Return a list of trusted servers fingerprints from local storage.
    #>

    $list = @()

    Get-Item -Path $global:LocalStoragePath_TrustedServers -ErrorAction Ignore | Select-Object -ExpandProperty Property | ForEach-Object { 
        try
        {
            $list += New-Object -TypeName PSCustomObject -Property @{
                Fingerprint = $_
                Detail = (Get-ItemPropertyValue -Path $global:LocalStoragePath_TrustedServers -Name $_) | ConvertFrom-Json
            }
        }
        catch
        { }        
    }

    return $list 
}

function Clear-TrustedServers
{
    <#
        .SYNOPSIS
            Remove all trusted servers from local storage.
    #>

    $trustedServers = Get-TrustedServers
    if (@($trustedServers).Length -eq 0)
    {
        throw "No trusted servers so far."
    }

    Write-Host "You are about to permanently delete $(@(trustedServers).Length) trusted servers."
    Write-Host "Are you sure ?"

    if (Get-BooleanAnswer)
    {
        Remove-Item -Path $global:LocalStoragePath_TrustedServers -Force -Verbose

        Write-Host "Servers successfully untrusted."
    }
}

function Test-ServerFingerprintFromLocalStorage
{
    <#
        .SYNOPSIS
            Check if a server certificate fingerprint was saved to local storage.

        .PARAMETER Fingerprint
            Type: String
            Default: None
            Description: Fingerprint to check in local storage.
    #>
    param (
        [Parameter(Mandatory=$True)]
        [string] $Fingerprint
    )

    return (Get-ItemProperty -Path $global:LocalStoragePath_TrustedServers -Name $Fingerprint -ErrorAction Ignore)
}

function Get-SHA512FromString
{
    <#
        .SYNOPSIS
            Return the SHA512 value from string.

        .PARAMETER String
            Type: String
            Default : None
            Description: A String to hash.

        .EXAMPLE
            Get-SHA512FromString -String "Hello, World"
    #>
    param (
        [Parameter(Mandatory=$True)]
        [string] $String
    )

    $buffer = [IO.MemoryStream]::new([byte[]][char[]]$String)

    return (Get-FileHash -InputStream $buffer -Algorithm SHA512).Hash
}

function Resolve-AuthenticationChallenge
{
    <#
        .SYNOPSIS
            Algorithm to solve the server challenge during password authentication.
        
        .DESCRIPTION
            Server needs to resolve the challenge and keep the solution in memory before sending
            the candidate to remote peer.

        .PARAMETER Password
            Type: SecureString
            Default: None
            Description: Secure String object containing the password for resolving challenge.            

        .PARAMETER Candidate
            Type: String
            Default: None
            Description:
                Random string used to solve the challenge. This string is public and is set across network by server.
                Each time a new connection is requested to server, a new candidate is generated.

        .EXAMPLE
            Resolve-AuthenticationChallenge -Password "s3cr3t!" -Candidate "rKcjdh154@]=Ldc"
    #>
    param (        
       [Parameter(Mandatory=$True)]
       [SecureString] $SecurePassword, 

       [Parameter(Mandatory=$True)]
       [string] $Candidate
    )

    $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    try
    {
        $solution = -join($Candidate, ":", [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR))

        for ([int] $i = 0; $i -le 1000; $i++)
        {
            $solution = Get-SHA512FromString -String $solution
        }

        return $solution
    }
    finally
    {
        [Runtime.InteropServices.Marshal]::FreeBSTR($BSTR)
    }
}

class ClientIO {
    [string] $RemoteAddress
    [int] $RemotePort
    [bool] $UseTLSv1_3

    [System.Net.Sockets.TcpClient] $Client = $null
    [System.Net.Security.SslStream] $SSLStream = $null
    [System.IO.StreamWriter] $Writer = $null
    [System.IO.StreamReader] $Reader = $null
    [System.IO.BinaryReader] $BinaryReader = $null

    ClientIO(
        [string] $RemoteAddress = "127.0.0.1",
        [int] $RemotePort = 2801,
        [bool] $UseTLSv1_3 = $false
    ) {
        $this.RemoteAddress = $RemoteAddress
        $this.RemotePort = $RemotePort
        $this.UseTLSv1_3 = $UseTLSv1_3
    }

    [void]Connect() {
        <#
            .SYNOPSIS
                Open a new connection to remote server.
                Create required streams and open a new secure connection with peer.
        #>
        Write-Verbose "Connect: ""$($this.RemoteAddress):$($this.RemotePort)..."""

        $this.Client = New-Object System.Net.Sockets.TcpClient($this.RemoteAddress, $this.RemotePort)

        Write-Verbose "Connected."

        if ($this.UseTLSv1_3)
        {
            $TLSVersion = [System.Security.Authentication.SslProtocols]::TLS13
        }
        else {
            $TLSVersion = [System.Security.Authentication.SslProtocols]::TLS12
        }  

        Write-Verbose "Establish an encrypted tunnel using: ${TLSVersion}..."

        $this.SSLStream = New-object System.Net.Security.SslStream(
            $this.Client.GetStream(),
            $false,
            {
                param(
                    $Sendr,
                    $Certificate,
                    $Chain,
                    $Policy
                ) 

                if (
                    (Test-ServerFingerprintFromLocalStorage -Fingerprint $Certificate.Thumbprint) -or
                    $global:EphemeralTrustedServers -contains $Certificate.Thumbprint                
                )
                {
                    Write-Verbose "Fingerprint already known and trusted: ""$($Certificate.Thumbprint)"""

                    return $true
                }
                else
                {
                    Write-Verbose "@Remote Server Certificate:"            
                    Write-Verbose $Certificate
                    Write-Verbose "---"                

                    Write-Host "Untrusted Server Certificate Fingerprint: """ -NoNewLine
                    Write-Host $Certificate.Thumbprint -NoNewline -ForegroundColor Green
                    Write-Host """"

                    while ($true)
                    {
                        Write-Host "`r`nDo you want to trust current server ?"
                        $choice = Read-Host "[A] Always  [Y] Yes  [N] No  [?] Help  (Default is ""N"")"
                        if (-not $choice)
                        {
                            $choice = "N"
                        }

                        switch ($choice)
                        {
                            "?"
                            {
                                Write-Host ""

                                Write-Host "[" -NoNewLine
                                Write-Host "A" -NoNewLine -ForegroundColor Cyan
                                Write-Host "] Always trust current server (Persistent between PowerShell Instances)"

                                Write-Host "[" -NoNewLine
                                Write-Host "Y" -NoNewLine -ForegroundColor Cyan
                                Write-Host "] Trust current server during current PowerShell Instance lifetime (Temporary)."

                                Write-Host "[" -NoNewLine
                                Write-Host "N" -NoNewLine -ForegroundColor Cyan
                                Write-Host "] Don't trust current server. Connection is aborted (Recommeneded if you don't recognize server fingerprint)."

                                Write-Host "[" -NoNewLine
                                Write-Host "?" -NoNewLine -ForegroundColor Cyan
                                Write-Host "] Current help output."

                                Write-Host ""
                            }

                            "A" 
                            {
                                Write-ServerFingerprintToLocalStorage -Fingerprint $Certificate.Thumbprint

                                return $true
                            }

                            "Y"
                            {
                                $global:EphemeralTrustedServers += $Certificate.Thumbprint

                                return $true
                            }

                            "N"
                            {
                                return $false
                            }

                            default
                            {
                                Write-Host "Invalid Answer, available options are ""A , Y , N , H""" -ForegroundColor Red
                            }
                        }
                    }                
                }
            }
        )              

        $this.SSLStream.AuthenticateAsClient(
            "PowerRemoteDesktop",
            $null,
            $TLSVersion,
            $null
        )

        if (-not $this.SSLStream.IsEncrypted)
        {
            throw "Could not establish a secure communication channel with remote server."
        }

        $this.SSLStream.WriteTimeout = 5000

        $this.Writer = New-Object System.IO.StreamWriter($this.SSLStream)
        $this.Writer.AutoFlush = $true

        $this.Reader = New-Object System.IO.StreamReader($this.SSLStream) 

        $this.BinaryReader = New-Object System.IO.BinaryReader($this.SSLStream)

        Write-Verbose "Encrypted tunnel opened and ready for use."               
    }

    [void]Authentify([SecureString] $SecurePassword) {
        <#
            .SYNOPSIS
                Handle authentication process with remote peer.

            .PARAMETER Password
                Type: SecureString
                Default: None
                Description: Secure String object containing the password.                

            .EXAMPLE
                .Authentify((ConvertTo-SecureString -String "urCompl3xP@ssw0rd" -AsPlainText -Force))
        #>

        Write-Verbose "Authentify with remote server (Challenged-Based Authentication)..."

        $candidate = $this.Reader.ReadLine()                        

        $challengeSolution = Resolve-AuthenticationChallenge -Candidate $candidate -SecurePassword $SecurePassword   

        Write-Verbose "@Challenge:"
        Write-Verbose "Candidate: ""${candidate}"""
        Write-Verbose "Solution: ""${challengeSolution}"""
        Write-Verbose "---"            

        $this.Writer.WriteLine($challengeSolution)

        $result = $this.Reader.ReadLine()
        if ($result -eq [ProtocolCommand]::Success)
        {
            Write-Verbose "Solution accepted. Authentication success."                
        }            
        else 
        {
            throw "Solution declined. Authentication failed."                
        }
    
    }

    [string] RemoteAddress() {
        return $this.Client.Client.RemoteEndPoint.Address
    }

    [int] RemotePort() {
        return $this.Client.Client.RemoteEndPoint.Port
    }

    [string] LocalAddress() {
        return $this.Client.Client.LocalEndPoint.Address
    }    

    [int] LocalPort() {
        return $this.Client.Client.LocalEndPoint.Port
    }

    [string] ReadLine([int] $Timeout) 
    {
        <#
            .SYNOPSIS
                Read string message from remote peer with timeout support.

            .PARAMETER Timeout
                Type: Integer                
                Description: Maximum period of time to wait for incomming data.
        #>
        $defautTimeout = $this.SSLStream.ReadTimeout
        try
        {
            $this.SSLStream.ReadTimeout = $Timeout

            return $this.Reader.ReadLine()        
        }
        finally
        {
            $this.SSLStream.ReadTimeout = $defautTimeout
        }        
    }

    [string] ReadLine() 
    {
        <#
            .SYNOPSIS
                Shortcut to Reader ReadLine method. No timeout support.
        #>
        return $this.Reader.ReadLine()
    }

    [void] WriteJson([PSCustomObject] $Object)
    {
        <#
            .SYNOPSIS
                Transform a PowerShell Object as a JSON Representation then send to remote
                peer.

            .PARAMETER Object
                Type: PSCustomObject
                Description: Object to be serialized in JSON.    
        #>

        $this.Writer.WriteLine(($Object | ConvertTo-Json -Compress))
    }

    [void] WriteLine([string] $Value)
    {
        $this.Writer.WriteLine($Value)
    }

    [PSCustomObject] ReadJson([int] $Timeout)
    {
        <#
            .SYNOPSIS
                Read json string from remote peer and attempt to deserialize as a PowerShell Object.

            .PARAMETER Timeout
                Type: Integer                
                Description: Maximum period of time to wait for incomming data.
        #>
        return ($this.ReadLine($Timeout) | ConvertFrom-Json)
    }

    [PSCustomObject] ReadJson()
    {
        <#
            .SYNOPSIS
                Alternative to ReadJson without timeout support.                
        #>
        return ($this.ReadLine() | ConvertFrom-Json)    
    }

    [void]Close() {
        <#
            .SYNOPSIS
                Release Streams and Connections.
        #>
        if ($this.Writer)
        {
            $this.Writer.Close()
        }

        if ($this.Reader)
        {
            $this.Reader.Close()
        }

        if ($this.BinaryReader)
        {
            $this.BinaryReader.Close()
        }

        if ($this.SSLStream)
        {
            $this.SSLStream.Close()
        }

        if ($this.Client)
        {            
            $this.Client.Close()
        }
    }
}

class ViewerConfiguration
{
    [bool] $RequireResize = $false    
    [int] $RemoteDesktopWidth = 0
    [int] $RemoteDesktopHeight = 0
    [int] $VirtualDesktopWidth = 0
    [int] $VirtualDesktopHeight = 0
    [int] $ScreenX_Delta = 0
    [int] $ScreenY_Delta = 0
    [float] $ScreenX_Ratio = 1
    [float] $ScreenY_Ratio = 1    
}

class ViewerSession
{
    [PSCustomObject] $ServerInformation = $null
    [ViewerConfiguration] $ViewerConfiguration = $null

    [string] $ServerAddress = "127.0.0.1"
    [string] $ServerPort = 2801
    [SecureString] $SecurePassword = $null
    [bool] $UseTLSv1_3 = $false       
    [int] $ImageCompressionQuality = 100 
    [int] $ResizeRatio = 0
    [PacketSize] $PacketSize = [PacketSize]::Size9216
    [BlockSize] $BlockSize = [BlockSize]::Size64
    [bool] $LogonUI = $false

    [ClientIO] $ClientDesktop = $null
    [ClientIO] $ClientEvents = $null

    ViewerSession(        
        [string] $ServerAddress,
        [int] $ServerPort,
        [SecureString] $SecurePassword        
    )    
    {                    
        # Or: System.Management.Automation.Runspaces.MaxPort (High(Word))
        if ($ServerPort -lt 0 -and $ServerPort -gt 65535)
        {
            throw "Invalid TCP Port (0-65535)"
        }

        $this.ServerAddress = $ServerAddress
        $this.ServerPort = $ServerPort 
        $this.SecurePassword = $SecurePassword
    }

    [void] OpenSession() {
        <#
            .SYNOPSIS
                Request a new session with remote server.
        #>        

        Write-Verbose "Request new session with remote server: ""$($this.ServerAddress):$($this.ServerPort)""..."

        if ($this.ServerInformation)
        {
            throw "A session already exists."
        }

        Write-Verbose "Establish first contact with remote server..."
        
        $client = [ClientIO]::New($this.ServerAddress, $this.ServerPort, $this.UseTLSv1_3)
        try
        {
            $client.Connect()        

            $client.Authentify($this.SecurePassword)

            Write-Verbose "Request session..."

            $client.WriteLine(([ProtocolCommand]::RequestSession))

            $this.ServerInformation = $client.ReadJson()

            Write-Verbose "@ServerInformation:"
            Write-Verbose $this.ServerInformation
            Write-Verbose "---"

            if (
                (-not ($this.ServerInformation.PSobject.Properties.name -contains "SessionId")) -or
                (-not ($this.ServerInformation.PSobject.Properties.name -contains "Version")) -or
                (-not ($this.ServerInformation.PSobject.Properties.name -contains "ViewOnly")) -or

                (-not ($this.ServerInformation.PSobject.Properties.name -contains "MachineName")) -or
                (-not ($this.ServerInformation.PSobject.Properties.name -contains "Username")) -or
                (-not ($this.ServerInformation.PSobject.Properties.name -contains "WindowsVersion")) -or                                      
                (-not ($this.ServerInformation.PSobject.Properties.name -contains "Screens"))                
            )
            {
                throw "Invalid server information object."
            }  

            Write-Verbose "Server informations acknowledged, prepare and send our expectation..."

            if ($this.ServerInformation.Version -ne $global:PowerRemoteDesktopVersion)
            {
                throw "Server and Viewer version mismatch.`r`n`
                Local: ""${global:PowerRemoteDesktopVersion}""`r`n`
                Remote: ""$($this.ServerInformation.Version)""`r`n`
                You cannot use two different version between Viewer and Server."
            }

            if ($this.ServerInformation.ViewOnly)
            {
                Write-Host "You are accessing a read-only desktop." -ForegroundColor Cyan
            }
            
            # Define which screen we want to capture
            $selectedScreen = $null

            if ($this.ServerInformation.Screens.Length -gt 1)
            {
                Write-Verbose "Remote server have $($this.ServerInformation.Screens.Length) screens."

                Write-Host "Remote server have " -NoNewLine
                Write-Host $($this.ServerInformation.Screens.Length) -NoNewLine -ForegroundColor Green
                Write-Host " different screens:`r`n"

                foreach ($screen in $this.ServerInformation.Screens)
                {
                    Write-Host $screen.Id -NoNewLine -ForegroundColor Cyan
                    Write-Host " - $($screen.Name)" -NoNewLine

                    if ($screen.Primary)
                    {
                        Write-Host " (" -NoNewLine
                        Write-Host "Primary" -NoNewLine -ForegroundColor Cyan
                        Write-Host ")" -NoNewLine
                    }

                    Write-Host ""
                }                                    

                while ($true)
                {
                    $choice = Read-Host "`r`nPlease choose which screen index to capture (Default: Primary)"

                    if (-not $choice)
                    {
                        # Select-Object -First 1 should also grab the Primary Screen (Since it is ordered).
                        $selectedScreen = $this.ServerInformation.Screens | Where-Object -FilterScript { $_.Primary -eq $true }
                    }
                    else 
                    {
                        if (-not $choice -is [int]) {
                            Write-Host "You must enter a valid index (integer), starting at 1."

                            continue
                        }                    

                        $selectedScreen = $this.ServerInformation.Screens | Where-Object -FilterScript { $_.Id -eq $choice }

                        if (-not $selectedScreen)
                        {
                            Write-Host "Invalid choice, please choose an existing screen index." -ForegroundColor Red
                        }
                    }

                    if ($selectedScreen)
                    {                        
                        break
                    }
                }            
            }
            else
            {
                $selectedScreen = $this.ServerInformation.Screens | Select-Object -First 1
            }            

            # Define our Virtual Desktop Form constraints
            $localScreenWidth = Get-LocalScreenWidth
            $localScreenHeight = (Get-LocalScreenHeight) - (Get-WindowCaptionHeight)

            $this.ViewerConfiguration = [ViewerConfiguration]::New()    

            $this.ViewerConfiguration.RemoteDesktopWidth = $selectedScreen.Width             
            $this.ViewerConfiguration.RemoteDesktopHeight = $selectedScreen.Height

            # If remote screen is bigger than local screen, we will resize remote screen to fit 90% of local screen.
            # Supports screen orientation (Horizontal / Vertical)
            if ($localScreenWidth -le $selectedScreen.Width -or $localScreenHeight -le $selectedScreen.Height)
            {                          
                $adjustRatio = 90

                $adjustVertically = $localScreenWidth -gt $localScreenHeight

                if ($adjustVertically)
                {
                    $this.ViewerConfiguration.VirtualDesktopWidth = [math]::Round(($localScreenWidth * $adjustRatio) / 100)
                    
                    $remoteResizedRatio = [math]::Round(($this.ViewerConfiguration.VirtualDesktopWidth * 100) / $selectedScreen.Width)

                    $this.ViewerConfiguration.VirtualDesktopHeight = [math]::Round(($selectedScreen.Height * $remoteResizedRatio) / 100)
                }
                else
                {
                    $this.ViewerConfiguration.VirtualDesktopHeight = [math]::Round(($localScreenHeight * $adjustRatio) / 100)
                    
                    $remoteResizedRatio = [math]::Round(($this.ViewerConfiguration.VirtualDesktopHeight * 100) / $selectedScreen.Height)

                    $this.ViewerConfiguration.VirtualDesktopWidth = [math]::Round(($selectedScreen.Width * $remoteResizedRatio) / 100)
                }                        
            }
            else
            {                                  
                $this.ViewerConfiguration.VirtualDesktopWidth = $selectedScreen.Width
                $this.ViewerConfiguration.VirtualDesktopHeight = $selectedScreen.Height                              
            }    

            # If remote desktop resize is forced, we apply defined ratio to current configuration            
            if ($this.ResizeRatio -ge 30 -and $this.ResizeRatio -le 99)
            {                
                $this.ViewerConfiguration.VirtualDesktopWidth = ($selectedScreen.Width * $this.ResizeRatio) / 100 
                $this.ViewerConfiguration.VirtualDesktopHeight = ($selectedScreen.Height * $this.ResizeRatio) / 100                
            }

            $this.ViewerConfiguration.RequireResize = $this.ViewerConfiguration.VirtualDesktopWidth -ne $selectedScreen.Width -or
                                                      $this.ViewerConfiguration.VirtualDesktopHeight -ne $selectedScreen.Height
            
            $this.ViewerConfiguration.ScreenX_Delta = $selectedScreen.X
            $this.ViewerConfiguration.ScreenY_Delta = $selectedScreen.Y

            if ($this.ViewerConfiguration.RequireResize)
            {            
                $this.ViewerConfiguration.ScreenX_Ratio = $selectedScreen.Width / $this.ViewerConfiguration.VirtualDesktopWidth
                $this.ViewerConfiguration.ScreenY_Ratio = $selectedScreen.Height / $this.ViewerConfiguration.VirtualDesktopHeight                
            } 

            $viewerExpectation = New-Object PSCustomObject -Property @{    
                ScreenName = $selectedScreen.Name 
                ImageCompressionQuality = $this.ImageCompressionQuality
                PacketSize = $this.PacketSize
                BlockSize = $this.BlockSize
                LogonUI = $this.LogonUI                       
            }                       

            Write-Verbose "@ViewerExpectation:"
            Write-Verbose $viewerExpectation
            Write-Verbose "---"

            $client.WriteJson($viewerExpectation)

            switch ([ProtocolCommand] $client.ReadLine(5 * 1000))
            {
                ([ProtocolCommand]::Success)
                {
                    break
                }    

                ([ProtocolCommand]::LogonUIAccessDenied)
                {
                    throw "Could not access LogonUI / Winlogon desktop.`r`n" +
                          "To access LogonUI desktop, you must have ""NT AUTHORITY/System"" privilege in current active session."

                    break
                }

                ([ProtocolCommand]::LogonUIWrongSession)
                {
                    throw "Could not access LogonUI / Winlogon desktop.`r`n"
                          "To access LogonUI desktop, server process must be running under active Windows Session."  

                    break
                }

                default
                {
                    throw "Remote server did not acknoledged our expectation in time."
                }
            }            
        } 
        catch
        {            
            $this.CloseSession()

            throw "Could not open a new session with error: ""$($_)"""
        }    
        finally
        {
            if ($client)
            {
                $client.Close()
            }
        }    
    }

    [ClientIO] ConnectWorker([WorkerKind] $WorkerKind)
    {
        Write-Verbose "Connect new worker: ""$WorkerKind""..."

        $this.CheckSession()

        $client = [ClientIO]::New($this.ServerAddress, $this.ServerPort, $this.UseTLSv1_3)
        try
        {            
            $client.Connect()

            $client.Authentify($this.SecurePassword)

            $client.WriteLine(([ProtocolCommand]::AttachToSession))

            Write-Verbose "Attach worker to remote session ""$($this.ServerInformation.SessionId)"""

            $client.WriteLine($this.ServerInformation.SessionId)

            switch ([ProtocolCommand] $client.ReadLine(5 * 1000))
            {
                ([ProtocolCommand]::ResourceFound)
                {
                    Write-Verbose "Worker successfully attached to session, define which kind of worker we are..."

                    $client.WriteLine($WorkerKind)

                    Write-Verbose "Worker ready."

                    break
                }

                ([ProtocolCommand]::ResourceNotFound)
                {
                    throw "Server could not locate session."
                }                

                default
                {
                    throw "Unexpected answer from remote server for session attach."
                }
            }

            return $client
        }
        catch
        {
            if ($client)
            {
                $client.Close()
            }

            throw "Could not connect worker with error: $($_)"
        }
    }

    [void] ConnectDesktopWorker()
    {
        Write-Verbose "Create new desktop streaming worker..."

        $this.ClientDesktop = $this.ConnectWorker([WorkerKind]::Desktop)
    }

    [void] ConnectEventsWorker()
    {
        Write-Verbose "Create new event event (in/out) worker..."

        $this.ClientEvents = $this.ConnectWorker([WorkerKind]::Events)
    }    

    [bool] HasSession()
    {
        return $this.ServerInformation -and $this.ViewerConfiguration
    }

    [void] CheckSession()
    {
        if (-not $this.HasSession)
        {
            throw "Session is missing."
        }
    }

    [void] CloseSession() {
        <#
            .SYNOPSIS
                Close an existing session with remote server.
                Terminate active connections and reset session informations.
        #>

        Write-Verbose "Close existing session..."

        if ($this.ClientDesktop)
        {
            $this.ClientDesktop.Close()
        }

        if ($this.ClientEvents)
        {
            $this.ClientEvents.Close()
        }        

        $this.ClientDesktop = $null
        $this.ClientEvents = $null
        
        $this.ServerInformation = $null
        $this.ViewerConfiguration = $null
        
        Write-Verbose "Session closed."
    }

}

$global:VirtualDesktopUpdaterScriptBlock = {   
    try
    {       
        $packetSize = [int]$Param.packetSize        

        # SizeOf(DWORD) * 3 (SizeOf(Desktop) + SizeOf(Left) + SizeOf(Top))
        $struct = New-Object -TypeName byte[] -ArgumentList (([Runtime.InteropServices.Marshal]::SizeOf([System.Type][UInt32])) * 3)
            
        $stream = New-Object System.IO.MemoryStream

        $scene = $null
        $sceneGraphics = $null

        $destPoint = [System.Drawing.Point]::New(0, 0)

        $scene = [System.Drawing.Bitmap]::New(
            $Param.ViewerConfiguration.RemoteDesktopWidth,
            $Param.ViewerConfiguration.RemoteDesktopHeight
        )

        $sceneGraphics = [System.Drawing.Graphics]::FromImage($scene)                            
        $sceneGraphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy  

        $Param.VirtualDesktopSyncHash.VirtualDesktop.Picture.Image = $scene # Assign our scene

        # Wait until the virtual desktop form is shown to user desktop.
        while (-not $Param.VirtualDesktopSyncHash.VirtualDesktop.Form.Visible)
        {
            Start-Sleep -Milliseconds 100
        }

        # Tiny hack to correctly bring to front window, this is the most effective technique so far.
        $Param.VirtualDesktopSyncHash.VirtualDesktop.Form.TopMost = $true        
        $Param.VirtualDesktopSyncHash.VirtualDesktop.Form.TopMost = $false

        while ($true)
        {                              
            try
            {             
                $null = $Param.Client.SSLStream.Read($struct, 0, $struct.Length)  

                $totalBufferSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($struct, 0x0)
                $destPoint.X = [System.Runtime.InteropServices.Marshal]::ReadInt32($struct, 0x4)
                $destPoint.Y = [System.Runtime.InteropServices.Marshal]::ReadInt32($struct, 0x8)               

                $stream.SetLength($totalBufferSize)

                $stream.Position = 0  
                do
                {
                    $bufferSize = $stream.Length - $stream.Position
                    if ($bufferSize -gt $packetSize)
                    {
                        $bufferSize = $packetSize
                    }    
                            
                    $null = $stream.Write($Param.Client.BinaryReader.ReadBytes($bufferSize), 0, $bufferSize)
                } until ($stream.Position -eq $stream.Length)                                                                               
                   
                if ($stream.Length -eq 0)
                {
                    continue
                }
                                             
                # Next Iterations
                $sceneGraphics.DrawImage(
                    [System.Drawing.Image]::FromStream($stream),
                    $destPoint
                )                        
                
                $Param.VirtualDesktopSyncHash.VirtualDesktop.Picture.Invalidate()              
            }
            catch 
            {              
                break
            }                            
        }
    }
    finally
    {        
        if ($scene)
        {
            $scene.Dispose()
        }

        if ($sceneGraphics)
        {
            $sceneGraphics.Dispose()
        }

        if ($stream)
        {
            $stream.Close()
        }

        $Param.VirtualDesktopSyncHash.VirtualDesktop.Form.Close()
    }
}

$global:IngressEventScriptBlock = {

    enum CursorType {
        IDC_APPSTARTING
        IDC_ARROW
        IDC_CROSS
        IDC_HAND
        IDC_HELP
        IDC_IBEAM
        IDC_ICON
        IDC_NO
        IDC_SIZE
        IDC_SIZEALL
        IDC_SIZENESW
        IDC_SIZENS
        IDC_SIZENWSE
        IDC_SIZEWE
        IDC_UPARROW
        IDC_WAIT
    }

    enum InputEvent {
        KeepAlive = 0x1
        MouseCursorUpdated = 0x2 
        ClipboardUpdated = 0x3
        DesktopActive = 0x4
        DesktopInactive = 0x5         
    }    

    enum ClipboardMode {
        Disabled = 1
        Receive = 2
        Send = 3
        Both = 4
    }

    while ($true)                    
    {        
        try
        {         
            $jsonEvent = $Param.Client.Reader.ReadLine()                        
        }
        catch
        { break }        

        try
        {
            $aEvent = $jsonEvent | ConvertFrom-Json
        }
        catch
        { continue }

        if (-not ($aEvent.PSobject.Properties.name -match "Id"))
        { continue }                       

        switch ([InputEvent] $aEvent.Id)
        {        
            # Remote Global Mouse Cursor State Changed (Icon)
            ([InputEvent]::MouseCursorUpdated)
            {                
                if (-not ($aEvent.PSobject.Properties.name -match "Cursor"))
                { continue }                 

                $cursor = [System.Windows.Forms.Cursors]::Arrow

                switch ([CursorType] $aEvent.Cursor)
                {                    
                    ([CursorType]::IDC_APPSTARTING) { $cursor = [System.Windows.Forms.Cursors]::AppStarting }                    
                    ([CursorType]::IDC_CROSS) { $cursor = [System.Windows.Forms.Cursors]::Cross }
                    ([CursorType]::IDC_HAND) { $cursor = [System.Windows.Forms.Cursors]::Hand }
                    ([CursorType]::IDC_HELP) { $cursor = [System.Windows.Forms.Cursors]::Help }
                    ([CursorType]::IDC_IBEAM) { $cursor = [System.Windows.Forms.Cursors]::IBeam }                    
                    ([CursorType]::IDC_NO) { $cursor = [System.Windows.Forms.Cursors]::No }                    
                    ([CursorType]::IDC_SIZENESW) { $cursor = [System.Windows.Forms.Cursors]::SizeNESW }
                    ([CursorType]::IDC_SIZENS) { $cursor = [System.Windows.Forms.Cursors]::SizeNS }
                    ([CursorType]::IDC_SIZENWSE) { $cursor = [System.Windows.Forms.Cursors]::SizeNWSE }
                    ([CursorType]::IDC_SIZEWE) { $cursor = [System.Windows.Forms.Cursors]::SizeWE }
                    ([CursorType]::IDC_UPARROW) { $cursor = [System.Windows.Forms.Cursors]::UpArrow }
                    ([CursorType]::IDC_WAIT) { $cursor = [System.Windows.Forms.Cursors]::WaitCursor }

                     {( $_ -eq ([CursorType]::IDC_SIZE) -or $_ -eq ([CursorType]::IDC_SIZEALL) )}
                     {
                        $cursor = [System.Windows.Forms.Cursors]::SizeAll 
                    }
                }

                try 
                {
                    $Param.VirtualDesktopSyncHash.VirtualDesktop.Picture.Cursor = $cursor
                }
                catch 
                {}

                break
            }

            ([InputEvent]::ClipboardUpdated)
            {
                if ($Param.Clipboard -eq ([ClipboardMode]::Disabled) -or $Param.Clipboard -eq ([ClipboardMode]::Send))
                { continue }

                if (-not ($aEvent.PSobject.Properties.name -match "Text"))
                { continue } 
                
                $HostSyncHash.ClipboardText = $aEvent.Text

                Set-Clipboard -Value $aEvent.Text

                break
            }

            ([InputEvent]::DesktopActive)
            {                
                break
            }

            ([InputEvent]::DesktopInactive)
            {                
                break
            }
        }
    }    
}

$global:EgressEventScriptBlock = {

    enum OutputEvent {
        # 0x1 0x2 0x3 are at another place (GUI Thread)
        KeepAlive = 0x4        
        ClipboardUpdated = 0x5
    }  

    enum ClipboardMode {
        Disabled = 1
        Receive = 2
        Send = 3
        Both = 4
    }

    function Send-Event
    {
        <#
            .SYNOPSIS
                Send an event to remote peer.

            .PARAMETER AEvent
                Define what kind of event to send.

            .PARAMETER Data
                An optional object containing additional information about the event. 
        #>
        param (            
            [Parameter(Mandatory=$True)]
            [OutputEvent] $AEvent,

            [PSCustomObject] $Data = $null
        )

        try 
        {
            if (-not $Data)
            {
                $Data = New-Object -TypeName PSCustomObject -Property @{
                    Id = $AEvent 
                }
            }
            else
            {
                $Data | Add-Member -MemberType NoteProperty -Name "Id" -Value $AEvent
            }            

            $Param.OutputEventSyncHash.Writer.WriteLine(($Data | ConvertTo-Json -Compress))  

            return $true
        }
        catch 
        { 
            return $false
        }
    }

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($true)
    {
        # Events that occurs every seconds needs to be placed bellow.
        # If no event has occured during this second we send a Keep-Alive signal to
        # remote peer and detect a potential socket disconnection.
        if ($stopWatch.ElapsedMilliseconds -ge 1000)
        {
            try
            {
                $eventTriggered = $false

                if ($Param.Clipboard -eq ([ClipboardMode]::Both) -or $Param.Clipboard -eq ([ClipboardMode]::Send))
                {
                    # IDEA: Check for existing clipboard change event or implement a custom clipboard
                    # change detector using "WM_CLIPBOARDUPDATE" for example (WITHOUT INLINE C#)
                    # It is not very important but it would avoid calling "Get-Clipboard" every seconds.                
                    $currentClipboard = (Get-Clipboard -Raw)

                    if ($currentClipboard -and $currentClipboard -cne $HostSyncHash.ClipboardText)
                    {                    
                        $data = New-Object -TypeName PSCustomObject -Property @{                
                            Text = $currentClipboard
                        } 

                        if (-not (Send-Event -AEvent ([OutputEvent]::ClipboardUpdated) -Data $data))
                        { break }

                        $HostSyncHash.ClipboardText = $currentClipboard

                        $eventTriggered = $true                    
                    }
                }
                
                # Send a Keep-Alive if during this second iteration nothing happened.
                if (-not $eventTriggered)
                {
                    if (-not (Send-Event -AEvent ([OutputEvent]::KeepAlive)))
                    { break }
                }
            }
            finally
            {
                $stopWatch.Restart()
            }
        }
    }
}

function Get-WindowCaptionHeight
{
    $form = New-Object System.Windows.Forms.Form
    try {
        $screenRect = $form.RectangleToScreen($form.ClientRectangle)

        return $screenRect.Top - $virtualDesktopSyncHash.VirtualDesktop.Form.Top
    }
    finally
    {
      if ($form)  
      {
          $form.Dispose()
      }
    }
}

function Get-LocalScreenWidth
{
    return [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width
}

function Get-LocalScreenHeight
{
    return [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height
}

function New-VirtualDesktopForm
{
    <#
        .SYNOPSIS
            Create new WinForms Components to handle Virtual Desktop.

        .DESCRIPTION
            This function first create a new Windows Form then create a new child component (PaintBox)
            to display remote desktop frames.

            It returns a PowerShell object containing both Form and PaintBox.

        .PARAMETER Width
            Type: Integer
            Default: 1200
            Description: The pre-defined width of new form

        .PARAMETER Height
            Type: Integer
            Default: 800
            Description: The pre-defined height of new form            

        .PARAMETER Caption
            Type: String
            Default: PowerRemoteDesktop Viewer
            Description: The pre-defined caption of new form.

        .EXAMPLE
            New-VirtualDesktopForm -Caption "New Desktop Form" -Width 1200 -Height 800
    #>
    param (
        [int] $Width = 1200,
        [int] $Height = 800,
        [string] $Caption = "PowerRemoteDesktop Viewer"        
    )        

    $form = New-Object System.Windows.Forms.Form

    $form.Width = $Width
    $form.Height = $Height
    $form.BackColor = [System.Drawing.Color]::Black
    $form.Text = $Caption
    $form.KeyPreview = $true # Necessary to capture keystrokes.
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
    $form.MaximizeBox = $false            

    $pictureBox = New-Object System.Windows.Forms.PictureBox
    $pictureBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $pictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage    

    $form.Controls.Add($pictureBox)    

    return New-Object PSCustomObject -Property @{
        Form = $form
        Picture = $pictureBox
    }
}

function New-RunSpace
{
    <#
        .SYNOPSIS
            Create a new PowerShell Runspace.

        .DESCRIPTION
            Notice: the $host variable is used for debugging purpose to write on caller PowerShell
            Terminal.

        .PARAMETER ScriptBlock
            Type: ScriptBlock
            Default: None
            Description: Instructions to execute in new runspace.

        .PARAMETER Param
            Type: PSCustomObject
            Default: None
            Description: Object to attach in runspace context.

        .EXAMPLE
            New-RunSpace -Client $newClient -ScriptBlock { Start-Sleep -Seconds 10 }
    #>

    param(
        [Parameter(Mandatory=$True)]
        [ScriptBlock] $ScriptBlock,

        [PSCustomObject] $Param = $null
    )   

    $runspace = [RunspaceFactory]::CreateRunspace()
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.ApartmentState = "STA"
    $runspace.Open()                   

    if ($Param)
    {
        $runspace.SessionStateProxy.SetVariable("Param", $Param) 
    }

    $runspace.SessionStateProxy.SetVariable("HostSyncHash", $global:HostSyncHash)

    $powershell = [PowerShell]::Create().AddScript($ScriptBlock)

    $powershell.Runspace = $runspace

    $asyncResult = $powershell.BeginInvoke()

    return New-Object PSCustomObject -Property @{
        Runspace = $runspace
        PowerShell = $powershell
        AsyncResult = $asyncResult
    }
}

function Invoke-RemoteDesktopViewer
{
    <#
        .SYNOPSIS
            Open a new remote desktop session with a remote server.

        .DESCRIPTION
            Notice: Prefer using SecurePassword over plain-text password even if a plain-text password is getting converted to SecureString anyway.

        .PARAMETER ServerAddress
            Type: String
            Default: 127.0.0.1
            Description: Remote server host/address.            

        .PARAMETER ServerPort
            Type: Integer
            Default: 2801 (0 - 65535)
            Description: Remote server port.            

        .PARAMETER SecurePassword
            Type: SecureString
            Default: None
            Description: SecureString object containing password used to authenticate with remote server (Recommended)

        .PARAMETER Password
            Type: String
            Default: None
            Description: Plain-Text Password used to authenticate with remote server (Not recommended, use SecurePassword instead)            

        .PARAMETER UseTLSv1_3
            Type: Switch
            Default: False
            Description: If present, TLS v1.3 will be used instead of TLS v1.2 (Recommended if applicable to both systems)            

        .PARAMETER DisableVerbosity
            Type: Boolean
            Default: False
            Description: If present, program wont show verbosity messages.            
            
        .PARAMETER Clipboard
            Type: Enum
            Default: Both
            Description: 
                Define clipboard synchronization mode (Both, Disabled, Send, Receive) see bellow for more detail.

                * Disabled -> Clipboard synchronization is disabled in both side
                * Receive  -> Only incomming clipboard is allowed
                * Send     -> Only outgoing clipboard is allowed
                * Both     -> Clipboard synchronization is allowed on both side

        .PARAMETER ImageCompressionQuality
            Type: Integer (0 - 100)
            Default: 75 
            Description: JPEG Compression level from 0 to 100. 0 = Lowest quality, 100 = Highest quality.

        .PARAMETER Resize
            Type: Switch
            Default: None
            Description: If present, remote desktop will get resized accordingly with ResizeRatio option.            

        .PARAMETER ResizeRatio
            Type: Integer (30 - 99)
            Default: None
            Description: Used with Resize option, define the resize ratio in percentage.

        .PARAMETER AlwaysOnTop
            Type: Switch
            Default: False
            Description: If present, virtual desktop form will be above all other window's.

        .PARAMETER BlockSize
            Type: Enum
            Values: Size32, Size64, Size96, Size128, Size256, Size512
            Default: Size64
            Description:
                (Advanced) Define the screen grid block size. 
                Choose the block size accordingly to remote screen size / computer constrainsts (CPU / Network)

                Size1024  -> 1024 Bytes (1KiB)
                Size2048  -> 2048 Bytes (2KiB)
                Size4096  -> 4096 Bytes (4KiB)
                Size8192  -> 8192 Bytes (8KiB)
                Size9216  -> 9216 Bytes (9KiB)
                Size12288 -> 12288 Bytes (12KiB)
                Size16384 -> 16384 Bytes (16KiB)

        .PARAMETER PacketSize
            Type: Enum
            Values: Size1024, Size2048, Size4096, Size8192, Size9216, Size12288, Size16384 
            Default: Size9216
            Description:
                (Advanced) Define the network packet size for streams.
                Choose the packet size accordingly to your network constrainsts.

                Size32  -> 32x32
                Size64  -> 64x64
                Size96  -> 96x96
                Size128 -> 128x128
                Size256	-> 256x256
                Size512	-> 512x512        

        .PARAMETER LogonUI
            Type: Switch
            Default: None
            Description: Request server to open LogonUI / Winlogon desktop insead of default user desktop (Requires SYSTEM privilege in active session).

        .EXAMPLE
            Invoke-RemoteDesktopViewer -ServerAddress "192.168.0.10" -ServerPort "2801" -SecurePassword (ConvertTo-SecureString -String "s3cr3t!" -AsPlainText -Force)
            Invoke-RemoteDesktopViewer -ServerAddress "192.168.0.10" -ServerPort "2801" -Password "s3cr3t!"
            Invoke-RemoteDesktopViewer -ServerAddress "127.0.0.1" -ServerPort "2801" -Password "Just4TestingLocally!"

    #>
    param (        
        [string] $ServerAddress = "127.0.0.1",

        [ValidateRange(0, 65535)]
        [int] $ServerPort = 2801,        

        [switch] $UseTLSv1_3,                        
        [SecureString] $SecurePassword,
        [String] $Password,                
        [switch] $DisableVerbosity,
        [ClipboardMode] $Clipboard = [ClipboardMode]::Both,

        [ValidateRange(0, 100)]
        [int] $ImageCompressionQuality = 75,

        [switch] $Resize,

        [ValidateRange(30, 99)]
        [int] $ResizeRatio = 90,

        [switch] $AlwaysOnTop,
        [PacketSize] $PacketSize = [PacketSize]::Size9216,
        [BlockSize] $BlockSize = [BlockSize]::Size64,
        [switch] $LogonUI
    )

    [System.Collections.Generic.List[PSCustomObject]]$runspaces = @()

    $oldErrorActionPreference = $ErrorActionPreference
    $oldVerbosePreference = $VerbosePreference
    try
    {
        $ErrorActionPreference = "stop"

        if (-not $DisableVerbosity)
        {
            $VerbosePreference = "continue"
        }
        else 
        {
            $VerbosePreference = "SilentlyContinue"
        }       

        Write-Banner 

        $null = [User32]::SetProcessDPIAware()
                
        Write-Verbose "Server address: ""${ServerAddress}:${ServerPort}"""

        if (-not $SecurePassword -and -not $Password)
        {
            throw "You must specify either a SecurePassword or Password parameter used during server authentication."
        }

        if ($Password -and -not $SecurePassword)
        {
            $SecurePassword = (ConvertTo-SecureString -String $Password -AsPlainText -Force)

            Remove-Variable -Name "Password" -ErrorAction SilentlyContinue
        }
        
        $session = [ViewerSession]::New(
            $ServerAddress,
            $ServerPort,
            $SecurePassword            
        )
        try
        {
            $session.UseTLSv1_3 = $UseTLSv1_3
            $session.ImageCompressionQuality = $ImageCompressionQuality
            $session.PacketSize = $PacketSize
            $session.BlockSize = $BlockSize
            $session.LogonUI = $LogonUI

            if ($Resize)
            {
                $session.ResizeRatio = $ResizeRatio
            }            

            Write-Host "Start new remote desktop session..."

            $session.OpenSession()

            $session.ConnectDesktopWorker()

            $session.ConnectEventsWorker()

            Write-Host "Session successfully established, start streaming..."

            Write-Verbose "Create WinForms Environment..."            

            $virtualDesktop = New-VirtualDesktopForm
            $virtualDesktopSyncHash = [HashTable]::Synchronized(@{
                VirtualDesktop = $virtualDesktop
            })            

            $virtualDesktop.Form.Text = [string]::Format(
                "Power Remote Desktop v{0}: {1}/{2} - {3}", 
                $global:PowerRemoteDesktopVersion,
                $session.ServerInformation.Username,
                $session.ServerInformation.MachineName,
                $session.ServerInformation.WindowsVersion
            )

            # Size Virtual Desktop Form Window
            $virtualDesktop.Form.ClientSize = [System.Drawing.Size]::New(
                $session.ViewerConfiguration.VirtualDesktopWidth, 
                $session.ViewerConfiguration.VirtualDesktopHeight
            )                                   

            # Create a thread-safe hashtable to send events to remote server.            
            $outputEventSyncHash = [HashTable]::Synchronized(@{
                Writer = $session.ClientEvents.Writer                
            })

            # WinForms Events (If enabled, I recommend to disable control when testing on local machine to avoid funny things)
            if (-not $session.ServerInformation.ViewOnly)                   
            {
                enum OutputEvent {
                    Keyboard = 0x1
                    MouseClickMove = 0x2
                    MouseWheel = 0x3
                }

                enum MouseState {
                    Up = 0x1
                    Down = 0x2
                    Move = 0x3
                }

                function New-MouseEvent
                {
                    <#
                        .SYNOPSIS
                            Generate a new mouse event object to be sent to server.
                            This event is used to simulate mouse move and clicks.

                        .PARAMETER X
                            Type: Integer
                            Default: None
                            Description: The position of mouse in horizontal axis.

                        .PARAMETER Y
                            Type: Integer
                            Default: None
                            Description: The position of mouse in vertical axis.

                        .PARAMETER Type
                            Type: Enum
                            Default: None
                            Description:  The type of mouse event (Example: Move, Click)

                        .PARAMETER Button
                            Type: String
                            Default: None
                            Description: The pressed button on mouse (Example: Left, Right, Middle)

                        .EXAMPLE
                            New-MouseEvent -X 10 -Y 35 -Type "Up" -Button "Left"
                            New-MouseEvent -X 10 -Y 35 -Type "Down" -Button "Left"
                            New-MouseEvent -X 100 -Y 325 -Type "Move"
                    #>
                    param (
                        [Parameter(Mandatory=$true)]
                        [int] $X,
                        [Parameter(Mandatory=$true)]
                        [int] $Y,        
                        [Parameter(Mandatory=$true)]
                        [MouseState] $Type,

                        [string] $Button = "None"
                    )

                    return New-Object PSCustomObject -Property @{
                        Id = [OutputEvent]::MouseClickMove
                        X = $X
                        Y = $Y
                        Button = $Button
                        Type = $Type 
                    }
                }

                function New-KeyboardEvent
                {
                    <#
                        .SYNOPSIS
                            Generate a new keyboard event object to be sent to server.
                            This event is used to simulate keyboard strokes.  

                        .PARAMETER Keys
                            Type: String
                            Default: None
                            Description: Plain text keys to be simulated on remote computer.

                        .EXAMPLE
                            New-KeyboardEvent -Keys "Hello, World"
                            New-KeyboardEvent -Keys "t"
                    #>
                    param (
                        [Parameter(Mandatory=$true)]
                        [string] $Keys
                    )

                    return New-Object PSCustomObject -Property @{
                        Id = [OutputEvent]::Keyboard
                        Keys = $Keys
                    }
                }

                function Send-VirtualMouse
                {
                    <#
                        .SYNOPSIS
                            Transform the virtual mouse (the one in Virtual Desktop Form) coordinates to real remote desktop
                            screen coordinates (especially when incomming desktop frames are resized)

                            When event is generated, it is immediately sent to remote server.

                        .PARAMETER X
                            Type: Integer
                            Default: None
                            Description: The position of virtual mouse in horizontal axis.

                        .PARAMETER Y
                            Type: Integer
                            Default: None
                            Description: The position of virtual mouse in vertical axis.

                        .PARAMETER Type
                            Type: Integer
                            Default: None
                            Description: The type of mouse event (Example: Move, Click)

                        .PARAMETER Button
                            Type: String
                            Default: None
                            Description: The pressed button on mouse (Example: Left, Right, Middle)

                        .EXAMPLE
                           Send-VirtualMouse -X 10 -Y 20 -Type "Move"
                    #>
                    param (
                        [Parameter(Mandatory=$True)]
                        [int] $X,                        
                        [Parameter(Mandatory=$True)]
                        [int] $Y,
                        [Parameter(Mandatory=$True)]
                        [MouseState] $Type,

                        [string] $Button = ""
                    )
                    
                    if ($session.ViewerConfiguration.RequireResize)
                    {
                        $X *= $session.ViewerConfiguration.ScreenX_Ratio
                        $Y *= $session.ViewerConfiguration.ScreenY_Ratio
                    }                    
      
                    $X += $session.ViewerConfiguration.ScreenX_Delta
                    $Y += $session.ViewerConfiguration.ScreenY_Delta

                    $aEvent = (New-MouseEvent -X $X -Y $Y -Button $Button -Type $Type)                    

                    try
                    {
                        $outputEventSyncHash.Writer.WriteLine(($aEvent | ConvertTo-Json -Compress)) 
                    }  
                    catch
                    {}               
                }

                function Send-VirtualKeyboard
                {
                    <#
                        .SYNOPSIS
                            Send to remote server key strokes to simulate.

                        .PARAMETER KeyChain
                            Type: String
                            Default: None
                            Description: A string representing character(s) to simulate remotely.

                        .EXAMPLE
                            Send-VirtualKeyboard -KeyChain "Hello, World"
                            Send-VirtualKeyboard -KeyChain "{LEFT}"
                    #>
                    param (
                        [Parameter(Mandatory=$True)]
                        [string] $KeyChain
                    )
                    
                    $aEvent = (New-KeyboardEvent -Keys $KeyChain)                                

                    try
                    {
                        $outputEventSyncHash.Writer.WriteLine(($aEvent  | ConvertTo-Json -Compress)) 
                    }
                    catch
                    {}                    
                }

                $virtualDesktop.Form.Add_KeyPress(
                    { 
                        if ($_.KeyChar)
                        {
                            switch -CaseSensitive ([string]$_.KeyChar)
                            {
                                "{" { $result = "{{}" }
                                "}" { $result = "{}}" }
                                "+" { $result = "{+}" }
                                "^" { $result = "{^}" }
                                "%" { $result = "{%}" }
                                "~" { $result = "{~}" }
                                "(" { $result = "{(}" }
                                ")" { $result = "{)}" }
                                "[" { $result = "{[}" }
                                "]" { $result = "{]}" }

                                default { $result = $_ }
                            }

                            Send-VirtualKeyboard -KeyChain $result                   
                        }
                    }
                )

                $virtualDesktop.Form.Add_Shown(
                    {
                        # Center Virtual Desktop Form
                        $virtualDesktop.Form.Location = [System.Drawing.Point]::New(
                            ((Get-LocalScreenWidth) - $virtualDesktop.Form.Width) / 2,
                            ((Get-LocalScreenHeight) - $virtualDesktop.Form.Height) / 2
                        ) 

                        $virtualDesktop.Form.TopMost = $AlwaysOnTop
                    }
                )

                $virtualDesktop.Form.Add_KeyDown(
                    {                       
                        $result = ""

                        switch ($_.KeyValue)
                        {
                            # WIN Key
                            91 { $result = "^{ESC}" }

                            # F Keys
                            112 { $result = "{F1}" }
                            113 { $result = "{F2}" }
                            114 { $result = "{F3}" }
                            115 { $result = "{F4}" }
                            116 { $result = "{F5}" }
                            117 { $result = "{F6}" }
                            118 { $result = "{F7}" }
                            119 { $result = "{F8}" }
                            120 { $result = "{F9}" }
                            121 { $result = "{F10}" }
                            122 { $result = "{F11}" }
                            123 { $result = "{F12}" }
                            124 { $result = "{F13}" }
                            125 { $result = "{F14}" }
                            126 { $result = "{F15}" }
                            127 { $result = "{F16}" }

                            # Arrows
                            37 { $result = "{LEFT}" }
                            38 { $result = "{UP}" }
                            39 { $result = "{RIGHT}" }
                            40 { $result = "{DOWN}" }

                            # Misc
                            92 { $result = "{WIN}" }
                            27 { $result = "{ESC}"}
                            33 { $result = "{PGUP}" }
                            34 { $result = "{PGDW}" }
                            36 { $result = "{HOME}" }
                            46 { $result = "{DELETE}" }
                            35 { $result = "{END}" }

                            # Add other keys bellow
                        }
                        
                        if ($result)
                        {                            
                            Send-VirtualKeyboard -KeyChain $result
                        }
                    }
                )                        

                $virtualDesktop.Picture.Add_MouseDown(
                    {                         
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type ([MouseState]::Down)
                    }
                )

                $virtualDesktop.Picture.Add_MouseUp(
                    { 
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type ([MouseState]::Up)
                    }
                )

                $virtualDesktop.Picture.Add_MouseMove(
                    { 
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type ([MouseState]::Move)
                    }
                )          

                $virtualDesktop.Picture.Add_MouseWheel(
                    {
                        $aEvent = New-Object PSCustomObject -Property @{
                            Id = [OutputEvent]::MouseWheel
                            Delta = $_.Delta
                        }

                        try
                        {
                            $outputEventSyncHash.Writer.WriteLine(($aEvent | ConvertTo-Json -Compress))
                        }
                        catch {}
                    }
                )  
            }            

            Write-Verbose "Create runspace for desktop streaming..."            

            $param = New-Object -TypeName PSCustomObject -Property @{
                Client = $session.ClientDesktop
                VirtualDesktopSyncHash = $virtualDesktopSyncHash
                ViewerConfiguration = $session.ViewerConfiguration
                PacketSize = $session.PacketSize                
            }

            $newRunspace = (New-RunSpace -ScriptBlock $global:VirtualDesktopUpdaterScriptBlock -Param $param)  
            $runspaces.Add($newRunspace)

            Write-Verbose "Create runspace for incoming events..."

            $param = New-Object -TypeName PSCustomObject -Property @{
                Client = $session.ClientEvents
                VirtualDesktopSyncHash = $virtualDesktopSyncHash
                Clipboard = $Clipboard
            }

            $newRunspace = (New-RunSpace -ScriptBlock $global:IngressEventScriptBlock -Param $param)  
            $runspaces.Add($newRunspace)

            Write-Verbose "Create runspace for outgoing events..."

            $param = New-Object -TypeName PSCustomObject -Property @{                
                OutputEventSyncHash = $outputEventSyncHash
                Clipboard = $Clipboard
            }

            $newRunspace = (New-RunSpace -ScriptBlock $global:EgressEventScriptBlock -Param $param)  
            $runspaces.Add($newRunspace)

            Write-Verbose "Done. Showing Virtual Desktop Form."                       

            $null = $virtualDesktop.Form.ShowDialog()
        }
        finally
        {                
            Write-Verbose "Free environement."

            if ($session)
            {
                $session.CloseSession()

                $session = $null
            }            

            Write-Verbose "Free runspaces..."

            foreach ($runspace in $runspaces)
            {
                $null = $runspace.PowerShell.EndInvoke($runspace.AsyncResult)
                $runspace.PowerShell.Runspace.Dispose()                                      
                $runspace.PowerShell.Dispose()                    
            }    
            $runspaces.Clear() 

            if ($virtualDesktop)
            {            
                $virtualDesktop.Form.Dispose()
            }      
            
            Write-Host "Remote desktop session has ended."
        }           
    }
    finally
    {    
        $ErrorActionPreference = $oldErrorActionPreference   
        $VerbosePreference = $oldVerbosePreference        
    } 
}

try {  
    Export-ModuleMember -Function Remove-TrustedServer
    Export-ModuleMember -Function Clear-TrustedServers    
    Export-ModuleMember -Function Get-TrustedServers
    Export-ModuleMember -Function Invoke-RemoteDesktopViewer
} catch {}