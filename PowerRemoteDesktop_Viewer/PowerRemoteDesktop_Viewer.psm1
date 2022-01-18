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

    .Why
        - Prove PowerShell is as "PowerFul" as compiled language.
        - Improve my PowerShell skills.
        - Because Remote Desktop Powershell Scripts doesn't exists so far.        

    .Important
        This PowerShell Application is not yet marked as Stable / Final. It is not recommended to use
        it in a production environment at this time.
        Wait for final 1.0 version.

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
Add-Type -MemberDefinition '[DllImport("User32.dll")] public static extern bool SetProcessDPIAware();' -Name User32 -Namespace W;

$global:PowerRemoteDesktopVersion = "1.0.5.beta.6"

$global:HostSyncHash = [HashTable]::Synchronized(@{
    host = $host
    ClipboardText = (Get-Clipboard -Raw)
})

# Last until PowerShell session is closed
$global:EphemeralTrustedServers = @()

# Local storage definitions
$global:LocalStoragePath = "HKCU:\SOFTWARE\PowerRemoteDesktop_Viewer"
$global:LocalStoragePath_TrustedServers = -join($global:LocalStoragePath, "\TrustedServers")

enum ClipboardMode {
    Disabled = 1
    Receive = 2
    Send = 3
    Both = 4
}

enum TransportMode {
    Raw = 1
    Base64 = 2
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
            The server certificate fingerprint to store.
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
            Server certificate to remove from trusted server list.
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
            The server certificate fingerprint to check.
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
            A String to hash.

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

        .PARAMETER SecurePassword
            Registered password string for server authentication.

        .PARAMETER Candidate
            Random string used to solve the challenge. This string is public and is set across network by server.
            Each time a new connection is requested to server, a new candidate is generated.

        .EXAMPLE
            Resolve-AuthenticationChallenge -SecurePassword "s3cr3t!" -Candidate "rKcjdh154@]=Ldc"
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
    [bool] $TLSv1_3

    [System.Net.Sockets.TcpClient] $Client = $null
    [System.Net.Security.SslStream] $SSLStream = $null
    [System.IO.StreamWriter] $Writer = $null
    [System.IO.StreamReader] $Reader = $null

    ClientIO(
        <#
            .SYNOPSIS
                Class constructor.

            .PARAMETER RemoteAddress
                IP/HOST of remote server.

            .PARAMETER RemotePort
                Remote server port.

            .PARAMETER TLSv1_3
                Define whether or not SSL/TLS v1.3 must be used.
        #>
        [string] $RemoteAddress = "127.0.0.1",
        [int] $RemotePort = 2801,
        [bool] $TLSv1_3 = $false
    ) {
        $this.RemoteAddress = $RemoteAddress
        $this.RemotePort = $RemotePort
        $this.TLSv1_3 = $TLSv1_3
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

        if ($this.TLSv1_3)
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

        Write-Verbose "Encrypted tunnel opened and ready for use."               
    }

    [void]Authentify([SecureString] $SecurePassword) {
        <#
            .SYNOPSIS
                Handle authentication process with remote server.

            .PARAMETER Password
                Password used for authentication with server.

            .EXAMPLE
                .Authentify("s3cr3t!")
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
        if ($result -eq "OK.")
        {
            Write-Verbose "Solution accepted. Authentication success."                
        }            
        else 
        {
            throw "Solution declined. Authentication failed."                
        }
    
    }

    [void]Hello([string] $SessionId) {
        <#
            .SYNOPSIS
                This method must be called after Password-Authentication to finalise an established
                connection with server.                

            .PARAMETER SessionId
                A String containing the Session Id.
        #>

        Write-Verbose "Say Hello..."

        $this.Writer.WriteLine($SessionId)

        $result = $this.Reader.ReadLine()
        if ($result -eq "HELLO.")
        {
            Write-Verbose "Server Hello back."
        }            
        else 
        {
            throw "Could not finalise connection with remote server. Session Id is wrong or was terminated."
        }
    }
    
    [PSCustomObject]Hello(){
        <#
            .SYNOPSIS
                This method must be called after Password-Authentication to finalise an established
                connection with server.

            .DESCRIPTION
                This method is called when no session is already present. Server will send several informations 
                including a new session id the store.

                TODO: Instead of PSCustomObject, create a specific class ?
        #>
        
        Write-Verbose "Say Hello..."

        $jsonObject = $this.Reader.ReadLine()

        Write-Verbose "@SessionInformation:"
        Write-Verbose $jsonObject
        Write-Verbose "---"

        $sessionInformation = $jsonObject | ConvertFrom-Json
        if (
            (-not ($sessionInformation.PSobject.Properties.name -contains "MachineName")) -or
            (-not ($sessionInformation.PSobject.Properties.name -contains "Username")) -or
            (-not ($sessionInformation.PSobject.Properties.name -contains "WindowsVersion")) -or                      
            (-not ($sessionInformation.PSobject.Properties.name -contains "SessionId")) -or
            (-not ($sessionInformation.PSobject.Properties.name -contains "TransportMode")) -or
            (-not ($sessionInformation.PSobject.Properties.name -contains "Version")) -or
            (-not ($sessionInformation.PSobject.Properties.name -contains "Screens")) -or
            (-not ($sessionInformation.PSobject.Properties.name -contains "ViewOnly"))
        )
        {
            throw "Invalid session information data."
        }   
        
        if ($sessionInformation.Version -ne $global:PowerRemoteDesktopVersion)
        {
            throw "Server and Viewer version mismatch.`r`n`
            Local: ""${global:PowerRemoteDesktopVersion}""`r`n`
            Remote: ""$($sessionInformation.Version)""`r`n`
            You cannot use two different version between Viewer and Server."
        }

        if ($sessionInformation.ViewOnly)
        {
            Write-Host "You are only authorized to view remote desktop (Mouse / Keyboard not authorized)" -ForegroundColor Cyan
        }

        # Check if remote server have multiple screens
        $selectedScreen = $null

        if ($sessionInformation.Screens.Length -gt 1)
        {
            Write-Verbose "Remote Server have $($sessionInformation.Screens.Length) Screens."

            Write-Host "Remote Server have " -NoNewLine
            Write-Host $($sessionInformation.Screens.Length) -NoNewLine -ForegroundColor Green
            Write-Host " Screens:`r`n"

            foreach ($screen in $sessionInformation.Screens)
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
                    $selectedScreen = $sessionInformation.Screens | Where-Object -FilterScript { $_.Primary -eq $true }
                }
                else 
                {
                    if (-not $choice -is [int]) {
                        Write-Host "You must enter a valid index (integer), starting at 1."

                        continue
                    }                    

                    $selectedScreen = $sessionInformation.Screens | Where-Object -FilterScript { $_.Id -eq $choice }

                    if (-not $selectedScreen)
                    {
                        Write-Host "Invalid choice, please choose an existing screen index." -ForegroundColor Red
                    }
                }

                if ($selectedScreen)
                {
                    $this.Writer.WriteLine($selectedScreen.Name)

                    break
                }
            }            
        }
        else
        {
            $selectedScreen = $sessionInformation.Screens | Select-Object -First 1
        }

        if (-not $selectedScreen)
        {
            throw "No screen to capture."
        }

        Write-Verbose "@SelectedScreen:"
        Write-Verbose $selectedScreen
        Write-Verbose "---"        

        $sessionInformation | Add-Member -MemberType NoteProperty -Name "Screen" -Value $selectedScreen

        return $sessionInformation
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

class ViewerSession
{
    [PSCustomObject] $SessionInformation = $null
    [string] $ServerAddress = "127.0.0.1"
    [string] $ServerPort = 2801
    [SecureString] $SecurePassword = $null
    [bool] $TLSv1_3 = $false        

    [ClientIO] $ClientDesktop = $null
    [ClientIO] $ClientEvents = $null

    ViewerSession(        
        [string] $ServerAddress,
        [int] $ServerPort,
        [SecureString] $SecurePassword,
        [bool] $TLSv1_3
    )    
    {
        <#
            .SYNOPSIS
                Create a new viewer session object.

            .DESCRIPTION
                This object will contain session information including active connection
                objects (ClientIO)

            .PARAMETER ServerAddress
            Remote Server Address.

            .PARAMETER ServerPort
                Remote Server Port.

            .PARAMETER SecureString
                Password used during server authentication.

            .PARAMETER TLSv1_3
                Define whether or not client must use SSL/TLS v1.3 to communicate with remote server.
                Recommended if possible.
        #>

        # TODO: Check if ServerAddress is a valid host.
        
        # Or: System.Management.Automation.Runspaces.MaxPort (High(Word))
        if ($ServerPort -lt 0 -and $ServerPort -gt 65535)
        {
            throw "Invalid TCP Port (0-65535)"
        }

        $this.ServerAddress = $ServerAddress
        $this.ServerPort = $ServerPort 
        $this.SecurePassword = $SecurePassword
        $this.TLSv1_3 = $TLSv1_3           
    }

    [void] OpenSession() {
        <#
            .SYNOPSIS
                Establish a new complete session with remote server.

            .DESCRIPTION
                This method handle both session handshake and Password-Authentication.
        #>        
        Write-Verbose "Open new session with remote server: ""$($this.ServerAddress):$($this.ServerPort)""..."

        if ($this.SessionInformation)
        {
            throw "An session already exists. Close existing session first."
        }

        Write-Verbose "Establish first contact with remote server..."

        $this.ClientDesktop = [ClientIO]::New($this.ServerAddress, $this.ServerPort, $this.TLSv1_3)
        try
        {
            $this.ClientDesktop.Connect()        

            $this.ClientDesktop.Authentify($this.SecurePassword)

            $this.SessionInformation = $this.ClientDesktop.Hello()

            if (-not $this.SessionInformation)
            {
                throw "Session cannot be null."
            }

            Write-Verbose "Open secondary tunnel for input control..."

            $this.ClientEvents = [ClientIO]::new($this.ServerAddress, $this.ServerPort, $this.TLSv1_3) 
            $this.ClientEvents.Connect()    
            
            $this.ClientEvents.Authentify($this.SecurePassword)

            $this.ClientEvents.Hello($this.SessionInformation.SessionId)

            Write-Verbose "New session successfully established with remote server."
            Write-Verbose "Session Id: $($this.SessionInformation.SessionId)"
        }
        catch
        {            
            $this.CloseSession()

            throw "Open Session Error. Detail: ""$($_)"""
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
        
        $this.SessionInformation = $null
        
        Write-Verbose "Session closed."
    }

}

$global:VirtualDesktopUpdaterScriptBlock = {   
    
    enum TransportMode {
        Raw = 1
        Base64 = 2
    }

    function Invoke-SmoothResize
    {
        <#
            .SYNOPSIS
                Output a resized version of input bitmap. The resize quality is quite fair.
                
            .PARAMETER OriginalImage
                Input bitmap to resize.

            .PARAMETER NewWidth
                Define the width of new bitmap version.

            .PARAMETER NewHeight
                Define the height of new bitmap version.

            .EXAMPLE
                Invoke-SmoothResize -OriginalImage $myImage -NewWidth 1920 -NewHeight 1024
        #>
        param (
            [Parameter(Mandatory=$true)]
            [System.Drawing.Bitmap] $OriginalImage,

            [Parameter(Mandatory=$true)]
            [int] $NewWidth,

            [Parameter(Mandatory=$true)]
            [int] $NewHeight
        )
        try
        {    
            $bitmap = New-Object -TypeName System.Drawing.Bitmap -ArgumentList $NewWidth, $NewHeight

            $resizedImage = [System.Drawing.Graphics]::FromImage($bitmap)

            $resizedImage.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $resizedImage.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $resizedImage.InterpolationMode =  [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $resizedImage.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality 
            
            $resizedImage.DrawImage($OriginalImage, 0, 0, $bitmap.Width, $bitmap.Height)

            return $bitmap
        }
        finally
        {
            if ($OriginalImage)
            {
                $OriginalImage.Dispose()
            }

            if ($resizedImage)
            {
                $resizedImage.Dispose()
            }
        }
    }

    try
    {       
        $packetSize = 4096

        while ($true)
        {                   
            $stream = New-Object System.IO.MemoryStream
            try
            {      
                switch ([TransportMode] $Param.TransportMode)         
                {
                    ([TransportMode]::Raw)
                    {                        
                        $buffer = New-Object -TypeName byte[] -ArgumentList 4 # SizeOf(Int32)

                        $Param.Client.SSLStream.Read($buffer, 0, $buffer.Length)

                        [int32] $totalBufferSize = [BitConverter]::ToInt32($buffer, 0)                

                        $stream.SetLength($totalBufferSize)

                        $stream.position = 0

                        $totalBytesRead = 0

                        $buffer = New-Object -TypeName Byte[] -ArgumentList $packetSize
                        do
                        {
                            $bufferSize = $totalBufferSize - $totalBytesRead
                            if ($bufferSize -gt $packetSize)
                            {
                                $bufferSize = $packetSize
                            }    
                            else
                            {
                                # Save some memory operations for creating objects.
                                # Usually, bellow code is call when last chunk is being sent.
                                $buffer = New-Object -TypeName byte[] -ArgumentList $bufferSize
                            }                

                            $Param.Client.SSLStream.Read($buffer, 0, $bufferSize)                    

                            $null = $stream.Write($buffer, 0, $buffer.Length)

                            $totalBytesRead += $bufferSize
                        } until ($totalBytesRead -eq $totalBufferSize)
                    }

                    ([TransportMode]::Base64)
                    {                        
                        [byte[]] $buffer = [System.Convert]::FromBase64String(($Param.Client.Reader.ReadLine()))

                        $stream.Write($buffer, 0, $buffer.Length)   
                    }
                }                    

                $stream.Position = 0                                                                

                if ($Param.RequireResize)
                {
                    #$image = [System.Drawing.Image]::FromStream($stream)

                    $bitmap = New-Object -TypeName System.Drawing.Bitmap -ArgumentList $stream

                    $Param.VirtualDesktopSyncHash.VirtualDesktop.Picture.Image = Invoke-SmoothResize -OriginalImage $bitmap -NewWidth $Param.VirtualDesktopWidth -NewHeight $Param.VirtualDesktopHeight                   
                }
                else
                {                    
                    $Param.VirtualDesktopSyncHash.VirtualDesktop.Picture.Image = [System.Drawing.Image]::FromStream($stream)                                                          
                }
            }
            catch 
            {               
                break
            }            
            finally
            {
                $stream.Close()
            }
                
        }
    }
    finally
    {        
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

                     {($_ -eq ([CursorType]::IDC_SIZE)) -or ($_ -eq [CursorType]::(IDC_SIZEALL))}
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
            Width of new form.

        .PARAMETER Height
            Height of new form.

        .PARAMETER Caption
            Caption of new form.

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
            A PowerShell block of code to be evaluated on the new Runspace.

        .PARAMETER Param
            Optional extra parameters to be attached to Runspace.

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
            Open a new Remote Desktop Session to remote Server.

        .PARAMETER ServerAddress
            Remote Server Address.

        .PARAMETER ServerPort
            Remote Server Port.

        .PARAMETER SecurePassword
            SecureString Password object used to authenticate with remote server (Recommended)

            Call "ConvertTo-SecureString -String "YouPasswordHere" -AsPlainText -Force" on this parameter to convert
            a plain-text String to SecureString.

            See example section.

        .PARAMETER Password
            Plain-Text Password used to authenticate with remote server (Not recommended, use SecurePassword instead)        

        .PARAMETER TLSv1_3
            Define whether or not client must use SSL/TLS v1.3 to communicate with remote server.
            Recommended if possible.

        .PARAMETER DisableVerbosity
            Disable verbosity (not recommended)  
            
        .PARAMETER Clipboard
            Define clipboard synchronization rules:
                - "Disabled": Completely disable clipboard synchronization.
                - "Receive": Update local clipboard with remote clipboard only.
                - "Send": Send local clipboard to remote peer.
                - "Both": Clipboards are fully synchronized between Viewer and Server.

        .EXAMPLE
            Invoke-RemoteDesktopViewer -ServerAddress "192.168.0.10" -ServerPort "2801" -SecurePassword (ConvertTo-SecureString -String "s3cr3t!" -AsPlainText -Force)
            Invoke-RemoteDesktopViewer -ServerAddress "192.168.0.10" -ServerPort "2801" -Password "s3cr3t!"
            Invoke-RemoteDesktopViewer -ServerAddress "127.0.0.1" -ServerPort "2801" -Password "Just4TestingLocally!"

    #>
    param (        
        [string] $ServerAddress = "127.0.0.1",
        [int] $ServerPort = 2801,        
        [switch] $TLSv1_3,
                           
        [SecureString] $SecurePassword,
        [String] $Password,                

        [switch] $DisableVerbosity,
        [ClipboardMode] $Clipboard = [ClipboardMode]::Both
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

        $VerbosePreference = "continue"

        Write-Banner 

        $null = [W.User32]::SetProcessDPIAware()
                
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
        
        $session = [ViewerSession]::New($ServerAddress, $ServerPort, $SecurePassword, $TLSv1_3)
        try
        {
            $session.OpenSession()

            Write-Verbose "Create WinForms Environment..."

            $virtualDesktopSyncHash = [HashTable]::Synchronized(@{
                VirtualDesktop = New-VirtualDesktopForm
            })            

            $virtualDesktopSyncHash.VirtualDesktop.Form.Text = [string]::Format(
                "Power Remote Desktop: {0}/{1} - {2}", 
                $session.SessionInformation.Username,
                $session.SessionInformation.MachineName,
                $session.SessionInformation.WindowsVersion
            )

            # Prepare Virtual Desktop 
            $locationResolutionInformation = [System.Windows.Forms.Screen]::PrimaryScreen

            $screenRect = $virtualDesktopSyncHash.VirtualDesktop.Form.RectangleToScreen($virtualDesktopSyncHash.VirtualDesktop.Form.ClientRectangle)
            $captionHeight = $screenRect.Top - $virtualDesktopSyncHash.VirtualDesktop.Form.Top

            $localScreenWidth = $locationResolutionInformation.WorkingArea.Width
            $localScreenHeight = $locationResolutionInformation.WorkingArea.Height           
            $localScreenHeight -= $captionHeight

            $requireResize = (
                ($localScreenWidth -le $session.SessionInformation.Screen.Width) -or
                ($localScreenHeight -le $session.SessionInformation.Screen.Height)            
            )

            $virtualDesktopWidth = 0
            $virtualDesktopHeight = 0

            $resizeRatio = 80

            if ($requireResize)
            {            
                $adjustVertically = $localScreenWidth -gt $localScreenHeight

                if ($adjustVertically)
                {
                    $virtualDesktopWidth = [math]::Round(($localScreenWidth * $resizeRatio) / 100)
                    
                    $remoteResizedRatio = [math]::Round(($virtualDesktopWidth * 100) / $session.SessionInformation.Screen.Width)

                    $virtualDesktopHeight = [math]::Round(($session.SessionInformation.Screen.Height * $remoteResizedRatio) / 100)
                }
                else
                {
                    $virtualDesktopHeight = [math]::Round(($localScreenHeight * $resizeRatio) / 100)
                    
                    $remoteResizedRatio = [math]::Round(($virtualDesktopHeight * 100) / $session.SessionInformation.Screen.Height)

                    $virtualDesktopWidth = [math]::Round(($session.SessionInformation.Screen.Width * $remoteResizedRatio) / 100)
                }                        
            }
            else
            {            
                $virtualDesktopWidth = $session.SessionInformation.Screen.Width
                $virtualDesktopHeight = $session.SessionInformation.Screen.Height
            }

            # Size Virtual Desktop Form Window
            $virtualDesktopSyncHash.VirtualDesktop.Form.ClientSize = [System.Drawing.Size]::new($virtualDesktopWidth, $virtualDesktopHeight) 

            # Center Virtual Desktop Form
            $virtualDesktopSyncHash.VirtualDesktop.Form.Location = [System.Drawing.Point]::new(
                (($localScreenWidth - $virtualDesktopSyncHash.VirtualDesktop.Form.Width) / 2),
                (($localScreenHeight - $virtualDesktopSyncHash.VirtualDesktop.Form.Height) / 2)
            )   
            
            # Create a thread-safe hashtable to send events to remote server.            
            $outputEventSyncHash = [HashTable]::Synchronized(@{
                Writer = $session.ClientEvents.Writer                
            })

            # WinForms Events (If enabled, I recommend to disable control when testing on local machine to avoid funny things)
            if (-not $session.SessionInformation.ViewOnly)                   
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
                            The position of mouse in horizontal axis.

                        .PARAMETER Y
                            The position of mouse in vertical axis.

                        .PARAMETER Type
                            The type of mouse event (Example: Move, Click)

                        .PARAMETER Button
                            The pressed button on mouse (Example: Left, Right, Middle)

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
                            Plain text keys to be simulated on remote computer.

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
                            The position of virtual mouse in horizontal axis.

                        .PARAMETER Y
                            The position of virtual mouse in vertical axis.

                        .PARAMETER Type
                            The type of mouse event (Example: Move, Click)

                        .PARAMETER Button
                            The pressed button on mouse (Example: Left, Right, Middle)

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

                    if ($requireResize)
                    {
                        $X = ($X * 100) / $resizeRatio
                        $Y = ($Y * 100) / $resizeRatio
                    }
      
                    $X += $session.SessionInformation.Screen.X
                    $Y += $session.SessionInformation.Screen.Y

                    $aEvent = (New-MouseEvent -X $X -Y $Y -Button $Button -Type $Type)                    

                    $outputEventSyncHash.Writer.WriteLine(($aEvent | ConvertTo-Json -Compress))                    
                }

                function Send-VirtualKeyboard
                {
                    <#
                        .SYNOPSIS
                            Send to remote server key strokes to simulate.

                        .PARAMETER KeyChain
                            A string representing character(s) to simulate remotely.

                        .EXAMPLE
                            Send-VirtualKeyboard -KeyChain "Hello, World"
                            Send-VirtualKeyboard -KeyChain "{LEFT}"
                    #>
                    param (
                        [Parameter(Mandatory=$True)]
                        [string] $KeyChain
                    )

                    $aEvent = (New-KeyboardEvent -Keys $KeyChain)                                

                    $outputEventSyncHash.Writer.WriteLine(($aEvent  | ConvertTo-Json -Compress)) 
                }

                $virtualDesktopSyncHash.VirtualDesktop.Form.Add_KeyPress(
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

                $virtualDesktopSyncHash.VirtualDesktop.Form.Add_KeyDown(
                    {                       
                        $result = ""
                        switch ($_.KeyValue)
                        {
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
                            Write-Verbose $result
                            Send-VirtualKeyboard -KeyChain $result
                        }
                    }
                )                        

                $virtualDesktopSyncHash.VirtualDesktop.Picture.Add_MouseDown(
                    {                         
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type ([MouseState]::Down)
                    }
                )

                $virtualDesktopSyncHash.VirtualDesktop.Picture.Add_MouseUp(
                    { 
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type ([MouseState]::Up)
                    }
                )

                $virtualDesktopSyncHash.VirtualDesktop.Picture.Add_MouseMove(
                    { 
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type ([MouseState]::Move)
                    }
                )          

                $virtualDesktopSyncHash.VirtualDesktop.Picture.Add_MouseWheel(
                    {
                        $aEvent = New-Object PSCustomObject -Property @{
                            Id = [OutputEvent]::MouseWheel
                            Delta = $_.Delta
                        }

                        $outputEventSyncHash.Writer.WriteLine(($aEvent | ConvertTo-Json -Compress))
                    }
                )  
            }

            Write-Verbose "Create runspace for desktop streaming..."            

            $param = New-Object -TypeName PSCustomObject -Property @{
                Client = $session.ClientDesktop
                VirtualDesktopSyncHash = $virtualDesktopSyncHash                            
                VirtualDesktopWidth = $virtualDesktopWidth 
                VirtualDesktopHeight = $virtualDesktopHeight
                RequireResize = $requireResize
                TransportMode = [TransportMode] $session.SessionInformation.TransportMode                
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

            $null = $virtualDesktopSyncHash.VirtualDesktop.Form.ShowDialog()
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

            if ($virtualDesktopSyncHash.VirtualDesktop)
            {            
                $virtualDesktopSyncHash.VirtualDesktop.Form.Dispose()
            }                                    
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