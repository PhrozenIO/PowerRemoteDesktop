<#-------------------------------------------------------------------------------

    Power Remote Desktop
    Version 1.0b
    REL: January 2022.

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

    .Todo                          
        - [EASY] Support Password Protected external Certificates.
        - [EASY] Server Fingerprint Authentication.
        - [EASY] Mutual Authentication for SSL/TLS (Client Certificate).
        - [EASY] Improve Error Control Flow.        
        - [EASY] Synchronize Cursor State.
        - [EASY] Improve Comments.
        - [EASY] Better detail on Verbose with possibility to disable verbose.
        - [EASY] Synchronize Clipboard. 
        - [EASY] Handle new client acceptation on a separated Runspace to avoid locks which could cause DoS of the Service.
                 This will be naturally fixed when I will implement my final version of client Connection Handler system.

        - [MEDIUM] Keep-Alive system to implement Read / Write Timeout.
        - [MEDIUM] Improve Virtual Keyboard.    
        - [MEDIUM] Server Concurrency.
        - [MEDIUM] Listen for local/remote screen resolution update event.
        - [MEDIUM] Multiple Monitor Support.
        - [MEDIUM] Improve HDPI Scaling / Quality.
        - [MEDIUM+] Motion Update for Desktop Streaming (Only send and update changing parts of desktop).

-------------------------------------------------------------------------------#>

Add-Type -Assembly System.Windows.Forms

$global:PowerRemoteDesktopVersion = "1.0.beta.2"

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

        .PARAMETER Password
            Registered password string for server authentication.

        .PARAMETER Candidate
            Random string used to solve the challenge. This string is public and is set across network by server.
            Each time a new connection is requested to server, a new candidate is generated.

        .EXAMPLE
            Resolve-AuthenticationChallenge -Password "s3cr3t!" -Candidate "rKcjdh154@]=Ldc"
    #>
    param (        
       [Parameter(Mandatory=$True)]
       [string] $Password, 

       [Parameter(Mandatory=$True)]
       [string] $Candidate
    )

    $solution = -join($Candidate, ":", $Password)

    for ([int] $i = 0; $i -le 1000; $i++)
    {
        $solution = Get-SHA512FromString -String $solution
    }

    return $solution
}

$global:VirtualDesktopUpdaterScriptBlock = {   
    <#
        .SYNOPSIS
            Threaded code block to receive updates of remote desktop and update Virtual Desktop Form.

            This code is expected to be run inside a new PowerShell Runspace.

        .PARAMETER syncHash.RequireResize
            Tell if desktop image needs to be resized to fit viewer screen constrainsts.

        .PARAMETER syncHash.Client
            A ClientIO Class instance for handling desktop updates.

        .PARAMETER syncHash.VirtualDesktopWidth
            The integer value representing remote screen width.

        .PARAMETER syncHash.VirtualDesktopHeight
            The integer value representing remote screen height.

        .PARAMETER syncHash.VirtualDesktopForm
            Virtual Desktop Object containing both Form and PaintBox.       

        .PARAMETER syncHash.TransportMode
            Define desktop image transport mode: Raw or Base64. This value is defined by server following
            its options.
    #>

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
                switch ([TransportMode] $syncHash.TransportMode)         
                {
                    "Raw"
                    {
                        $buffer = New-Object -TypeName byte[] -ArgumentList 4 # SizeOf(Int32)

                        $syncHash.Client.SSLStream.Read($buffer, 0, $buffer.Length)

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

                            $syncHash.Client.SSLStream.Read($buffer, 0, $bufferSize)                    

                            $stream.Write($buffer, 0, $buffer.Length) | Out-Null

                            $totalBytesRead += $bufferSize
                        } until ($totalBytesRead -eq $totalBufferSize)
                    }

                    "Base64"
                    {
                        [byte[]] $buffer = [System.Convert]::FromBase64String(($syncHash.Client.Reader.ReadLine()))

                        $stream.Write($buffer, 0, $buffer.Length)   
                    }
                }                    

                $stream.Position = 0                                                                

                if ($syncHash.RequireResize)
                {
                   #$image = [System.Drawing.Image]::FromStream($stream)

                   $bitmap = New-Object -TypeName System.Drawing.Bitmap -ArgumentList $stream

                   $syncHash.VirtualDesktopForm.Picture.Image = Invoke-SmoothResize -OriginalImage $bitmap -NewWidth $syncHash.VirtualDesktopWidth -NewHeight $syncHash.VirtualDesktopHeight                   
                }
                else
                {                    
                    $syncHash.VirtualDesktopForm.Picture.Image = [System.Drawing.Image]::FromStream($stream)                                                          
                }
            }
            catch 
            {
                $syncHash.host.UI.WriteLine($_)
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
        $syncHash.VirtualDesktopForm.Form.Close()
    }
}

class ClientIO {
    <#
        .SYNOPSIS
            Extended version of TcpClient that automatically creates and releases
            required streams with other useful methods.

            Supports SSL/TLS.
    #>

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
        Write-Verbose "Connect to server ""$($this.RemoteAddress):$($this.RemotePort)..."""

        $this.Client = New-Object System.Net.Sockets.TcpClient($this.RemoteAddress, $this.RemotePort)

        Write-Verbose "Connected.  Create new SSL Stream..."

        $this.SSLStream = New-object System.Net.Security.SslStream(
            $this.Client.GetStream(),
            $false,
            {
                    param(
                        $Sender,
                        $Certificate,
                        $Chain,
                        $Policy
                ) 

                return $true # Always return valid (TODO: Certificate / Fingerprint Validation)
            }
        )

        if ($this.TLSv1_3)
        {
            $TLSVersion = [System.Security.Authentication.SslProtocols]::TLS13
        }
        else {
            $TLSVersion = [System.Security.Authentication.SslProtocols]::TLS12
        }

        Write-Verbose "Authenticate as client using ${TLSVersion}..."

        $this.SSLStream.AuthenticateAsClient(
            "PowerRemoteDesktop",
            $null,
            $TLSVersion,
            $null
        )

        if (-not $this.SSLStream.IsEncrypted)
        {
            throw "Could not established an encrypted tunnel with server."
        }

        Write-Verbose "Open communication channels..."

        $this.Writer = New-Object System.IO.StreamWriter($this.SSLStream)
        $this.Writer.AutoFlush = $true

        $this.Reader = New-Object System.IO.StreamReader($this.SSLStream)        
    }

    [bool]Authentify([string] $Password) {
        <#
            .SYNOPSIS
                Handle authentication process with remote server.

            .PARAMETER Password
                Password used for authentication with server.

            .EXAMPLE
                .Authentify("s3cr3t!")
        #>
        if (-not $Password) { return $false }
        try
        {
            Write-Verbose "Authentify to remote server..."

            $candidate = $this.Reader.ReadLine()            

            Write-Verbose "Challenge candidate received: ""${candidate}"". Resolving challenge..."

            $challengeSolution = Resolve-AuthenticationChallenge -Candidate $candidate -Password $Password   

            Write-Verbose "Offered solution: ""${challengeSolution}"". Sending to server..."

            $this.Writer.WriteLine($challengeSolution)

            $result = $this.Reader.ReadLine()
            if ($result -eq "OK.")
            {
                Write-Verbose "Authentication success."

                return $true
            }            
            else 
            {
                Write-Verbose "Authentication failed."

                return $false
            }
        }
        catch 
        {
            return $false
        }
    }

    [bool]Hello([string] $SessionId) {
        <#
            .SYNOPSIS
                This method must be called before password authentication if current connection requires
                session pre-authentication.

            .PARAMETER SessionId
                A String containing the Session Id.
        #>

        Write-Verbose "Starting Session Pre-Auth."

        Write-Verbose "Sending Session Token: ${SessionId}"

        $this.Writer.WriteLine($SessionId)

        $result = $this.Reader.ReadLine()
        if ($result -eq "HELLO.")
        {
            Write-Verbose "Session Pre-Auth Success."

            return $true
        }            
        else 
        {
            Write-Verbose "Session Pre-Auth Failed."

            return $false
        }
    }

    [void]Close() {
        <#
            .SYNOPSIS
                Release streams and client.
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

function Invoke-RemoteDesktopViewer
{
    <#
        .SYNOPSIS
            Open a new Remote Desktop Session to remote Server.

        .PARAMETER ServerAddress
            Remote Server Address.

        .PARAMETER ServerPort
            Remote Server Port.

        .PARAMETER DisableInputControl
            If set to $true, this option disables control events on form (Mouse Clicks, Moves and Keyboard)
            This option is generally set to true during development when connecting to local machine to avoid funny
            things.

        .PARAMETER Password
            Password used during server authentication.

        .PARAMETER TLSv1_3
            Define whether or not client must use SSL/TLS v1.3 to communicate with remote server.
            Recommended if possible.

        .EXAMPLE
            Invoke-RemoteDesktopViewer -ServerAddress "192.168.0.10" -ServerPort "2801" -Password "s3cr3t!"
            Invoke-RemoteDesktopViewer -ServerAddress "127.0.0.1" -ServerPort "2801" -Password "Just4TestingLocally!"

    #>
    param (        
        [string] $ServerAddress = "127.0.0.1",
        [int] $ServerPort = 2801,
        [bool] $DisableInputControl = $false,
        [bool] $TLSv1_3 = $false,

        [Parameter(Mandatory=$true)]
        [string] $Password
    )

    $oldErrorActionPreference = $ErrorActionPreference
    $oldVerbosePreference = $VerbosePreference
    try
    {
        $ErrorActionPreference = "stop"
        $VerbosePreference = "continue"

        Write-Banner 
                
        Write-Verbose "Server address: ""${ServerAddress}:${ServerPort}"""
        Write-Verbose "Connect to server for Desktop Streaming..."

        # Create Client Socket for Desktop Capture
        $clientDesktop = [ClientIO]::New($ServerAddress, $ServerPort, $TLSv1_3)
        $clientDesktop.Connect()

        if (-not $clientDesktop.Authentify($Password))
        {
            throw "Could not connect to target server. Authentication error."
        }

        Write-Verbose "Connection established. Waiting for session information..."
        $jsonObject = $clientDesktop.Reader.ReadLine()

        Write-Verbose $jsonObject

        $sessionInformation = $jsonObject | ConvertFrom-Json
        if (
            (-not ($sessionInformation.PSobject.Properties.name -match "MachineName")) -or
            (-not ($sessionInformation.PSobject.Properties.name -match "Username")) -or
            (-not ($sessionInformation.PSobject.Properties.name -match "WindowsVersion")) -or
            #(-not ($sessionInformation.PSobject.Properties.name -match "ScreenWidth")) -or
            #(-not ($sessionInformation.PSobject.Properties.name -match "ScreenHeight")) -or
            #(-not ($sessionInformation.PSobject.Properties.name -match "ScreenX")) -or
            #(-not ($sessionInformation.PSobject.Properties.name -match "ScreenY")) -or            
            (-not ($sessionInformation.PSobject.Properties.name -match "SessionId")) -or
            (-not ($sessionInformation.PSobject.Properties.name -match "TransportMode")) -or
            (-not ($sessionInformation.PSobject.Properties.name -match "Version")) -or
            (-not ($sessionInformation.PSobject.Properties.name -match "ScreenInformation"))
        )
        {
            throw "Invalid System Information Object. Abort connection..."
        }   
        
        if ($sessionInformation.Version -ne $global:PowerRemoteDesktopVersion)
        {
            throw "PowerRemoteDesktop version mismatch. Local version ""${global:PowerRemoteDesktopVersion}"" != Remote version ""$($sessionInformation.Version)""."
        }

        Write-Verbose "Connect to server for Input Control..."

        # Create Client Socket for Desktop Control (Mouse / Keyboard)
        $clientControl = [ClientIO]::new($ServerAddress, $ServerPort, $TLSv1_3) 
        $clientControl.Connect()

        if (-not $clientControl.Hello($sessionInformation.SessionId))
        {
            throw "Could not connect to target server. Session Pre-Auth Failed."
        }

        if (-not $clientControl.Authentify($Password))
        {
            throw "Could not connect to target server. Authentication error."
        }

        Write-Verbose "Connection established."
        try
        {
            Write-Verbose "Prepare environment. Create Virtual Desktop Form and Runspace for handling frame updates..."

            $virtualDesktopForm = New-VirtualDesktopForm            

            $virtualDesktopForm.Form.Text = [string]::Format(
                "Power Remote Desktop: {0}/{1} - {2}", 
                $sessionInformation.Username,
                $sessionInformation.MachineName,
                $sessionInformation.WindowsVersion
            )

            # Prepare Virtual Desktop 
            $locationResolutionInformation = [System.Windows.Forms.Screen]::PrimaryScreen

            $screenRect = $virtualDesktopForm.Form.RectangleToScreen($virtualDesktopForm.Form.ClientRectangle)
            $captionHeight = $screenRect.Top - $virtualDesktopForm.Form.Top

            $requireResize = (
                ($locationResolutionInformation.WorkingArea.Width -le $sessionInformation.ScreenInformation.Width) -or
                (($locationResolutionInformation.WorkingArea.Height - $captionHeight) -le $sessionInformation.ScreenInformation.Height)            
            )

            $virtualDesktopWidth = 0
            $virtualDesktopHeight = 0

            $resizeRatio = 80

            if ($requireResize)
            {            
                $virtualDesktopWidth = [math]::Round(($sessionInformation.ScreenInformation.Width * $resizeRatio) / 100)
                $virtualDesktopHeight = [math]::Round(($sessionInformation.ScreenInformation.Height * $resizeRatio) / 100)            
            }
            else
            {
                $virtualDesktopWidth = $sessionInformation.ScreenInformation.Width
                $virtualDesktopHeight = $sessionInformation.ScreenInformation.Height
            }

            # Size Virtual Desktop Form Window
            $virtualDesktopForm.Form.ClientSize = [System.Drawing.Size]::new($virtualDesktopWidth, $virtualDesktopHeight) 

            # Center Virtual Desktop Form
            $virtualDesktopForm.Form.Location = [System.Drawing.Point]::new(
                (($locationResolutionInformation.WorkingArea.Width - $virtualDesktopForm.Form.Width) / 2),
                (($locationResolutionInformation.WorkingArea.Height - $virtualDesktopForm.Form.Height) / 2)
            )

            # Prepare our synchronized hashtable   
            $syncHash = [HashTable]::Synchronized(@{})         
            $syncHash.VirtualDesktopForm = $virtualDesktopForm
            $syncHash.Client = $clientDesktop
            $syncHash.host = $host # Mostly for debugging 
            $syncHash.VirtualDesktopWidth = $virtualDesktopWidth 
            $syncHash.VirtualDesktopHeight = $virtualDesktopHeight
            $syncHash.RequireResize = $requireResize
            $syncHash.TransportMode = $sessionInformation.TransportMode

            # WinForms Events (If enabled, I recommend to disable control when testing on local machine to avoid funny things)
            if (-not $DisableInputControl)                   
            {
                enum InputCommand {
                    Keyboard = 0x1
                    MouseClickMove = 0x2
                    MouseWheel = 0x3
                }

                enum MouseState {
                    Up = 0x1
                    Down = 0x2
                    Move = 0x3
                }

                function New-MouseCommand
                {
                    <#
                        .SYNOPSIS
                            Generate a new mouse command object to be sent to server.
                            This command is used to simulate mouse move and clicks.

                        .PARAMETER X
                            The position of mouse in horizontal axis.

                        .PARAMETER Y
                            The position of mouse in vertical axis.

                        .PARAMETER Type
                            The type of mouse event (Example: Move, Click)

                        .PARAMETER Button
                            The pressed button on mouse (Example: Left, Right, Middle)

                        .EXAMPLE
                            New-MouseCommand -X 10 -Y 35 -Type "Up" -Button "Left"
                            New-MouseCommand -X 10 -Y 35 -Type "Down" -Button "Left"
                            New-MouseCommand -X 100 -Y 325 -Type "Move"
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
                        Id = [int][InputCommand]::MouseClickMove
                        X = $X
                        Y = $Y
                        Button = $Button
                        Type = [int]$Type 
                    }
                }

                function New-KeyboardCommand
                {
                    <#
                        .SYNOPSIS
                            Generate a new keyboard command object to be sent to server.
                            This command is used to simulate keyboard strokes.  

                        .PARAMETER Keys
                            Plain text keys to be simulated on remote computer.

                        .TODO
                            Supports more complex keys (ARROWS ETC...)

                        .EXAMPLE
                            New-KeyboardCommand -Keys "Hello, World"
                            New-KeyboardCommand -Keys "t"
                    #>
                    param (
                        [Parameter(Mandatory=$true)]
                        [string] $Keys
                    )

                    return New-Object PSCustomObject -Property @{
                        Id = [int][InputCommand]::Keyboard
                        Keys = $Keys
                    }
                }

                function Send-VirtualMouse
                {
                    <#
                        .SYNOPSIS
                            Transform the virtual mouse (the one in Virtual Desktop Form) coordinates to real remote desktop
                            screen coordinates (especially when incomming desktop frames are resized)

                            When command is generated, it is immediately sent to remote server.

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
      
                    $X += $sessionInformation.ScreenInformation.X
                    $Y += $sessionInformation.ScreenInformation.Y

                    $command = (New-MouseCommand -X $X -Y $Y -Button $Button -Type $Type)                    

                    $clientControl.Writer.WriteLine(($command | ConvertTo-Json -Compress))                    
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

                    $command = (New-KeyboardCommand -Keys $KeyChain)                                

                    $clientControl.Writer.WriteLine(($command  | ConvertTo-Json -Compress)) 
                }

                $virtualDesktopForm.Form.Add_KeyPress(
                    { 
                        if ($_.KeyChar)
                        {
                            $String = [string]$_.KeyChar

                            $String = $String.Replace("{", "{{}")
                            $String = $String.Replace("}", "{}}")

                            $String = $String.Replace("+", "{+}")
                            $String = $String.Replace("^", "{^}")
                            $String = $String.Replace("%", "{%}")
                            $String = $String.Replace("~", "{%}")
                            $String = $String.Replace("(", "{()}")
                            $String = $String.Replace(")", "{)}")
                            $String = $String.Replace("[", "{[]}")
                            $String = $String.Replace("]", "{]}")    

                            Send-VirtualKeyboard -KeyChain $String                   
                        }                        
                    }
                )       

                $virtualDesktopForm.Form.Add_KeyDown(
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

                $virtualDesktopForm.Picture.Add_MouseDown(
                    {                         
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type "Down"
                    }
                )

                $virtualDesktopForm.Picture.Add_MouseUp(
                    { 
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type "Up"
                    }
                )

                $virtualDesktopForm.Picture.Add_MouseMove(
                    { 
                        Send-VirtualMouse -X $_.X -Y $_.Y -Button $_.Button -Type "Move"
                    }
                )          

                $virtualDesktopForm.Picture.Add_MouseWheel(
                    {
                        $command = New-Object PSCustomObject -Property @{
                            Id = [int][InputCommand]::MouseWheel
                            Delta = $_.Delta
                        }

                        $clientControl.Writer.WriteLine(($command | ConvertTo-Json -Compress))
                    }
                )  
            }

            Write-Verbose "Create and open new runspace..."

            $runspace = [RunspaceFactory]::CreateRunspace()
            $runspace.ThreadOptions = "ReuseThread"
            $runspace.ApartmentState = "STA"
            $runspace.Open()                                                       

            $runspace.SessionStateProxy.SetVariable("syncHash", $syncHash)

            $powershell = [PowerShell]::Create().AddScript($global:VirtualDesktopUpdaterScriptBlock)
            $powershell.Runspace = $runspace
            $asyncResult = $powershell.BeginInvoke()   

            Write-Verbose "Done. Environment successfully created. Showing Virtual Desktop Form."                       

            $virtualDesktopForm.Form.ShowDialog() | Out-Null                         
        }
        finally
        {    
            Write-Verbose "Virtual Desktop Form closed, free/restore environment."

            if ($clientDesktop)
            {
                $clientDesktop.Close()
            }

            if ($clientControl)
            {
                $clientControl.Close()
            }

            if ($powershell) 
            {         
                if ($asyncResult)
                {
                    $powershell.EndInvoke($asyncResult) | Out-Null
                }

                $powershell.Runspace.Dispose()                  
                $powershell.Dispose()
            } 

            if ($syncHash.VirtualDesktopForm.Form)
            {            
                $syncHash.VirtualDesktopForm.Form.Dispose()
            }                                    
        }   

        Write-Verbose "Done."
    }
    finally
    {    
        $ErrorActionPreference = $oldErrorActionPreference   
        $VerbosePreference = $oldVerbosePreference        
    } 
}

try {  
    Export-ModuleMember -Function Invoke-RemoteDesktopViewer
} catch {}