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
        - [EASY] Add option for TLS v1.3.        
        - [EASY] Version Synchronization.
        - [EASY] Support Password Protected external Certificates.
        - [EASY] Server Fingerprint Authentication.
        - [EASY] Mutual Authentication for SSL/TLS (Client Certificate).
        - [EASY] Improve Error Control Flow.        
        - [EASY] Synchronize Cursor State.
        - [EASY] Improve Comments.
        - [EASY] Better detail on Verbose with possibility to disable verbose.
        - [EASY] Synchronize Clipboard. 
        - [EASY] Handle new client acceptation on a separated Runspace to avoid locks which could cause DoS of the Service.
                 This will be naturally fixed when I will implement my final version of client Connection Handler System.

        - [MEDIUM] Improve Virtual Keyboard.
        - [MEDIUM] Avoid Base64 for Desktop Steaming (Only if 100% Stable).
                   It sounds obvious that writing RAW Bytes using Stream.Write is 100% stable but strangely locally
                   it worked like a charm but while testing remotely, it sometimes acted funny. I will investigate about
                   this issue and re-implement my other technique. 

        - [MEDIUM] Server Concurrency.
        - [MEDIUM] Listen for local/remote screen resolution update event.
        - [MEDIUM] Multiple Monitor Support.
        - [MEDIUM] Improve HDPI Scaling / Quality.
        - [MEDIUM+] Motion Update for Desktop Streaming (Only send and update changing parts of desktop).

-------------------------------------------------------------------------------#>

Add-Type -Assembly System.Windows.Forms
Add-Type -Assembly System.Drawing
Add-Type -MemberDefinition '[DllImport("gdi32.dll")] public static extern int GetDeviceCaps(IntPtr hdc, int nIndex);' -Name GDI32 -Namespace W;
Add-Type -MemberDefinition '[DllImport("User32.dll")] public static extern int GetDC(IntPtr hWnd);[DllImport("User32.dll")] public static extern int ReleaseDC(IntPtr hwnd, int hdc);' -Name User32 -Namespace W;

function Write-Banner 
{
    <#
        .SYNOPSIS
            Output cool information about current PowerShell module to terminal.
    #>

    Write-Host ""
    Write-Host "Power Remote Desktop Server- Version " -NoNewLine
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

function New-DefaultX509Certificate
{    
    <#
        .SYNOPSIS
            Generate and install a new self-signed X509 Certificate and install on local machine.

        .DESCRIPTION
            This function is called only if no custom certificate are defined when starting a new Remote
            Desktop Server.

            Important Notice:
                This function requires administrator privileges to enroll / install certificate on local machine.
                If you don't provide your own certificate, you will need to run Remote Desktop Server through an
                elevated PowerShell version.

                You can generate your own certificate using the following OpenSSL commands:
                    * openssl req -x509 -sha512 -nodes -days 365 -newkey rsa:4096 -keyout phrozen.key -out phrozen.crt
                    * openssl pkcs12 -export -out phrozen.p12 -inkey phrozen.key -in phrozen.crt

                Then use the CertificateFile option and use the p12 file.

                You can also export the newly created certificate in Base64 and use it with EncodedCertificate option.
                    * base64 -i phrozen.p12

        .PARAMETER X509_CN
            Certificate Common Name.

        .PARAMETER X509_O
            Certificate Organisation.

        .PARAMETER X509_L
            Certificate Locality (City)

        .PARAMETER X509_S
            Certificate State.

        .PARAMETER X509_C
            Certificate Company Name.

        .PARAMETER X509_OU
            Certificate Organizational Unit.

        .PARAMETER HashAlgorithmName
            Certificate Hash Algorithm.
                Example: SHA128, SHA256, SHA512...

        .PARAMETER CertExpirationInDays
            Certificate Expiration in days.
    #>
    param (
        [string] $X509_CN = "PowerRemoteDesktop.Server",
        [string] $X509_O = "Phrozen",
        [string] $X509_L = "Maisons Laffitte",
        [string] $X509_S = "Yvelines",
        [string] $X509_C = "FR",
        [string] $X509_OU = "Freeware",
        [string] $HashAlgorithmName = "SHA512",
        [int] $CertExpirationInDays = 365
    )

    enum X500NameFlags {
        XCN_CERT_NAME_STR_NONE
        XCN_CERT_SIMPLE_NAME_STR
        XCN_CERT_OID_NAME_STR
        XCN_CERT_X500_NAME_STR
        XCN_CERT_XML_NAME_STR
        XCN_CERT_NAME_STR_SEMICOLON_FLAG
        XCN_CERT_NAME_STR_NO_PLUS_FLAG
        XCN_CERT_NAME_STR_NO_QUOTING_FLAG
        XCN_CERT_NAME_STR_CRLF_FLAG
        XCN_CERT_NAME_STR_COMMA_FLAG
        XCN_CERT_NAME_STR_REVERSE_FLAG
        XCN_CERT_NAME_STR_FORWARD_FLAG
        XCN_CERT_NAME_STR_AMBIGUOUS_SEPARATOR_FLAGS
        XCN_CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
        XCN_CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG
        XCN_CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG
        XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG
        XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG
        XCN_CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
        XCN_CERT_NAME_STR_DS_ESCAPED
    }

    enum CAPICOM_KEY_SPEC {
        CAPICOM_KEY_SPEC_KEYEXCHANGE = 1
        CAPICOM_KEY_SPEC_SIGNATURE = 2
    }
    
    enum ObjectIdGroupId {
        XCN_CRYPT_ANY_GROUP_ID = 0
        XCN_CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2
        XCN_CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7
        XCN_CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6
        XCN_CRYPT_FIRST_ALG_OID_GROUP_ID = 1
        XCN_CRYPT_GROUP_ID_MASK = 65535
        XCN_CRYPT_HASH_ALG_OID_GROUP_ID = 1
        XCN_CRYPT_KEY_LENGTH_MASK = 268369920
        XCN_CRYPT_LAST_ALG_OID_GROUP_ID = 4
        XCN_CRYPT_LAST_OID_GROUP_ID = 10
        XCN_CRYPT_OID_DISABLE_SEARCH_DS_FLAG = -2147483648
        XCN_CRYPT_OID_INFO_OID_GROUP_BIT_LEN_MASK = 268369920
        XCN_CRYPT_OID_INFO_OID_GROUP_BIT_LEN_SHIFT = 16
        XCN_CRYPT_OID_PREFER_CNG_ALGID_FLAG = 1073741824
        XCN_CRYPT_POLICY_OID_GROUP_ID = 8
        XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3
        XCN_CRYPT_RDN_ATTR_OID_GROUP_ID = 5
        XCN_CRYPT_SIGN_ALG_OID_GROUP_ID = 4
        XCN_CRYPT_TEMPLATE_OID_GROUP_ID = 9
    }    

    enum X509ContentType {
        Authenticode = 6
        Cert = 1
        Pfx = 3
        Pkcs12 = 3
        Pkcs7 = 5
        SerializedCert = 2
        SerializedStore = 4
        Unknown = 0
    }

    enum X509PrivateKeyExportFlags {
        XCN_NCRYPT_ALLOW_EXPORT_NONE
        XCN_NCRYPT_ALLOW_EXPORT_FLAG
        XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
        XCN_NCRYPT_ALLOW_ARCHIVING_FLAG
        XCN_NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG
    }

    enum ObjectIdPublicKeyFlags {
        XCN_CRYPT_OID_INFO_PUBKEY_ANY
        XCN_CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG
        XCN_CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG
    }

    enum X509CertificateEnrollmentContext {
        ContextNone
        ContextUser
        ContextMachine
        ContextAdministratorForceMachine
    }

    enum InstallResponseRestrictionFlags {
        AllowNone
        AllowNoOutstandingRequest
        AllowUntrustedCertificate
        AllowUntrustedRoot
    } 

    enum EncodingType {
        XCN_CRYPT_STRING_BASE64HEADER
        XCN_CRYPT_STRING_BASE64
        XCN_CRYPT_STRING_BINARY
        XCN_CRYPT_STRING_BASE64REQUESTHEADER
        XCN_CRYPT_STRING_HEX
        XCN_CRYPT_STRING_HEXASCII
        XCN_CRYPT_STRING_BASE64_ANY
        XCN_CRYPT_STRING_ANY
        XCN_CRYPT_STRING_HEX_ANY
        XCN_CRYPT_STRING_BASE64X509CRLHEADER
        XCN_CRYPT_STRING_HEXADDR
        XCN_CRYPT_STRING_HEXASCIIADDR
        XCN_CRYPT_STRING_HEXRAW
        XCN_CRYPT_STRING_BASE64URI
        XCN_CRYPT_STRING_ENCODEMASK
        XCN_CRYPT_STRING_CHAIN
        XCN_CRYPT_STRING_TEXT
        XCN_CRYPT_STRING_PERCENTESCAPE
        XCN_CRYPT_STRING_HASHDATA
        XCN_CRYPT_STRING_STRICT
        XCN_CRYPT_STRING_NOCRLF
        XCN_CRYPT_STRING_NOCR
    }

    # Create X.509 Certificate
    $distinguishedName = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName.1'

    # Feel free to edit bellow information with your own.
    $distinguishedName.Encode(
        "CN=${X509_CN},O=${X509_O},L=${X509_L},S=${X509_S},C=${X509_C},OU=${X509_OU}",
        [int][X500NameFlags]::XCN_CERT_NAME_STR_NONE
    )

    # Generate new Private Key    
    $privateKey = New-Object -ComObject 'X509Enrollment.CX509PrivateKey.1'
    $privateKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"  

    $privateKey.ExportPolicy = [int][X509PrivateKeyExportFlags]::XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
    $privateKey.KeySpec = [int][CAPICOM_KEY_SPEC]::CAPICOM_KEY_SPEC_KEYEXCHANGE
    $privateKey.Length = 4096
    $privateKey.MachineContext = $true

    $privateKey.Create()

    # Create Hash Algorithm Object
    $hashAlgorithm = New-Object -ComObject 'X509Enrollment.CObjectId.1'
    $hashAlgorithm.InitializeFromAlgorithmName(
        [int][ObjectIdGroupId]::XCN_CRYPT_FIRST_ALG_OID_GROUP_ID,
        [int][ObjectIdGroupId]::XCN_CRYPT_ANY_GROUP_ID,
        [int][ObjectIdPublicKeyFlags]::XCN_CRYPT_OID_INFO_PUBKEY_ANY,
        $HashAlgorithmName
    )
    
    # Generate Certificate
    $certificate = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestCertificate.1'

    $certificate.InitializeFromPrivateKey(
        [int][X509CertificateEnrollmentContext]::ContextAdministratorForceMachine,
        $privateKey,
        ""
    )

    $certificate.Subject = $distinguishedName     
    $certificate.Issuer = $distinguishedName     

    $certificate.HashAlgorithm = $hashAlgorithm

    $certificate.NotBefore = [DateTime]::Now.AddDays(-1)
    $certificate.NotAfter = [DateTime]::Now.AddDays($CertExpirationInDays)

    $certificate.Encode()

    # Enroll
    $enroll = New-Object -ComObject 'X509Enrollment.CX509Enrollment.1'
    $enroll.InitializeFromRequest($certificate)
    $enroll.CertificateFriendlyName = "Phrozen, PowerRemoteDesktop Server"

    $certificateContent = $enroll.CreateRequest()

    # Install Certificate
    $Enroll.InstallResponse(
        [int][InstallResponseRestrictionFlags]::AllowUntrustedCertificate,
        $certificateContent,
        [int][EncodingType]::XCN_CRYPT_STRING_BASE64,
        "" # No password
    )   
}

function Get-X509CertificateFromStore
{
    <#
        .SYNOPSIS
            Retrieve a X509 Certificate from local machine certificate store using its Subject Name.

        .DESCRIPTION
            Notice, as for generating a new self-signed certificate. This function requires an administrator
            privilege to recover the complete certificate (including the private key).

            It then needs to be run inside an elevated PowerShell session.

            To avoid this issue, as for generating a self-signed certificate, you must provide your own
            certificate when starting a new Remote Desktop Server.

        .PARAMETER SubjectName
            The certificate Subject Name to retrieve from local machine certificate store.

        .EXAMPLE
            Get-X509CertificateFromStore -SubjectName "PowerRemoteDesktop.Server"
    #>
    param (
        [string] $SubjectName = "PowerRemoteDesktop.Server"
    )

    enum StoreLocation {
        CurrentUser = 1
        LocalMachine = 2
    }

    enum OpenFlags {
        IncludeArchived = 8
        MaxAllowed = 2
        OpenExistingOnly = 4
        ReadOnly = 0
        ReadWrite = 1
    }

    enum StoreName {
        AddressBook = 1
        AuthRoot = 2
        CertificateAuthority = 3
        Disallowed = 4
        My = 5
        Root = 6
        TrustedPeople = 7
        TrustedPublisher = 8
    }

    enum X509FindType {
        FindByApplicationPolicy = 10
        FindByCertificatePolicy = 11
        FindByExtension = 12
        FindByIssuerDistinguishedName = 4
        FindByIssuerName = 3
        FindByKeyUsage = 13
        FindBySerialNumber = 5
        FindBySubjectDistinguishedName = 2
        FindBySubjectKeyIdentifier = 14
        FindBySubjectName = 1
        FindByTemplateName = 9
        FindByThumbprint = 0
        FindByTimeExpired = 8
        FindByTimeNotYetValid = 7
        FindByTimeValid = 6
    }

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [StoreName]::My,
        [StoreLocation]::LocalMachine
    )

    $store.Open([OpenFlags]::ReadOnly)
    try
    {
        $certCollection = $store.Certificates

        return $certCollection.Find(
            [X509FindType]::FindBySubjectName,
             $SubjectName,
             $false
        )[0]        
    }
    finally
    {
        $store.Close()   
    }
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
        
        .DESCRIPTION
            Server needs to resolve the challenge and keep the solution in memory before sending
            the candidate to remote peer.

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

class ClientIO {
    <#
        .SYNOPSIS
            Extended version of TcpClient that automatically creates and releases
            required streams with other useful methods.

            Supports SSL/TLS.
    #>

    [System.Net.Sockets.TcpClient] $Client = $null
    [System.IO.StreamWriter] $Writer = $null
    [System.IO.StreamReader] $Reader = $null
    [System.Net.Security.SslStream] $SSLStream = $null

    ClientIO(
        [System.Net.Sockets.TcpClient] $Client,
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    ) {
        <#
            .SYNOPSIS
                Class constructor.

            .PARAMETER Client
                TcpClient instance returned by listener.

            .PARAMETER Certificate
                X509 Certificate used for SSL/TLS encryption tunnel.
        #>

        if ((-not $Client) -or (-not $Certificate))
        {
            throw "ClientIO Class requires both a valid TcpClient and X509Certificate2."
        }
        
        $this.Client = $Client

        Write-Verbose "Create new SSL Stream..."

        $this.SSLStream = New-Object System.Net.Security.SslStream($this.Client.GetStream(), $false)        

        Write-Verbose "Authenticate as server..."

        $this.SSLStream.AuthenticateAsServer(
            $Certificate,
            $false,
            [System.Security.Authentication.SslProtocols]::TLS12, # TODO: Also Support 1.3
            $false
        )

        if (-not $this.SSLStream.IsEncrypted)
        {
            throw "Could not established an encrypted tunnel with remote peer."
        }

        Write-Verbose "Open communication channels..."

        $this.Writer = New-Object System.IO.StreamWriter($this.SSLStream)
        $this.Writer.AutoFlush = $true

        $this.Reader = New-Object System.IO.StreamReader($this.SSLStream)      

        Write-Verbose "Connection ready for use."  
    }

    [bool]Authentify([string] $Password) {
        <#
            .SYNOPSIS
                Handle authentication process with remote peer.

            .PARAMETER Password
                Password used to validate challenge and grant access for a new Client.

            .EXAMPLE
                .Authentify("s3cr3t!")
        #>
        if (-not $Password) { return $false }
        try
        {            
            Write-Verbose "Generate new challenge, this might take up to few seconds..."

            $candidate = (-join ((33..126) | Get-Random -Count 128 | %{[char] $_}))
            $candidate = Get-SHA512FromString -String $candidate

            $challengeSolution = Resolve-AuthenticationChallenge -Candidate $candidate -Password $Password   

            Write-Verbose "Challenge Solution: ""${challengeSolution}"" for candidate: ""${candidate}"""  

            $this.Writer.WriteLine($candidate)

            Write-Verbose "Candidate sent to remote viewer. Waiting for answer..."

            $challengeReply = $this.Reader.ReadLine()
            if ($challengeReply -ne $challengeSolution)
            {
                Write-Verbose "Viewer challenge was not resolved. Bad Password!"

                $this.Writer.WriteLine("KO.")

                return $false
            }
            else
            {
                Write-Verbose "Challenge accepted. Connection granted!. Notify."

                $this.Writer.WriteLine("OK.")

                return $true
            }
        }
        catch 
        {
            return $false
        }
    }

    [bool]Hello([string] $SessionId, [string] $Address) {
        <#
            .SYNOPSIS
                This method must be called before password authentication if current connection requires
                session pre-authentication.

            .PARAMETER SessionId
                A String containing the Session Id.

            .PARAMETER Address
                A String containing peer expected address (Tied to session during session generation).
        #>

        Write-Verbose "Starting Session Pre-Auth with Remote Peer. Waiting for Session Id."        

        try 
        {
            $receivedSessionId = $this.Reader.ReadLine()

            Write-Verbose "Received Session Token: ${SessionId}. Comparing..."

            if (($SessionId -eq $receivedSessionId) -and ($Address -eq $this.RemoteAddress()))
            {
                Write-Verbose "Session Pre-Auth Success."

                $this.Writer.WriteLine("HELLO.")

                return $true
            }
            else
            {
                Write-Verbose "Session Pre-Auth Failed."

                $this.Writer.WriteLine("BYE.")

                return $false
            }
        }
        catch
        {
            return $false
        }
    }

    [string]RemoteAddress() {
        <#
            .SYNOPSIS
                Returns the remote address of peer.
        #>
        return $this.Client.Client.RemoteEndPoint.Address
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

        if ($this.Stream)
        {
            $this.Stream.Close()
        }

        if ($this.Client)
        {        
            $this.Client.Close()
        }
    }
}

<#
    Server Socket Handler Class
#>
class ServerIO {
    <#
        .SYNOPSIS
            Extended version of TcpListener.

            Supports SSL/TLS.
    #>

    [string] $ListenAddress
    [int] $ListenPort

    [System.Net.Sockets.TcpListener] $Server = $null    
    [System.IO.StreamWriter] $Writer = $null
    [System.IO.StreamReader] $Reader = $null
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate = $null

    ServerIO(
        <#
            .SYNOPSIS
                Class constructor.

            .PARAMETER ListenAddress
                Define in which interface to listen.

                127.0.0.1: Listen on localhost only.
                0.0.0.0: Listen on all interfaces. 

            .PARAMETER ListenPort
                Define which TCP port to listen for new connection.

            .PARAMETER Certificate
                X509 Certificate used for SSL/TLS encryption tunnel.
        #>

        [string] $ListenAddress = "0.0.0.0",
        [int] $ListenPort = 2801,
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate = $null
    ) {
        $this.ListenAddress = $ListenAddress
        $this.ListenPort = $ListenPort

        if (-not $Certificate)
        {
            Write-Verbose "No custom X509 Certificate specified."

            $this.Certificate = Get-X509CertificateFromStore        
            if (-not $this.Certificate)
            {
                Write-Verbose "Create new Certificate..."

                New-DefaultX509Certificate
                
                Write-verbose "Successfully generated and installed on local machine."

                $this.Certificate = Get-X509CertificateFromStore
                if (-not $this.Certificate)
                {
                    throw "Could not acquire default X509 Certificate."
                }
            }
            else
            {
                Write-Verbose "Default X509 Certificate Openned."            
            }
        }
        else
        {
            $this.Certificate = $Certificate
        }

        Write-Verbose "Using Certificate:"
        Write-Verbose $this.Certificate
        Write-Verbose "---"
    }

    [void]Listen() {
        <#
            .SYNOPSIS
                Start listening on defined interface:port.
        #>
        Write-Verbose "Start new server on ""$($this.ListenAddress):$($this.ListenPort)""..."

        $this.Server = New-Object System.Net.Sockets.TcpListener($this.ListenAddress, $this.ListenPort)        
        $this.Server.Start()

        Write-Verbose "Listening..."
    }

    [ClientIO]PullClient() {
        <#
            .SYNOPSIS
                Accept new client and associate this client with a new ClientIO Object.
        #>
        $client = $this.Server.AcceptTcpClient()  

        Write-Verbose "New client. Remote Address: ""$($client.Client.RemoteEndPoint.Address)""."    

        return [ClientIO]::New(            
            $client,
            $this.Certificate
        )
    }

    [void]Close() {
        <#
            .SYNOPSIS
                Stop waiting for new clients (Stop listening)
        #>
        if ($this.Server)
        {
            $this.Server.Stop()
        }
    }
}

$global:DesktopStreamScriptBlock = {
    <#
        .SYNOPSIS
            Threaded code block to send updates of local desktop to remote peer.

            This code is expected to be run inside a new PowerShell Runspace.

        .PARAMETER syncHash.Client
            A ClientIO Object containing an active connection. This is where, desktop updates will be
            sent over network.     
    #>

    function Get-ResolutionScaleFactor    
    {
        <#
            .SYNOPSIS
                Return the scale factor of target screen to capture.
        #>

        $hdc = [W.User32]::GetDC(0)
        try
        {
            return [W.GDI32]::GetDeviceCaps($hdc, 117) / [W.GDI32]::GetDeviceCaps($hdc, 10)
        }
        finally
        {
            [W.User32]::ReleaseDC(0, $hdc) | Out-Null
        }        
    }    

    function Get-DesktopImage {	
        <#
            .SYNOPSIS
                Return a snapshot of primary screen desktop.

            .DESCRIPTION
                Notice:
                    At this time, PowerRemoteDesktop only supports PrimaryScreen.
                    Even if multi-screen capture is a very easy feature to implement, It will probably be present
                    in final version 1.0

            .PARAMETER ScaleFactor
                Define target monitor scale factor to adjust bounds.
        #>
        param (
            [int] $ScaleFactor = 1
        )
        try 
        {	
            $primaryDesktop = [System.Windows.Forms.Screen]::PrimaryScreen

            $size = New-Object System.Drawing.Size(
                ($primaryDesktop.Bounds.Size.Width * $ScaleFactor),
                ($primaryDesktop.Bounds.Size.Height * $ScaleFactor)
            )

            $location = New-Object System.Drawing.Point(
                ($primaryDesktop.Bounds.Location.X * $ScaleFactor),
                ($primaryDesktop.Bounds.Location.Y * $ScaleFactor)
            )

            $bitmap = New-Object System.Drawing.Bitmap($size.Width, $size.Height)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                        
            $graphics.CopyFromScreen($location, [System.Drawing.Point]::Empty, $size)
            
            return $bitmap
        }        
        catch
        {
            if ($bitmap)
            {
                $bitmap.Dispose()
            }
        }
        finally
        {
            if ($graphics)
            {
                $graphics.Dispose()
            }
        }
    } 

    $imageQuality = 100

    try
    {
        [System.IO.MemoryStream] $oldImageStream = New-Object System.IO.MemoryStream

        $jpegEncoder = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' };

        $encoderParameters = New-Object System.Drawing.Imaging.EncoderParameters(1) 
        $encoderParameters.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, $imageQuality)

        $scaleFactor = Get-ResolutionScaleFactor

        while ($true)
        {           
            try
            {                                                   
                $desktopImage = Get-DesktopImage -ScaleFactor 1                                                                     

                $imageStream = New-Object System.IO.MemoryStream

                $desktopImage.Save($imageStream, $jpegEncoder, $encoderParameters)                             

                $sendUpdate = $true

                # Check both stream size.
                $sendUpdate = ($oldImageStream.Length -ne $imageStream.Length)                

                # If sizes are equal, compare both Fingerprint to confirm finding.
                if (-not $sendUpdate)
                {            
                    $imageStream.position = 0
                    $oldImageStream.position = 0  

                    $md5_1 = (Get-FileHash -InputStream $imageStream -Algorithm MD5).Hash   
                    $md5_2 = (Get-FileHash -InputStream $oldImageStream -Algorithm MD5).Hash                   

                    $sendUpdate = ($md5_1 -ne $md5_2)                 
                }

                if ($sendUpdate)
                {
                    # TODO: Get rid of "ToBase64String(...)". Improve a past attempt in RAW that was not sufficiently stable to be used
                    # in production.
                    $imageStream.position = 0 
                    try 
                    {
                        $syncHash.Client.Writer.WriteLine(
                            [System.Convert]::ToBase64String($imageStream.ToArray())
                        )  
                    }
                    catch
                    { break }

                    # Update Old Image Stream for Comparison
                    $imageStream.position = 0 

                    $oldImageStream.SetLength(0)

                    $imageStream.CopyTo($oldImageStream)
                }
                else {}              
            }    
            catch 
            { }
            finally
            {
                if ($desktopImage)
                {
                    $desktopImage.Dispose()
                }

                if ($imageStream)
                {
                    $imageStream.Close()
                }
            }
        }
    }
    finally
    {
        if ($oldImageStream)
        {
            $oldImageStream.Close()
        }
    }
}

$global:InputControlScriptBlock = {   
    <#
        .SYNOPSIS
            Threaded code block to receive remote orders (Ex: Keyboard Strokes, Mouse Clicks, Moves etc...)

            This code is expected to be run inside a new PowerShell Runspace.

        .PARAMETER syncHash.Client
            A ClientIO Object containing an active connection. This is where, remote events will be
            received and treated.            
    #>

    Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern void mouse_event(int flags, int dx, int dy, int cButtons, int info);[DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);' -Name U32 -Namespace W;

    enum MouseFlags {
        MOUSEEVENTF_ABSOLUTE = 0x8000
        MOUSEEVENTF_LEFTDOWN = 0x0002
        MOUSEEVENTF_LEFTUP = 0x0004
        MOUSEEVENTF_MIDDLEDOWN = 0x0020
        MOUSEEVENTF_MIDDLEUP = 0x0040
        MOUSEEVENTF_MOVE = 0x0001
        MOUSEEVENTF_RIGHTDOWN = 0x0008
        MOUSEEVENTF_RIGHTUP = 0x0010
        MOUSEEVENTF_WHEEL = 0x0800
        MOUSEEVENTF_XDOWN = 0x0080
        MOUSEEVENTF_XUP = 0x0100
        MOUSEEVENTF_HWHEEL = 0x01000
    }

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

    class KeyboardSim {
        <#
            .SYNOPSIS
                Class to simulate Keyboard Events using a WScript.Shell
                Instance.
        #>
        [System.__ComObject] $WShell = $null

        KeyboardSim () 
        <#
            .SYNOPSIS
                Class constructor
        #>
        {
            $this.WShell = New-Object -ComObject WScript.Shell        
        }

        [void] SendInput([string] $String) 
        {
            <#
                .SYNOPSIS
                    Simulate Keyboard Strokes. It can contain a single char or a complex string.

                .PARAMETER String
                    Char or String to be simulated as pressed.

                .EXAMPLE
                    .SendInput("Hello, World")
                    .SendInput("J")
            #>        

            # Simulate
            $this.WShell.SendKeys($String)
        }
    }
    

    $keyboardSim = [KeyboardSim]::New()

    while ($true)                    
    {       
        try 
        {            
            $jsonCommand = $syncHash.Client.Reader.ReadLine()                        
        }
        catch
        { 
            # ($_ | Out-File "c:\temp\debug.txt")
            
            break 
        }

        if (-not $jsonCommand)
        { break }

        $command = $jsonCommand | ConvertFrom-Json

        if (-not ($command.PSobject.Properties.name -match "Id"))
        { continue }                                             
         
        switch ([InputCommand] $command.Id)
        {
            # Keyboard Input Simulation
            "Keyboard"
            {                    
                if (-not ($command.PSobject.Properties.name -match "Keys"))
                { break }

                $keyboardSim.SendInput($command.Keys)                             
                break  
            }

            # Mouse Move & Click Simulation
            "MouseClickMove"
            {          
                if (-not ($command.PSobject.Properties.name -match "Type"))
                { break }

                switch ([MouseState] $command.Type)
                {
                    # Mouse Down/Up
                    {($_ -eq "Down") -or ($_ -eq "Up")}
                    {
                        [W.U32]::SetCursorPos($command.X, $command.Y)   

                        $down = ($_ -eq "Down")

                        $mouseCode = [int][MouseFlags]::MOUSEEVENTF_LEFTDOWN
                        if (-not $down)
                        {
                            $mouseCode = [int][MouseFlags]::MOUSEEVENTF_LEFTUP
                        }                                            

                        switch($command.Button)
                        {                        
                            "Right"
                            {
                                if ($down)
                                {
                                    $mouseCode = [int][MouseFlags]::MOUSEEVENTF_RIGHTDOWN
                                }
                                else
                                {
                                    $mouseCode = [int][MouseFlags]::MOUSEEVENTF_RIGHTUP
                                }

                                break
                            }      

                            "Middle"                      
                            {
                                if ($down)
                                {
                                    $mouseCode = [int][MouseFlags]::MOUSEEVENTF_MIDDLEDOWN
                                }
                                else
                                {
                                    $mouseCode = [int][MouseFlags]::MOUSEEVENTF_MIDDLEUP
                                }
                            }

                            # TODO Support Mouse Wheel
                        }                     
                        [W.U32]::mouse_event($mouseCode, 0, 0, 0, 0);

                        break
                    }

                    # Mouse Move
                    "Move"
                    {
                        [W.U32]::SetCursorPos($command.X, $command.Y)

                        break
                    }                    
                }                

                break                
            }        

            # Mouse Wheel Simulation
            "MouseWheel" {
                [W.U32]::mouse_event([int][MouseFlags]::MOUSEEVENTF_WHEEL, 0, 0, $command.Delta, 0);

                break
            }    
        }
    }    
}

function New-SessionId 
{
    <#
        .SYNOPSIS
            Generate a new Session Id.

        .DESCRIPTION
            Actually this Session Id is used to avoid possible race condition between first and second client.
    #>

    return (SHA512FromString -String (-join ((33..126) | Get-Random -Count 128 | %{[char] $_})))
}

function Get-SessionInformation
{
    <#
        .SYNOPSIS
            Generate an object containing few useful information about current machine.

        .DESCRIPTION
            Most important part is the target screen information. Without this information, remote viewer
            will not be able to correctly draw / adjust desktop image and simulate mouse events.

            This function is expected to be progressively updated with new required session information.

        .PARAMETER SessionId
            A String containing a random string tied to current remote desktop session.

    #>
    param (
        [Parameter(Mandatory=$True)]
        [string] $SessionId
    )

    $screenBounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds

    return New-Object PSCustomObject -Property @{
        SessionId = $SessionId

        MachineName = [Environment]::MachineName
        Username = [Environment]::UserName
        WindowsVersion = [Environment]::OSVersion.VersionString

        # BEGIN TODO: 
        # => Send as one object.
        ScreenWidth = $screenBounds.Width    
        ScreenHeight = $screenBounds.Height
        ScreenX = $screenBounds.X
        ScreenY = $screenBounds.Y
        # END TODO
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

        .PARAMETER Client
            A ClientIO object containing an active connection with a remote viewer.

        .PARAMETER ScriptBlock
            A PowerShell block of code to be evaluated on the new Runspace.

        .EXAMPLE
            New-RunSpace -Client $newClient -ScriptBlock { Start-Sleep -Seconds 10 }
    #>

    param(
        [Parameter(Mandatory=$True)]
        [ClientIO] $Client,

        [Parameter(Mandatory=$True)]
        [ScriptBlock] $ScriptBlock
    )   

    $syncHash = [HashTable]::Synchronized(@{})
    $syncHash.Client = $Client
    $syncHash.host = $host # For debugging purpose

    $runspace = [RunspaceFactory]::CreateRunspace()
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.ApartmentState = "STA"
    $runspace.Open()                   

    $runspace.SessionStateProxy.SetVariable("syncHash", $syncHash) 

    $powershell = [PowerShell]::Create().AddScript($ScriptBlock)

    $powershell.Runspace = $runspace

    $asyncResult = $powershell.BeginInvoke()

    return New-Object PSCustomObject -Property @{
        Runspace = $runspace
        PowerShell = $powershell
        AsyncResult = $asyncResult
    }
}

function Test-Administrator
{
    <#
        .SYNOPSIS
            Return true if current PowerShell is running with Administrator privilege, otherwise return false.
    #>
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    
    return $windowsPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )    
}

function Invoke-RemoteDesktopServer
{
    <#
        .SYNOPSIS
            Start a new Remote Desktop Server.

        .DESCRIPTION
            Notice: Certificate options are evaluated in this order.
                1) CertificateFile.
                2) EncodedCertificate.

        .PARAMETER ListenAddress
            Define in which interface to listen for new viewer.

        .PARAMETER ListenPort
            Define in which port to listen for new viewer.

        .PARAMETER Password
            Define password used during authentication process. 
            (!) Absolutely use a complex password.

            If no password is specified, then a random complex password will be generated
            and printed on terminal.

        .PARAMETER CertificateFile
            A valid X509 Certificate (With Private Key) File. If set, this parameter is prioritize.

        .PARAMETER EncodedCertificate
            A valid X509 Certificate (With Private Key) encoded as a Base64 String.
    #>

    param (
        [string] $ListenAddress = "0.0.0.0", 
        [int] $ListenPort = 2801,
        [string] $Password = "",

        [string] $CertificateFile = "", # 1
        # Or
        [string] $EncodedCertificate = "" # 2
    )

    [System.Collections.Generic.List[PSCustomObject]]$runspaces = @()

    $oldErrorActionPreference = $ErrorActionPreference
    $oldVerbosePreference = $VerbosePreference    
    try
    {
        $ErrorActionPreference = "stop"
        $VerbosePreference = "continue"

        Write-Banner    

        if (-not (Test-Administrator) -and -not $CertificateFile -and -not $EncodedCertificate)
        {
            throw "When no custom X509 Certificate specified, you must run current PowerShell instance as Administrator."
        }

        if ($CertificateFile)
        {
            if (-not (Test-Path -Path $CertificateFile))
            {
                throw "Could load find Certificate File at location: ""${CertificateFile}""."
            }
        }

        if (-not $Password)
        {
            $Password = (-join ((48..57) + (64..90) + (97..122) | Get-Random -Count 18 | %{[char] $_}))
            
            Write-Verbose "No password were set, generating a new random and complex password..."

            Write-Host -NoNewLine "Random password to connect to server: """
            Write-Host -NoNewLine ${Password} -ForegroundColor green
            Write-Host """."
        }        

        $Certificate = $null

        if ($CertificateFile -or $EncodedCertificate)
        {
            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            if ($CertificateFile)
            {
                $Certificate.Import($CertificateFile)
            }
            else
            {
                $Certificate.Import([Convert]::FromBase64String($EncodedCertificate))
            }
        }

        # Create new server and listen
        $server = [ServerIO]::New($ListenAddress, $ListenPort, $Certificate)        
        $server.Listen()        

        while ($true)
        {            
            try
            {                              
                Write-Verbose "Waiting for new clients..."

                $clientDesktop = $server.PullClient();                                   
                if (-not $clientDesktop.Authentify($Password)) 
                {
                    continue
                }

                $Session = New-Object PSCustomObject -Property @{
                    Id = (New-SessionId)   
                    Addr = $clientDesktop.RemoteAddress()
                }
                
                Write-Verbose "New session generated:"
                Write-Verbose $Session
                Write-Verbose "---"

                Write-Verbose "Submit Session Information..."                

                $clientDesktop.Writer.WriteLine((Get-SessionInformation -SessionId $Session.Id | ConvertTo-Json -Compress))                
                
                $clientControl = $server.PullClient();                                 

                if (-not $clientControl.Hello($Session.Id, $Session.Addr))
                {
                    continue
                }

                if (-not $clientControl.Authentify($Password)) 
                {
                    continue
                }                

                $newRunspace = (New-RunSpace -Client $clientDesktop -ScriptBlock $global:DesktopStreamScriptBlock)                
                $runspaces.Add($newRunspace)

                $newRunspace = (New-RunSpace -Client $clientControl -ScriptBlock $global:InputControlScriptBlock)                
                $runspaces.Add($newRunspace)  

                while ($true)
                {
                    $completed = $true                    
                    
                    foreach ($runspace in $runspaces)
                    {
                        if (-not $runspace.AsyncResult.IsCompleted)
                        {
                            $completed = $false

                            break
                        }
                    }

                    if ($completed)
                    { break }

                    Start-Sleep -Seconds 2
                }                                           
            } 
            catch {
                Write-Verbose $_
            }
            finally
            {
                Write-Verbose "Release clients..."

                if ($clientControl) 
                {
                    $clientControl.Close()
                }

                if ($clientDesktop)
                {
                    $clientDesktop.Close()
                }

                Write-Verbose "Dispose runspaces..."

                foreach ($runspace in $runspaces)
                {
                    $runspace.PowerShell.EndInvoke($runspace.AsyncResult) | Out-Null                    
                    $runspace.PowerShell.Runspace.Dispose()                                      
                    $runspace.PowerShell.Dispose()                    
                }    
                $runspaces.Clear()            
            }
        }
    }
    finally
    {
        Write-Verbose "Close server..."

        if ($server)
        {
            $server.Close()
        }

        Write-Verbose "Dispose runspaces..."        

        $ErrorActionPreference = $oldErrorActionPreference
        $VerbosePreference = $oldVerbosePreference
    }
}

try {  
    Export-ModuleMember -Function Invoke-RemoteDesktopServer
} catch {}