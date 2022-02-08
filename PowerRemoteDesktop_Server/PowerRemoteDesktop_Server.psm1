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
Add-Type -Assembly System.Drawing

Add-Type @"
    using System;    
    using System.Runtime.InteropServices;

    public static class User32 
    {
        [DllImport("User32.dll")] 
        public static extern bool SetProcessDPIAware();    

        [DllImport("User32.dll")] 
        public static extern int LoadCursorA(int hInstance, int lpCursorName);

        [DllImport("User32.dll")] 
        public static extern bool GetCursorInfo(IntPtr pci);

        [DllImport("user32.dll")] 
        public static extern void mouse_event(int flags, int dx, int dy, int cButtons, int info);
        
        [DllImport("user32.dll")] 
        public static extern bool SetCursorPos(int X, int Y);
    }    

    public static class Kernel32
    {
        [DllImport("Kernel32.dll")] 
        public static extern uint SetThreadExecutionState(uint esFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void CopyMemory(
            IntPtr dest,
            IntPtr src,
            uint count
        );        
    }

    public static class MSVCRT
    {
        [DllImport("msvcrt.dll", CallingConvention=CallingConvention.Cdecl)]
        public static extern int memcmp(IntPtr p1, IntPtr p2, UInt64 count);
    }
"@

$global:PowerRemoteDesktopVersion = "3.0.0"

$global:HostSyncHash = [HashTable]::Synchronized(@{
    host = $host
    ClipboardText = (Get-Clipboard -Raw)    
})

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
}

enum WorkerKind {
    Desktop = 1
    Events = 2
}

enum LogKind {
    Information
    Warning
    Success
    Error
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

function Write-Log
{
    <#
        .SYNOPSIS
            Output a log message to terminal with associated "icon".

        .PARAMETER Message
            Type: String
            Default: None

            Description: The message to write to terminal.

        .PARAMETER LogKind
            Type: LogKind Enum
            Default: Information

            Description: Define the logger "icon" kind.
    #>
    param(
        [Parameter(Mandatory=$True)]
        [string] $Message,

        [LogKind] $LogKind = [LogKind]::Information
    )

    switch ($LogKind)
    {    
        ([LogKind]::Warning)
        {
            $icon = "!!"
            $color = [System.ConsoleColor]::Yellow

            break
        }

        ([LogKind]::Success)
        {
            $icon = "OK"
            $color = [System.ConsoleColor]::Green

            break
        }

        ([LogKind]::Error)
        {
            $icon = "KO"
            $color = [System.ConsoleColor]::Red

            break
        }

        default
        {
            $color = [System.ConsoleColor]::Cyan
            $icon = "i"
        }
    }

    Write-Host "[ " -NoNewLine    
    Write-Host $icon -ForegroundColor $color -NoNewLine        
    Write-Host " ] $Message"
}

function Write-OperationSuccessState
{
    param(
        [Parameter(Mandatory=$True)]
        $Result,
        
        [Parameter(Mandatory=$True)]
        $Message
    )

    if ($Result)
    {
        $kind = [LogKind]::Success
    }
    else
    {
        $kind = [LogKind]::Error
    }

    Write-Log -Message $Message -LogKind $kind
}

function Invoke-PreventSleepMode
{
    <#
        .SYNOPSIS
            Prevent computer to enter sleep mode while server is running.

        .DESCRIPTION
            Function returns thread execution state old flags value. You can use this old flags
            to restore thread execution to its original state.
    #>

    $ES_AWAYMODE_REQUIRED = [uint32]"0x00000040"
    $ES_CONTINUOUS = [uint32]"0x80000000"
    $ES_DISPLAY_REQUIRED = [uint32]"0x00000002"
    $ES_SYSTEM_REQUIRED = [uint32]"0x00000001"
    $ES_USER_PRESENT = [uint32]"0x00000004"

    return [Kernel32]::SetThreadExecutionState(
        $ES_CONTINUOUS -bor
        $ES_SYSTEM_REQUIRED -bor
        $ES_AWAYMODE_REQUIRED
    )
}

function Update-ThreadExecutionState
{
    <#
        .SYNOPSIS
            Update current thread execution state flags.

        .PARAMETER Flags
            Execution state flags.
    #>
    param(
        [Parameter(Mandatory=$True)]
        $Flags    
    )

    return [Kernel32]::SetThreadExecutionState($Flags) -ne 0
}

function Get-PlainTextPassword
{
    <#
        .SYNOPSIS
            Retrieve the plain-text version of a secure string.

        .PARAMETER SecurePassword
            The SecureString object to be reversed.

    #>
    param(
        [Parameter(Mandatory=$True)]
        [SecureString] $SecurePassword
    )

    $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    try
    {        
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
    }
    finally
    {
        [Runtime.InteropServices.Marshal]::FreeBSTR($BSTR)
    }
}

function Test-PasswordComplexity
{
    <#
        .SYNOPSIS
            Check if password is sufficiently complex.

        .DESCRIPTION
            To return True, Password must follow bellow complexity rules:
                * Minimum 12 Characters.
                * One of following symbols: "!@#%^&*_".
                * At least of lower case character.
                * At least of upper case character. 

        .PARAMETER SecurePasswordCandidate
            The password object to test
    #>
    param (
        [Parameter(Mandatory=$True)]
        [SecureString] $SecurePasswordCandidate
    )

    $complexityRules = "(?=^.{12,}$)(?=.*[!@#%^&*_]+)(?=.*[a-z])(?=.*[A-Z]).*$"

    return (Get-PlainTextPassword -SecurePassword $SecurePasswordCandidate) -match $complexityRules
}

function New-RandomPassword
{    
    <#
        .SYNOPSIS
            Generate a new secure password.

        .DESCRIPTION
            Generate new password candidates until one candidate match complexity rules.
            Generally only one iteration is enough but in some rare case it could be one or two more.            
    #>
    do
    {
        $authorizedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*_"

        $candidate = -join ((1..18) | ForEach-Object { Get-Random -Input $authorizedChars.ToCharArray() })

        $secureCandidate = ConvertTo-SecureString -String $candidate -AsPlainText -Force        
    } until (Test-PasswordComplexity -SecurePasswordCandidate $secureCandidate)

    $candidate = $null

    return $secureCandidate
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

function Get-ScreenList()
{
    <#
        .SYNOPSIS
            Return an array of screen objects.

        .DESCRIPTION
            A screen refer to physical or virtual screen (monitor).                

    #>
    $result = @()

    $screens = ([System.Windows.Forms.Screen]::AllScreens | Sort-Object -Property Primary -Descending)

    $i = 0
    foreach ($screen in $screens)
    {
        $i++

        $result += New-Object -TypeName PSCustomObject -Property @{
            Id = $i
            Name = $screen.DeviceName
            Primary = $screen.Primary
            Width = $screen.Bounds.Width
            Height = $screen.Bounds.Height
            X = $screen.Bounds.X 
            Y = $screen.Bounds.Y
        }
    }

    return $result
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
       [SecureString] $SecurePassword, 

       [Parameter(Mandatory=$True)]
       [string] $Candidate
    )

    $solution = -join($Candidate, ":", (Get-PlainTextPassword -SecurePassword $SecurePassword))

    for ([int] $i = 0; $i -le 1000; $i++)
    {
        $solution = Get-SHA512FromString -String $solution
    }

    return $solution
}

$global:DesktopStreamScriptBlock = { 
    $BlockSize = [int]$Param.SafeHash.ViewerConfiguration.BlockSize
    $HighQualityResize = $Param.SafeHash.ViewerConfiguration.HighQualityResize
    $packetSize = [int]$Param.SafeHash.ViewerConfiguration.PacketSize  

    $WidthConstrainsts = 0
    $HeightConstrainsts = 0
    
    $ResizeDesktop = $Param.SafeHash.ViewerConfiguration.ResizeDesktop()
    if ($ResizeDesktop)
    {
        $WidthConstrainsts = $Param.SafeHash.ViewerConfiguration.ExpectDesktopWidth
        $HeightConstrainsts = $Param.SafeHash.ViewerConfiguration.ExpectDesktopHeight
    }

    $bitmapPixelFormat = [System.Drawing.Imaging.PixelFormat]::Format24bppRgb    

    $screen = [System.Windows.Forms.Screen]::AllScreens | Where-Object -FilterScript { 
        $_.DeviceName -eq $Param.SafeHash.ViewerConfiguration.ScreenName 
    }
    if (-not $screen)
    {
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen
    }

    $virtualScreenBounds = [System.Drawing.Rectangle]::New(
        0,
        0,
        $screen.Bounds.Width,
        $screen.Bounds.Height
    )

    if ($ResizeDesktop)
    {
        $virtualScreenBounds.Width = $WidthConstrainsts
        $virtualScreenBounds.Height = $HeightConstrainsts
    }    

    $SpaceGrid = $null
    $horzBlockCount = [math]::ceiling($virtualScreenBounds.Width / $BlockSize)
    $vertBlockCount = [math]::ceiling($virtualScreenBounds.Height / $BlockSize)         

    $encoderParameters = New-Object System.Drawing.Imaging.EncoderParameters(1) 
    $encoderParameters.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter(
        [System.Drawing.Imaging.Encoder]::Quality,
        $Param.SafeHash.ViewerConfiguration.ImageCompressionQuality
    )

    $encoder = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' };

    $SpaceGrid = New-Object IntPtr[][] $vertBlockCount, $horzBlockCount    

    $firstIteration = $true

    $bmpBlock = New-Object System.Drawing.Bitmap(
        $BlockSize,
        $BlockSize,
        $bitmapPixelFormat
    ) 

    $desktopImage = New-Object System.Drawing.Bitmap(
        $virtualScreenBounds.Width,
        $virtualScreenBounds.Height,
        $bitmapPixelFormat
    )   

    if ($ResizeDesktop)
    {
        $fullSizeDesktop = New-Object System.Drawing.Bitmap(
            $screen.Bounds.Width,
            $screen.Bounds.Height,
            $bitmapPixelFormat
        )                   

        $fullSizeDesktopGraphics = [System.Drawing.Graphics]::FromImage($fullSizeDesktop)

        if ($HighQualityResize -and $ResizeDesktop)
        {
            $fullSizeDesktopGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $fullSizeDesktopGraphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $fullSizeDesktopGraphics.InterpolationMode =  [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $fullSizeDesktopGraphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality     
        }
    }    

    # SizeOf(DWORD) * 3 (SizeOf(Desktop) + SizeOf(Left) + SizeOf(Top))
    $struct = New-Object -TypeName byte[] -ArgumentList (([Runtime.InteropServices.Marshal]::SizeOf([System.Type][UInt32])) * 3)

    $graphics = [System.Drawing.Graphics]::FromImage($desktopImage)
    try
    {        
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()                

        while ($true)
        {      
            # Using a stopwatch instead of replacing main loop "while ($true)" by "while($this.SafeHash.SessionActive)"
            # sounds strange but this is done to avoid locking our SafeHash to regularly and loosing some
            # performance. If you think this is useless, just use while($this.SafeHash.SessionActive) in main
            # loop instead of while($true).
            if ($stopWatch.ElapsedMilliseconds -ge 2000)
            {
                if (-not $Param.SafeHash.SessionActive)
                {
                    $stopWatch.Stop()                   

                    break
                }

                $stopWatch.Restart()
            }

            # ///

            if ($firstIteration)
            {
                $updatedRect = $virtualScreenBounds              
            }
            else
            {
                $updatedRect = New-Object -TypeName System.Drawing.Rectangle -ArgumentList 0, 0, 0, 0
            }

            if ($ResizeDesktop)
            {                                
                $fullSizeDesktopGraphics.CopyFromScreen(
                    $screen.Bounds.Location,
                    [System.Drawing.Point]::Empty,
                    [System.Drawing.Size]::New(
                        $fullSizeDesktop.Width,
                        $fullSizeDesktop.Height
                    )
                )

                $graphics.DrawImage(
                    $fullSizeDesktop,
                    0,
                    0,
                    $virtualScreenBounds.Width,
                    $virtualScreenBounds.Height
                )
            }
            else
            {
                $graphics.CopyFromScreen(
                    [System.Drawing.Point]::Empty,
                    [System.Drawing.Point]::Empty,
                    [System.Drawing.Size]::New(
                        $virtualScreenBounds.Width,
                        $virtualScreenBounds.Height
                    )
                )
            }            

            for ($y = 0; $y -lt $vertBlockCount; $y++)    
            {                             
                for ($x = 0; $x -lt $horzBlockCount; $x++)
                {                       
                    $rect = New-Object -TypeName System.Drawing.Rectangle

                    $rect.X = ($x * $BlockSize)
                    $rect.Y = ($y * $BlockSize)
                    $rect.Width = $BlockSize
                    $rect.Height = $BlockSize

                    $rect = [System.Drawing.Rectangle]::Intersect($rect, $virtualScreenBounds)   
                        
                    $bmpBlock = $desktopImage.Clone($rect, $bitmapPixelFormat)

                    $bmpBlockData = $bmpBlock.LockBits(
                        [System.Drawing.Rectangle]::New(0, 0, $bmpBlock.Width, $bmpBlock.Height), 
                        [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
                        $bitmapPixelFormat
                    )
                    try
                    {
                        $blockMemSize = ($bmpBlockData.Stride * $bmpBlock.Height)
                        if ($firstIteration)
                        {
                            # Big bang occurs, tangent univers is getting created, where is Donnie?
                            $SpaceGrid[$y][$x] = [Runtime.InteropServices.Marshal]::AllocHGlobal($blockMemSize)
                                                                                                    
                            [Kernel32]::CopyMemory($SpaceGrid[$y][$x], $bmpBlockData.Scan0, $blockMemSize)                        
                        }
                        else
                        {                        
                            if ([MSVCRT]::memcmp($bmpBlockData.Scan0, $SpaceGrid[$y][$x], $blockMemSize) -ne 0)
                            {
                                [Kernel32]::CopyMemory($SpaceGrid[$y][$x], $bmpBlockData.Scan0, $blockMemSize) 

                                if ($updatedRect.IsEmpty)
                                {
                                    $updatedRect.X = $x * $BlockSize
                                    $updatedRect.Width = $BlockSize

                                    $updatedRect.Y = $y * $BlockSize
                                    $updatedRect.Height = $BlockSize                                    
                                }
                                else
                                {    
                                    if ($x * $BlockSize -lt $updatedRect.X)
                                    {
                                        $updatedRect.X = $x * $BlockSize
                                    }

                                    if (($x+1) * $BlockSize -gt $updatedRect.Right)
                                    {
                                        $updatedRect.Width = (($x + 1) * $BlockSize) - $updatedRect.X
                                    }

                                    if ($y * $BlockSize -lt $updatedRect.Y)
                                    {
                                        $updatedRect.Y = $y * $BlockSize
                                    }

                                    if (($y+1) * $BlockSize -gt $updatedRect.Bottom)
                                    {
                                        $updatedRect.Height = (($y + 1) * $BlockSize) - $updatedRect.Y
                                    }
                                }
                            }                        
                        }
                    }
                    finally
                    {
                        if ($bmpBlockData)
                        {
                            $bmpBlock.UnlockBits($bmpBlockData)
                        }
                    }                               
                }                            
            }          

            if (-not $updatedRect.IsEmpty -and $desktopImage)
            {                           
                try
                {
                    $updatedRect = [System.Drawing.Rectangle]::Intersect($updatedRect, $virtualScreenBounds)

                    $updatedDesktop = $desktopImage.Clone(
                        $updatedRect,
                        $bitmapPixelFormat
                    )    
                
                    $desktopStream = New-Object System.IO.MemoryStream

                    $updatedDesktop.Save($desktopStream, $encoder, $encoderParameters)                        

                    $desktopStream.Position = 0
                    try 
                    {         
                        # One call please  
                        [System.Runtime.InteropServices.Marshal]::WriteInt32($struct, 0x0, $desktopStream.Length)
                        [System.Runtime.InteropServices.Marshal]::WriteInt32($struct, 0x4, $updatedRect.Left)
                        [System.Runtime.InteropServices.Marshal]::WriteInt32($struct, 0x8, $updatedRect.Top)

                        $Param.Client.SSLStream.Write($struct , 0, $struct.Length)   
              
                        $binaryReader = New-Object System.IO.BinaryReader($desktopStream)
                        do
                        {       
                            $bufferSize = ($desktopStream.Length - $desktopStream.Position)
                            if ($bufferSize -gt $packetSize)
                            {
                                $bufferSize = $packetSize
                            }                                                                      

                            $Param.Client.SSLStream.Write($binaryReader.ReadBytes($bufferSize), 0, $bufferSize)                              
                        } until ($desktopStream.Position -eq $desktopStream.Length)
                    }
                    catch
                    { 
                        break 
                    }
                }
                finally
                {
                    if ($desktopStream)
                    {
                        $desktopStream.Dispose()
                    }

                    if ($updatedDesktop)
                    {
                        $updatedDesktop.Dispose()
                    }
                }
            }

            if ($firstIteration)
            {
                $firstIteration = $false
            }
        }
    }
    finally
    {        
        if ($graphics)
        {
            $graphics.Dispose()
        }

        if ($desktopImage)
        {
            $desktopImage.Dispose()
        }

        if ($fullSizeDesktopGraphics)
        {
            $fullSizeDesktopGraphics.Dispose()
        }

        if ($fullSizeDesktop)
        {
            $fullSizeDesktop.Dispose()
        }        

        if ($bmpBlock)
        {
            $bmpBlock.Dispose()
        }

        # Tangent univers big crunch
        for ($y = 0; $y -lt $vertBlockCount; $y++)    
        {                             
            for ($x = 0; $x -lt $horzBlockCount; $x++)
            {                          
                [Runtime.InteropServices.Marshal]::FreeHGlobal($SpaceGrid[$y][$x])           
            }
        }
    }  
}

$global:IngressEventScriptBlock = {       
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

    enum InputEvent {
        Keyboard = 0x1
        MouseClickMove = 0x2
        MouseWheel = 0x3
        KeepAlive = 0x4        
        ClipboardUpdated = 0x5
    }

    enum MouseState {
        Up = 0x1
        Down = 0x2
        Move = 0x3
    }

    enum ClipboardMode {
        Disabled = 1
        Receive = 2
        Send = 3
        Both = 4
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

    while ($Param.SafeHash.SessionActive)                    
    {             
        try 
        {            
            $jsonEvent = $Param.Reader.ReadLine()
        }
        catch
        { 
            # ($_ | Out-File "c:\temp\debug.txt")
            
            break 
        }     
        
        try
        {
            $aEvent = $jsonEvent | ConvertFrom-Json
        }
        catch { continue }

        if (-not ($aEvent.PSobject.Properties.name -match "Id"))
        { continue }                                             
         
        switch ([InputEvent] $aEvent.Id)
        {
            # Keyboard Input Simulation
            ([InputEvent]::Keyboard)
            {      
                if ($Param.ViewOnly)              
                { continue }

                if (-not ($aEvent.PSobject.Properties.name -match "Keys"))
                { break }

                $keyboardSim.SendInput($aEvent.Keys)                             
                break  
            }

            # Mouse Move & Click Simulation
            ([InputEvent]::MouseClickMove)
            {          
                if ($Param.ViewOnly)              
                { continue }

                if (-not ($aEvent.PSobject.Properties.name -match "Type"))
                { break }

                switch ([MouseState] $aEvent.Type)
                {
                    # Mouse Down/Up
                    {($_ -eq ([MouseState]::Down)) -or ($_ -eq ([MouseState]::Up))}
                    {
                        [User32]::SetCursorPos($aEvent.X, $aEvent.Y)   

                        $down = ($_ -eq ([MouseState]::Down))

                        $mouseCode = [int][MouseFlags]::MOUSEEVENTF_LEFTDOWN
                        if (-not $down)
                        {
                            $mouseCode = [int][MouseFlags]::MOUSEEVENTF_LEFTUP
                        }                                            

                        switch($aEvent.Button)
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
                        }                     
                        [User32]::mouse_event($mouseCode, 0, 0, 0, 0);

                        break
                    }

                    # Mouse Move
                    ([MouseState]::Move)
                    {
                        if ($Param.ViewOnly)              
                        { continue }

                        [User32]::SetCursorPos($aEvent.X, $aEvent.Y)

                        break
                    }                    
                }                

                break                
            }        

            # Mouse Wheel Simulation
            ([InputEvent]::MouseWheel) {
                if ($Param.ViewOnly)              
                { continue }

                [User32]::mouse_event([int][MouseFlags]::MOUSEEVENTF_WHEEL, 0, 0, $aEvent.Delta, 0);

                break
            }    

            # Clipboard Update
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

    enum CursorType {
        IDC_APPSTARTING = 32650
        IDC_ARROW = 32512
        IDC_CROSS = 32515
        IDC_HAND = 32649
        IDC_HELP = 32651
        IDC_IBEAM = 32513
        IDC_ICON = 32641
        IDC_NO = 32648
        IDC_SIZE = 32640
        IDC_SIZEALL = 32646
        IDC_SIZENESW = 32643
        IDC_SIZENS = 32645
        IDC_SIZENWSE = 32642
        IDC_SIZEWE = 32644
        IDC_UPARROW = 32516
        IDC_WAIT = 32514
    }

    enum OutputEvent {
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

    function Initialize-Cursors
    {
        <#
            .SYNOPSIS
                Initialize different Windows supported mouse cursors.

            .DESCRIPTION
                Unfortunately, there is not WinAPI to get current mouse cursor icon state (Ex: as a flag) 
                but only current mouse cursor icon (via its handle).

                One solution, is to resolve each supported mouse cursor handles (HCURSOR) with corresponding name 
                in a hashtable and then compare with GetCursorInfo() HCURSOR result.
        #>
        $cursors = @{}

        foreach ($cursorType in [CursorType].GetEnumValues()) { 
            $result = [User32]::LoadCursorA(0, [int]$cursorType)

            if ($result -gt 0)
            {
                $cursors[[string] $cursorType] = $result
            }
        }

        return $cursors
    }        

    function Get-GlobalMouseCursorIconHandle
    {
        <#
            .SYNOPSIS
                Return global mouse cursor handle.
            .DESCRIPTION
                For this project I really want to avoid using "inline c#" but only pure PowerShell Code.
                I'm using a Hackish method to retrieve the global Windows cursor info by playing by hand
                with memory to prepare and read CURSORINFO structure.
                ---
                typedef struct tagCURSORINFO {
                    DWORD   cbSize;       // Size: 0x4
                    DWORD   flags;        // Size: 0x4
                    HCURSOR hCursor;      // Size: 0x4 (32bit) , 0x8 (64bit)
                    POINT   ptScreenPos;  // Size: 0x8
                } CURSORINFO, *PCURSORINFO, *LPCURSORINFO;
                Total Size of Structure:
                    - [32bit] 20 Bytes
                    - [64bit] 24 Bytes
        #>

        # sizeof(cbSize) + sizeof(flags) + sizeof(ptScreenPos) = 16
        $structSize = [IntPtr]::Size + 16

        $cursorInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($structSize)
        try
        {
            # ZeroMemory(@cursorInfo, SizeOf(tagCURSORINFO))
            for ($i = 0; $i -lt $structSize; $i++)
            {
                [System.Runtime.InteropServices.Marshal]::WriteByte($cursorInfo, $i, 0x0)    
            }

            [System.Runtime.InteropServices.Marshal]::WriteInt32($cursorInfo, 0x0, $structSize)

            if ([User32]::GetCursorInfo($cursorInfo))
            {
                $hCursor = [System.Runtime.InteropServices.Marshal]::ReadInt64($cursorInfo, 0x8)

                return $hCursor
            }    

            <#for ($i = 0; $i -lt $structSize; $i++)
            {
                $offsetValue = [System.Runtime.InteropServices.Marshal]::ReadByte($cursorInfo, $i)
                Write-Host "Offset: ${i} -> " -NoNewLine
                Write-Host $offsetValue -ForegroundColor Green -NoNewLine
                Write-Host ' (' -NoNewLine
                Write-Host ('0x{0:x}' -f $offsetValue) -ForegroundColor Cyan -NoNewLine
                Write-Host ')'
            }#>
        }
        finally
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cursorInfo)
        }
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

            $Param.Writer.WriteLine(($Data | ConvertTo-Json -Compress))  

            return $true
        }
        catch 
        { 
            return $false
        }
    }

    $cursors = Initialize-Cursors

    $oldCursor = 0

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($Param.SafeHash.SessionActive)
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

        # Monitor for global mouse cursor change
        # Update Frequently (Maximum probe time to be efficient: 30ms)
        $currentCursor = Get-GlobalMouseCursorIconHandle
        if ($currentCursor -ne 0 -and $currentCursor -ne $oldCursor)
        {   
            $cursorTypeName = ($cursors.GetEnumerator() | Where-Object { $_.Value -eq $currentCursor }).Key

            $data = New-Object -TypeName PSCustomObject -Property @{                
                Cursor = $cursorTypeName
            }             

            if (-not (Send-Event -AEvent ([OutputEvent]::MouseCursorUpdated) -Data $data))
            { break }

            $oldCursor = $currentCursor
        }    

        Start-Sleep -Milliseconds 30 
    } 

    $stopWatch.Stop()
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


class ClientIO {  
    [System.Net.Sockets.TcpClient] $Client = $null
    [System.IO.StreamWriter] $Writer = $null
    [System.IO.StreamReader] $Reader = $null
    [System.Net.Security.SslStream] $SSLStream = $null  


    ClientIO(
        [System.Net.Sockets.TcpClient] $Client,
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [bool] $UseTLSv1_3
    ) {
        if ((-not $Client) -or (-not $Certificate))
        {
            throw "ClientIO Class requires both a valid TcpClient and X509Certificate2."
        }
        
        $this.Client = $Client

        Write-Verbose "Create new SSL Stream..."

        $this.SSLStream = New-Object System.Net.Security.SslStream($this.Client.GetStream(), $false)                

        if ($UseTLSv1_3)
        {
            $TLSVersion = [System.Security.Authentication.SslProtocols]::TLS13
        }
        else {
            $TLSVersion = [System.Security.Authentication.SslProtocols]::TLS12
        }

        Write-Verbose "Authenticate as server using ${TLSVersion}..."

        $this.SSLStream.AuthenticateAsServer(
            $Certificate,
            $false,
            $TLSVersion,
            $false
        )        

        if (-not $this.SSLStream.IsEncrypted)
        {
            throw "Could not established an encrypted tunnel with remote peer."
        }

        $this.SSLStream.WriteTimeout = 5000
        $this.SSLStream.ReadTimeout = [System.Threading.Timeout]::Infinite # Default

        Write-Verbose "Open communication channels..."

        $this.Writer = New-Object System.IO.StreamWriter($this.SSLStream)
        $this.Writer.AutoFlush = $true        

        $this.Reader = New-Object System.IO.StreamReader($this.SSLStream)      

        Write-Verbose "Connection ready for use."  
    }

    [bool] Authentify([SecureString] $SecurePassword) {
        <#
            .SYNOPSIS
                Handle authentication process with remote peer.

            .PARAMETER Password
                Password used to validate challenge and grant access for a new Client.

            .EXAMPLE
                .Authentify("s3cr3t!")
        #>        
        try
        { 
            if (-not $SecurePassword) { 
                throw "During client authentication, a password cannot be blank."
            }

            Write-Verbose "New authentication challenge..."

            $candidate = -join ((1..128) | ForEach-Object {Get-Random -input ([char[]](33..126))})
            $candidate = Get-SHA512FromString -String $candidate

            $challengeSolution = Resolve-AuthenticationChallenge -Candidate $candidate -SecurePassword $SecurePassword   

            Write-Verbose "@Challenge:"
            Write-Verbose "Candidate: ""${candidate}"""
            Write-Verbose "Solution: ""${challengeSolution}"""  
            Write-Verbose "---"

            $this.Writer.WriteLine($candidate)

            Write-Verbose "Candidate sent to client, waiting for answer..."

            $challengeReply = $this.ReadLine(5 * 1000)

            Write-Verbose "Replied solution: ""${challengeReply}"""

            # Challenge solution is a Sha512 Hash so comparison doesn't need to be sensitive (-ceq or -cne)
            if ($challengeReply -ne $challengeSolution)
            {            
                $this.Writer.WriteLine(([ProtocolCommand]::Fail))

                throw "Client challenge solution does not match our solution."
            }
            else
            {            
                $this.Writer.WriteLine(([ProtocolCommand]::Success))

                Write-Verbose "Password Authentication Success"

                return 280121 # True
            }
        }
        catch 
        {
            throw "Password Authentication Failed. Reason: `r`n $($_)"
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
                Define the maximum time (in milliseconds) to wait for remote peer message.
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
                A PowerShell Object to be serialized as JSON String.
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
                Define the maximum time (in milliseconds) to wait for remote peer message.
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

    [void] Close() {    
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

class TcpListenerEx : System.Net.Sockets.TcpListener
{
    TcpListenerEx([string] $ListenAddress, [int] $ListenPort) : base($ListenAddress, $ListenPort)
    { }

    [bool] Active()
    {
        return $this.Active     
    }
}

class ServerIO {        
    [TcpListenerEx] $Server = $null    
    [System.IO.StreamWriter] $Writer = $null
    [System.IO.StreamReader] $Reader = $null    

    ServerIO() 
    { }

    [void] Listen(
        [string] $ListenAddress,
        [int] $ListenPort
    ) 
    {                         
        if ($this.Server)
        {
            $this.Close()            
        }        

        $this.Server = New-Object TcpListenerEx(
            $ListenAddress,
            $ListenPort
        )            
                
        $this.Server.Start()

        Write-Verbose "Listening on ""$($ListenAddress):$($ListenPort)""..."                    
    }

    [ClientIO] PullClient(
        [SecureString] $SecurePassword,

        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [bool] $UseTLSv13,
        [int] $Timeout
    ) {
        <#
            .SYNOPSIS
                Accept new client and associate this client with a new ClientIO Object.

            .PARAMETER Timeout
                By default AcceptTcpClient() will block current thread until a client connects.
                
                Using Timeout and a cool technique, you can stop waiting for client after a certain amount
                of time (In Milliseconds)                

                If Timeout is greater than 0 (Milliseconds) then connection timeout is enabled.

                Other method: AsyncWaitHandle.WaitOne([timespan])'h:m:s') -eq $true|$false with BeginAcceptTcpClient(...)
        #>
            
        if (-not (Test-PasswordComplexity -SecurePasswordCandidate $SecurePassword))
        {
            throw "Client socket pull request requires a complex password to be set."
        }

        if ($Timeout -gt 0)
        {
            $socketReadList = [System.Collections.ArrayList]@($this.Server.Server)

            [System.Net.Sockets.Socket]::Select($socketReadList, $null, $null, $Timeout * 1000)

            if (-not $socketReadList.Contains($this.Server.Server))
            {
                throw "Pull timeout."
            }
        }

        $socket = $this.Server.AcceptTcpClient()          

        $client = [ClientIO]::New(            
            $socket,
            $Certificate,
            $UseTLSv13
        )
        try
        {            
            Write-Verbose "New client socket connected from: ""$($client.RemoteAddress())""."              

            $authenticated = ($client.Authentify($SecurePassword) -eq 280121)
            if (-not $authenticated)
            {
                throw "Access Denied."
            }                               
        }
        catch
        {
            $client.Close()

            throw $_
        }

        return $client
    }

    [bool] Active()
    {
        if ($this.Server)
        {
            return $this.Server.Active()
        }
        else
        {
            return $false
        }
    }

    [void] Close() 
    {
        <#
            .SYNOPSIS
                Stop listening and release TcpListener object.
        #>
        if ($this.Server)
        {                     
            if ($this.Server.Active)
            {                
                $this.Server.Stop()                
            }

            $this.Server = $null

            Write-Verbose "Server is now released."
        }
    }
}

class ViewerConfiguration {
    [string] $ScreenName = ""    
    [int] $ExpectDesktopWidth = 0
    [int] $ExpectDesktopHeight = 0
    [int] $ImageCompressionQuality = 100    
    [PacketSize] $PacketSize = [PacketSize]::Size9216
    [BlockSize] $BlockSize = [BlockSize]::Size64
    [bool] $HighQualityResize = $false 

    [bool] ResizeDesktop()
    {
        return $this.ExpectDesktopHeight -gt 0 -or $this.ExpectDesktopWidth -gt 0
    }

    [void] SetImageCompressionQuality([int] $Value)
    {
        if ($Value -lt 0)
        {
            $Value = 0
        }

        if ($Value -gt 100)
        {
            $Value = 100
        }

        $this.ImageCompressionQuality = $Value
    }
}

class ServerSession {
    [string] $Id = ""   
    [bool] $ViewOnly = $false
    [ClipboardMode] $Clipboard = [ClipboardMode]::Both
    [string] $ViewerLocation = ""
    
    [System.Collections.Generic.List[PSCustomObject]]
    $WorkerThreads = @()

    [System.Collections.Generic.List[ClientIO]]
    $Clients = @()
        
    $SafeHash = [HashTable]::Synchronized(@{
        ViewerConfiguration = [ViewerConfiguration]::New()
        SessionActive = $true
    })

    ServerSession(
        [bool] $ViewOnly,
        [ClipboardMode] $Clipboard,
        [string] $ViewerLocation
    ) 
    {
        $this.Id = (SHA512FromString -String (-join ((1..128) | ForEach-Object {Get-Random -input ([char[]](33..126))})))    
        
        $this.ViewOnly = $ViewOnly
        $this.Clipboard = $Clipboard
        $this.ViewerLocation = $ViewerLocation
    }

    [bool] CompareSession([string] $Id) 
    {
        <#
            .SYNOPSIS
                Compare two session object. In this case just compare session id string.

            .PARAMETER Id
                A session id to compare with current session object.
        #>
        return ($this.Id -ceq $Id)
    }

    [void] NewDesktopWorker([ClientIO] $Client)
    {
        <#
            .SYNOPSIS
                Create a new desktop streaming worker (Runspace/Thread).

            .PARAMETER Client
                An established connection with remote peer as a ClientIO Object.
        #>
        $param = New-Object -TypeName PSCustomObject -Property @{                      
            Client = $Client            
            SafeHash = $this.SafeHash
        }
        
        $this.WorkerThreads.Add((New-RunSpace -ScriptBlock $global:DesktopStreamScriptBlock -Param $param))       
        
        ###

        $this.Clients.Add($Client)
    }

    [void] NewEventWorker([ClientIO] $Client)
    {
        <#
            .SYNOPSIS
                Create a new egress / ingress worker (Runspace/Thread) to process outgoing / incomming events.

            .PARAMETER Client
                An established connection with remote peer as a ClientIO Object.
        #>

        $param = New-Object -TypeName PSCustomObject -Property @{                                                                           
            Writer = $Client.Writer
            Clipboard = $this.Clipboard
            SafeHash = $this.SafeHash
        }

        $this.WorkerThreads.Add((New-RunSpace -ScriptBlock $global:EgressEventScriptBlock -Param $param))    
        
        ###

        $param = New-Object -TypeName PSCustomObject -Property @{                                                                           
            Reader = $Client.Reader   
            Clipboard = $this.Clipboard
            ViewOnly = $this.ViewOnly   
            SafeHash = $this.SafeHash       
        }
                        
        $this.WorkerThreads.Add((New-RunSpace -ScriptBlock $global:IngressEventScriptBlock -Param $param)) 

        ###

        $this.Clients.Add($Client)
    }

    [void] CheckSessionIntegrity()
    {
        <#
            .SYNOPSIS
                Check if session integrity is still respected.

            .DESCRIPTION
                We consider that a dead session, is a session with at least one worker that has completed his 
                tasks.

                This will notify other workers that something happened (disconnection, fatal exception).
        #>

        foreach ($worker in $this.WorkerThreads)
        {
            if ($worker.AsyncResult.IsCompleted)
            {
                $this.Close()
                
                break
            }                 
        }  
    }

    [void] Close()
    {
        <#
            .SYNOPSIS
                Close components associated with current session (Ex: runspaces, sockets etc..)
        #>

        Write-Verbose "Closing session..."

        $this.SafeHash.SessionActive = $false

        Write-Verbose "Close associated peers..."

        # Close connection with remote peers associated with this session    
        foreach ($client in $this.Clients)
        {
            $client.Close()
        }

        $this.Clients.Clear()

        Write-Verbose "Wait for associated threads to finish their tasks..."

        while ($true)
        {                
            $completed = $true                   
            
            foreach ($worker in $this.WorkerThreads)
            {
                if (-not $worker.AsyncResult.IsCompleted)
                {
                    $completed = $false
                    
                    break
                }                 
            }

            if ($completed)
            { break }

            Start-Sleep -Seconds 1
        }

        Write-Verbose "Dispose threads (runspaces)..."

        # Terminate runspaces associated with this session
        foreach ($worker in $this.WorkerThreads)
        {
            $null = $worker.PowerShell.EndInvoke($worker.AsyncResult)
            $worker.PowerShell.Runspace.Dispose()                                      
            $worker.PowerShell.Dispose()                    
        }    
        $this.WorkerThreads.Clear() 

        Write-Host "Session terminated with viewer: $($this.ViewerLocation)" 

        Write-Verbose "Session closed."
    }
}

class SessionManager {    
    [ServerIO] $Server = $null

    [System.Collections.Generic.List[ServerSession]]
    $Sessions = @()        

    [SecureString] $SecurePassword = $null 

    [System.Security.Cryptography.X509Certificates.X509Certificate2] 
    $Certificate = $null

    [bool] $ViewOnly = $false
    [bool] $UseTLSv13 = $false

    [ClipboardMode] $Clipboard = [ClipboardMode]::Both

    SessionManager(
        [SecureString] $SecurePassword,

        [System.Security.Cryptography.X509Certificates.X509Certificate2] 
        $Certificate,

        [bool] $ViewOnly,
        [bool] $UseTLSv13,
        [ClipboardMode] $Clipboard
    )
    {
        Write-Verbose "Initialize new session manager..."

        $this.SecurePassword = $SecurePassword        
        $this.ViewOnly = $ViewOnly
        $this.UseTLSv13 = $UseTLSv13
        $this.Clipboard = $Clipboard

        if (-not $Certificate)
        {
            Write-Verbose "Custom X509 Certificate not specified."

            $this.Certificate = Get-X509CertificateFromStore        
            if (-not $this.Certificate)
            {
                Write-Verbose "Generate and Install a new local X509 Certificate."

                New-DefaultX509Certificate
                
                Write-verbose "Certificate was successfully installed on local machine. Opening..."

                $this.Certificate = Get-X509CertificateFromStore
                if (-not $this.Certificate)
                {
                    throw "Could not open our new local certificate."
                }
            }
            else
            {
                Write-Verbose "Default X509 Certificate was specified."            
            }
        }
        else
        {
            $this.Certificate = $Certificate
        }

        Write-Verbose "@Certificate:"
        Write-Verbose $this.Certificate
        Write-Verbose "---"

        Write-Verbose "Session manager initialized."
    }

    [void] OpenServer(
        [string] $ListenAddress,
        [int] $ListenPort        
    )
    {    
        <#
            .SYNOPSIS
                Create a new server object then start listening on desired interface / port.

            .PARAMETER ListenAddress
                Desired interface to listen for new peers.
                "127.0.0.1" = Only listen for localhost peers.
                "0.0.0.0" = Listen on all interfaces for peers.

            .PARAMETER ListenPort
                TCP Port to listen for new peers (0-65535)
        #>

        $this.CloseServer()        
        try
        {
            $this.Server = [ServerIO]::New()

            $this.Server.Listen(
                $ListenAddress,
                $ListenPort
            )
        }
        catch
        {
            $this.CloseServer()

            throw $_
        }
    }

    [ServerSession] GetSession([string] $SessionId)
    {
        <#
            .SYNOPSIS
                Find a session by its id on current session pool.

            .PARAMETER SessionId
                Session id to search in current pool.
        #>
        foreach ($session in $this.Sessions)
        {
            if ($session.CompareSession($SessionId))
            {
                return $session
            }
        }

        return $null
    }

    [void] ProceedNewSessionRequest([ClientIO] $Client)
    {        
        <#
            .SYNOPSIS
                Attempt a new session request with remote peer.

            .DESCRIPTION
                Session creation is now requested from a dedicated client instead of using
                same client as for desktop streaming.

                I prefer to use a dedicated client to have a more cleaner session establishement 
                process.

                Session request will basically generate a new session object, send some information 
                about current server marchine state then wait for viewer acknowledgement with desired
                configuration (Ex: desired screen to capture, quality and local size constraints).

                When session creation is done, client is then closed.                
                
        #>
        try
        {                           
            Write-Verbose "Remote peer as requested a new session..."

            $session = [ServerSession]::New($this.ViewOnly, $this.Clipboard, $client.RemoteAddress())

            Write-Verbose "@ServerSession"
            Write-Verbose "Id: ""$($session.Id)"""            
            Write-Verbose "---"

            $serverInformation = New-Object PSCustomObject -Property @{    
                # Session information and configuration
                SessionId = $session.Id
                Version = $global:PowerRemoteDesktopVersion
                ViewOnly = $this.ViewOnly

                # Local machine information
                MachineName = [Environment]::MachineName
                Username = [Environment]::UserName
                WindowsVersion = [Environment]::OSVersion.VersionString
                Screens = Get-ScreenList
            }            

            Write-Verbose "Sending server information to remote peer..."

            Write-Verbose "@ServerInformation:"
            Write-Verbose $serverInformation
            Write-Verbose "---"

            $client.WriteJson($serverInformation)

            Write-Verbose "Waiting for viewer expectation..."
            
            if ($serverInformation.Screens.Length -gt 1)
            {
                # Client have a maximum of 1 Minute to reply with viewer expectation.
                # This timeout is high to give enough time to the end-user to choose which screen he wants to use
                $timeout = 60 * 1000
            }
            else
            {
                $timeout = 5 * 1000
            }

            $viewerExpectation = $client.ReadJson($timeout)

            if ($viewerExpectation.PSobject.Properties.name -contains "ScreenName")
            {
                $session.SafeHash.ViewerConfiguration.ScreenName = $viewerExpectation.ScreenName    
            }
            
            if ($viewerExpectation.PSobject.Properties.name -contains "ExpectDesktopWidth")
            {
                $session.SafeHash.ViewerConfiguration.ExpectDesktopWidth = $viewerExpectation.ExpectDesktopWidth
            }

            if ($viewerExpectation.PSobject.Properties.name -contains "ExpectDesktopHeight")
            {
                $session.SafeHash.ViewerConfiguration.ExpectDesktopHeight = $viewerExpectation.ExpectDesktopHeight
            }

            if ($viewerExpectation.PSobject.Properties.name -contains "ImageCompressionQuality")
            {
                $session.SafeHash.ViewerConfiguration.ImageCompressionQuality = $viewerExpectation.ImageCompressionQuality
            }

            if ($viewerExpectation.PSobject.Properties.name -contains "PacketSize")
            {
                $session.SafeHash.ViewerConfiguration.PacketSize = [PacketSize]$viewerExpectation.PacketSize
            }

            if ($viewerExpectation.PSobject.Properties.name -contains "BlockSize")
            {
                $session.SafeHash.ViewerConfiguration.BlockSize = [BlockSize]$viewerExpectation.BlockSize
            }

            if ($viewerExpectation.PSobject.Properties.name -contains "HighQualityResize")
            {
                $session.SafeHash.ViewerConfiguration.HighQualityResize = $viewerExpectation.HighQualityResize
            }

            Write-Verbose "New session successfully created."

            $this.Sessions.Add($session)    
            
            $client.WriteLine((([ProtocolCommand]::Success)))
        }
        catch
        {
            $session = $null

            throw $_
        }
        finally
        {
            if ($client)
            {
                $client.Close()
            }
        }
    }   

    [void] ProceedAttachRequest([ClientIO] $Client)
    {    
        <#
            .SYNOPSIS
                Attach a new peer to an existing session then dispatch this new peer as a 
                new stateful worker.

            .PARAMETER Client
                An established connection with remote peer as a ClientIO Object.
        #>
        Write-Verbose "Proceed new session attach request..."

        $session = $this.GetSession($Client.ReadLine(5 * 1000))
        if (-not $session)
        {
            $Client.WriteLine(([ProtocolCommand]::ResourceNotFound))

            throw "Session object matchin given id could not be find in active session pool."
        }

        Write-Verbose "Client successfully attached to session: ""$($session.id)"""

        $Client.WriteLine(([ProtocolCommand]::ResourceFound))

        $workerKind = $Client.ReadLine(5 * 1000)

        switch ([WorkerKind] $workerKind)
        {
            (([WorkerKind]::Desktop))
            {
                $session.NewDesktopWorker($Client)

                break
            }

            (([WorkerKind]::Events))
            {                            
                $session.NewEventWorker($Client) # I/O

                break
            }            
        }
    }
    
    [void] ListenForWorkers()
    {               
        while ($true)
        {          
            if (-not $this.Server -or -not $this.Server.Active())
            {
                throw "A server must be active to listen for new workers."
            }

            try
            {
                # It is important to check regularly for dead sessions to let the garbage collector do his job
                # and avoid dead threads (most of the time desktop streaming threads).
                $this.CheckSessionsIntegrity()
            }
            catch
            {  }

            $client = $null
            try 
            {
                $client = $this.Server.PullClient(
                    $this.SecurePassword,
                    $this.Certificate,
                    $this.UseTLSv13,
                    5 * 1000
                )

                $requestMode = $client.ReadLine(5 * 1000)

                switch ([ProtocolCommand] $requestMode)
                {
                    ([ProtocolCommand]::RequestSession)
                    {                        
                        $remoteAddress = $client.RemoteAddress()

                        $this.ProceedNewSessionRequest($client)

                        Write-Host "New remote desktop session established with: $($remoteAddress)" 

                        break
                    }

                    ([ProtocolCommand]::AttachToSession)
                    {
                        $this.ProceedAttachRequest($client)

                        break
                    }

                    default:
                    {
                        $client.WriteLine(([ProtocolCommand]::BadRequest))

                        throw "Bad request."
                    }
                }                
            }
            catch 
            {
                if ($client)
                {
                    $client.Close()

                    $client = $null
                }
            }
            finally
            { }
        }
    }

    [void] CheckSessionsIntegrity()
    {
        foreach ($session in $this.Sessions)
        {
            $session.CheckSessionIntegrity()
        }
    }

    [void] CloseSessions()
    {
        <#
            .SYNOPSIS
                Close all existing sessions
        #>

        foreach ($session in $this.Sessions)
        {
            $session.Close()            
        }

        $this.Sessions.Clear()
    }

    [void] CloseServer()
    {
        <#
            .SYNOPSIS
                Close all existing sessions and dispose server.
        #>

        $this.CloseSessions()

        if ($this.Server)
        {            
            $this.Server.Close()

            $this.Server = $null            
        }
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

        .PARAMETER SecurePassword
            SecureString Password object used by remote viewer to authenticate with server (Recommended)

            Call "ConvertTo-SecureString -String "YouPasswordHere" -AsPlainText -Force" on this parameter to convert
            a plain-text String to SecureString.

        .PARAMETER Password
            Plain-Text Password used by remote viewer to authenticate with server (Not recommended, use SecurePassword instead)

            If no password is specified, then a random complex password will be generated
            and printed on terminal.

        .PARAMETER CertificateFile
            A valid X509 Certificate (With Private Key) File. If set, this parameter is prioritize.

        .PARAMETER EncodedCertificate
            A valid X509 Certificate (With Private Key) encoded as a Base64 String.

        .PARAMETER UseTLSv1_3
            Define whether or not TLS v1.3 must be used for communication with Viewer.

        .PARAMETER DisableVerbosity
            Disable verbosity (not recommended)        

        .PARAMETER Clipboard
            Define clipboard synchronization rules:
                - "Disabled": Completely disable clipboard synchronization.
                - "Receive": Update local clipboard with remote clipboard only.
                - "Send": Send local clipboard to remote peer.
                - "Both": Clipboards are fully synchronized between Viewer and Server.

        .PARAMETER ViewOnly (Default: None)
            If this switch is present, viewer wont be able to take the control of mouse (moves, clicks, wheel) and keyboard. 
            Useful for view session only.

        .PARAMETER PreventComputerToSleep
            Type: Switch
            Default: None
            Description:             
                If present, this option will prevent computer to enter in sleep mode while server is active and waiting for new connections.            
    #>

    param (
        [string] $ListenAddress = "0.0.0.0", 

        [ValidateRange(0, 65535)]
        [int] $ListenPort = 2801,

        [SecureString] $SecurePassword,
        [string] $Password = "",

        [string] $CertificateFile = "", # 1
        # Or
        [string] $EncodedCertificate = "", # 2

        [switch] $UseTLSv1_3,        
        [switch] $DisableVerbosity,
        [ClipboardMode] $Clipboard = [ClipboardMode]::Both,
        [switch] $ViewOnly,
        [switch] $PreventComputerToSleep
    )

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

        if (-not (Test-Administrator) -and -not $CertificateFile -and -not $EncodedCertificate)
        {
            throw "Insuficient Privilege`r`n`
            When a custom X509 Certificate is not specified, server will generate and install a default one on local machine store.`r`n`
            This operation requires Administrator Privilege.`r`n`
            Specify your own X509 Certificate or run the server in a elevated prompt."
        }

        $Certificate = $null

        if (($CertificateFile -and (Test-Path -Path $CertificateFile)) -or $EncodedCertificate)
        {
            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

            if ($CertificateFile)
            {
                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertificateFile
            }
            else
            {
                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @(, [Convert]::FromBase64String($EncodedCertificate))
            }
        }

        # If plain-text password is set, we convert this password to a secured representation.
        if ($Password -and -not $SecurePassword)
        {
            $SecurePassword = (ConvertTo-SecureString -String $Password -AsPlainText -Force)            
        }

        if (-not $SecurePassword)
        {
            $SecurePassword = New-RandomPassword
            
            Write-Host -NoNewLine "Server password: """
            Write-Host -NoNewLine $(Get-PlainTextPassword -SecurePassword $SecurePassword) -ForegroundColor green
            Write-Host """." 
        } 
        else 
        {
            if (-not (Test-PasswordComplexity -SecurePasswordCandidate $SecurePassword))
            {
                throw "Password complexity is too weak. Please choose a password following following rules:`r`n`
                * Minimum 12 Characters`r`n`
                * One of following symbols: ""!@#%^&*_""`r`n`
                * At least of lower case character`r`n`
                * At least of upper case character`r`n"
            }
        }   
        
        Remove-Variable -Name "Password" -ErrorAction SilentlyContinue

        try
        {
            $oldExecutionStateFlags = $null            
            if ($PreventComputerToSleep)
            {
                $oldExecutionStateFlags = Invoke-PreventSleepMode

                Write-OperationSuccessState -Message "Preventing computer to entering sleep mode." -Result ($oldExecutionStateFlags -gt 0)
            }

            Write-Host "Loading remote desktop server components..."

            $sessionManager = [SessionManager]::New(
                $SecurePassword,
                $Certificate,
                $ViewOnly,
                $UseTLSv1_3,
                $Clipboard
            )
            
            $sessionManager.OpenServer(
                $ListenAddress,
                $ListenPort
            )

            Write-Host "Server is ready to receive new connections..."
        
            $sessionManager.ListenForWorkers()            
        }
        finally
        {
            if ($sessionManager)
            {            
                $sessionManager.CloseServer()

                $sessionManager = $null
            }  

            if ($oldExecutionStateFlags)
            {
                Write-OperationSuccessState -Message "Stop preventing computer to enter sleep mode. Restore thread execution state." -Result (Update-ThreadExecutionState -Flags $oldExecutionStateFlags)
            }

            Write-Host "Remote desktop was closed."
        }                                                  
    }
    finally
    {            
        $ErrorActionPreference = $oldErrorActionPreference
        $VerbosePreference = $oldVerbosePreference
    }
}

try {  
    Export-ModuleMember -Function Invoke-RemoteDesktopServer
} catch {}