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
    using System.Security;
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
        public static extern int GetSystemMetrics(int nIndex);

        [DllImport("User32.dll")] 
        public static extern IntPtr GetWindowDC(IntPtr hWnd);

        [DllImport("User32.dll")] 
        public static extern bool ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("user32.dll")]
        public static extern IntPtr GetDesktopWindow();

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenDesktop(
            [MarshalAs(UnmanagedType.LPTStr)] string DesktopName,
            uint Flags,
            bool Inherit,
            uint Access
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetThreadDesktop(
            IntPtr hDesktop
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool CloseDesktop(
            IntPtr hDesktop
        );    

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetForegroundWindow();
    }    

    public static class Kernel32
    {
        [DllImport("Kernel32.dll")] 
        public static extern uint SetThreadExecutionState(uint esFlags);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="RtlMoveMemory"), SuppressUnmanagedCodeSecurity]
        public static extern void CopyMemory(
            IntPtr dest,
            IntPtr src,
            IntPtr count
        );        
    }

    public static class MSVCRT
    {
        [DllImport("msvcrt.dll", CallingConvention=CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
        public static extern IntPtr memcmp(
            IntPtr p1,
            IntPtr p2,
            IntPtr count
        );
    }

    public static class GDI32
    {
        [DllImport("gdi32.dll")]
        public static extern IntPtr DeleteDC(IntPtr hDc);

        [DllImport("gdi32.dll")]
        public static extern IntPtr DeleteObject(IntPtr hDc);

        [DllImport("gdi32.dll"), SuppressUnmanagedCodeSecurity]
        public static extern bool BitBlt(
            IntPtr hdcDest,
            int xDest,
            int yDest,
            int wDest,
            int hDest,
            IntPtr hdcSource,
            int xSrc,
            int ySrc,
            int RasterOp
        );

        [DllImport("gdi32.dll")]
        public static extern IntPtr CreateDIBSection(
            IntPtr hdc,
            IntPtr pbmi,
            uint usage,
            out IntPtr ppvBits,
            IntPtr hSection,
            uint offset
        );

        [DllImport ("gdi32.dll")]
        public static extern IntPtr CreateCompatibleBitmap(
            IntPtr hdc,
            int nWidth,
            int nHeight
        );

        [DllImport ("gdi32.dll")]
        public static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        [DllImport ("gdi32.dll")]
        public static extern IntPtr SelectObject(IntPtr hdc, IntPtr bmp); 
    }
"@

$global:PowerRemoteDesktopVersion = "4.0.0"

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
    LogonUIAccessDenied = 8
    LogonUIWrongSession = 9
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
    $ES_SYSTEM_REQUIRED = [uint32]"0x00000001"    

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
            Type: SecureString
            Default: None
            Description: Secure String object containing the password to test.            
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
            Type: String
            Default: PowerRemoteDesktop.Server
            Description: Certificate Common Name.

        .PARAMETER X509_O
            Type: String
            Default: Phrozen 
            Description: Certificate Organisation.

        .PARAMETER X509_L
            Type: String
            Default: Maisons Laffitte
            Description: Certificate Locality (City)

        .PARAMETER X509_S
            Type: String
            Default: Yvelines
            Description: Certificate State.

        .PARAMETER X509_C
            Type: String
            Default: FR
            Description: Certificate Company Name.

        .PARAMETER X509_OU
            Type: String
            Default: Freeware
            Description: Certificate Organizational Unit.

        .PARAMETER HashAlgorithmName
            Type: String
            Default: SHA512
            Description: Certificate Hash Algorithm.
                         Example: SHA128, SHA256, SHA512...

        .PARAMETER CertExpirationInDays
            Type: Integer
            Default: 365
            Description: Certificate expiration in days.
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
            Type: String
            Default: PowerRemoteDesktop.Server
            Description: The certificate Subject Name to retrieve from local machine certificate store.

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

    $solution = -join($Candidate, ":", (Get-PlainTextPassword -SecurePassword $SecurePassword))

    for ([int] $i = 0; $i -le 1000; $i++)
    {
        $solution = Get-SHA512FromString -String $solution
    }

    return $solution
}

$global:DesktopStreamScriptBlock = { 
    $mirrorDesktop_DC = [IntPtr]::Zero
    $desktop_DC = [IntPtr]::Zero
    $mirrorDesktop_hBmp = [IntPtr]::Zero
    $spaceBlock_DC = [IntPtr]::Zero
    $spaceBlock_hBmp = [IntPtr]::Zero
    $dirtyRect_DC = [IntPtr]::Zero
    $pBitmapInfoHeader = [IntPtr]::Zero
    try
    {  
        $BlockSize = [int]$Param.SafeHash.ViewerConfiguration.BlockSize
        $packetSize = [int]$Param.SafeHash.ViewerConfiguration.PacketSize  
        $compressionQuality = $Param.SafeHash.ViewerConfiguration.ImageCompressionQuality

        $SRCCOPY = 0x00CC0020    
        $DIB_RGB_COLORS = 0x0

        $screen = [System.Windows.Forms.Screen]::AllScreens | Where-Object -FilterScript { 
            $_.DeviceName -eq $Param.SafeHash.ViewerConfiguration.ScreenName 
        }

        if (-not $screen)
        {
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen
        }

        $screenBounds = $screen.Bounds

        $SpaceGrid = $null
        $horzBlockCount = [math]::ceiling($screenBounds.Width / $BlockSize)
        $vertBlockCount = [math]::ceiling($screenBounds.Height / $BlockSize)         

        $encoderParameters = New-Object System.Drawing.Imaging.EncoderParameters(1) 
        $encoderParameters.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter(
            [System.Drawing.Imaging.Encoder]::Quality,
            $compressionQuality
        )

        $encoder = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' };

        $SpaceGrid = New-Object IntPtr[][] $vertBlockCount, $horzBlockCount    

        $firstIteration = $true

        # Create our desktop mirror (For speeding up BitBlt calls)

        [IntPtr] $desktop_DC = [User32]::GetWindowDC([User32]::GetDesktopWindow())
        [IntPtr] $mirrorDesktop_DC = [GDI32]::CreateCompatibleDC($desktop_DC)

        [IntPtr] $mirrorDesktop_hBmp = [GDI32]::CreateCompatibleBitmap(
            $desktop_DC,
            $screenBounds.Width,
            $screenBounds.Height
        )

        $null = [GDI32]::SelectObject($mirrorDesktop_DC, $mirrorDesktop_hBmp)   

        # Create our block of space for change detection

        <#
            typedef struct tagBITMAPINFOHEADER {
                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x0        
                DWORD biSize;

                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x4        
                LONG  biWidth;

                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x8        
                LONG  biHeight;

                // x86-32|64: 0x2 Bytes | Padding = 0x0 | Offset: 0xc        
                WORD  biPlanes;

                // x86-32|64: 0x2 Bytes | Padding = 0x0 | Offset: 0xe      
                WORD  biBitCount;

                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x10       
                DWORD biCompression;

                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x14        
                DWORD biSizeImage;

                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x18       
                LONG  biXPelsPerMeter;

                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x1c       
                LONG  biYPelsPerMeter;

                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x20       
                DWORD biClrUsed;

                // x86-32|64: 0x4 Bytes | Padding = 0x0 | Offset: 0x24       
                DWORD biClrImportant;
            } BITMAPINFOHEADER, *LPBITMAPINFOHEADER, *PBITMAPINFOHEADER; 

            // x86-32|64 Struct Size: 0x28 (40 Bytes)
            // BITMAPINFO = BITMAPINFOHEADER (0x28) + RGBQUAD (0x4) = 0x2c
        #>

        $bitmapInfoHeaderSize = 0x28
        $bitmapInfoSize = $bitmapInfoHeaderSize + 0x4

        $pBitmapInfoHeader = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bitmapInfoSize)

        # ZeroMemory
        for ($i = 0; $i -lt $bitmapInfoSize; $i++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($pBitmapInfoHeader, $i, 0x0)    
        }

        [System.Runtime.InteropServices.Marshal]::WriteInt32($pBitmapInfoHeader, 0x0, $bitmapInfoHeaderSize) # biSize
        [System.Runtime.InteropServices.Marshal]::WriteInt32($pBitmapInfoHeader, 0x4, $BlockSize) # biWidth
        [System.Runtime.InteropServices.Marshal]::WriteInt32($pBitmapInfoHeader, 0x8, $BlockSize) # biHeight
        [System.Runtime.InteropServices.Marshal]::WriteInt16($pBitmapInfoHeader, 0xc, 0x1) # biPlanes
        [System.Runtime.InteropServices.Marshal]::WriteInt16($pBitmapInfoHeader, 0xe, 0x20) # biBitCount
        
        [IntPtr] $spaceBlock_DC = [GDI32]::CreateCompatibleDC(0)
        [IntPtr] $spaceBlock_Ptr = [IntPtr]::Zero

        [IntPtr] $spaceBlock_hBmp = [GDI32]::CreateDIBSection(
            $spaceBlock_DC,
            $pBitmapInfoHeader,
            $DIB_RGB_COLORS,
            [ref] $spaceBlock_Ptr,
            [IntPtr]::Zero,
            0
        )

        $null = [GDI32]::SelectObject($spaceBlock_DC, $spaceBlock_hBmp)

        # Create our dirty rect DC
        $dirtyRect_DC = [GDI32]::CreateCompatibleDC(0)

        # SizeOf(DWORD) * 3 (SizeOf(Desktop) + SizeOf(Left) + SizeOf(Top))
        $sizeOfUInt32 = [Runtime.InteropServices.Marshal]::SizeOf([System.Type][UInt32])
        $struct = New-Object -TypeName byte[] -ArgumentList ($sizeOfUInt32 * 3)

        $topLeftBlock = [System.Drawing.Point]::Empty
        $bottomRightBlock = [System.Drawing.Point]::Empty   

        $blockMemSize = ((($BlockSize * 32) + 32) -band -bnot 32) / 8
        $blockMemSize *= $BlockSize 
        $ptrBlockMemSize = [IntPtr]::New($blockMemSize)

        $dirtyRect = New-Object -TypeName System.Drawing.Rectangle -ArgumentList 0, 0, $screenBounds.Width, $screenBounds.Height
            
        <#
        $fps = 0
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        #>

        while ($Param.SafeHash.SessionActive)
        {      
            # Refresh our desktop mirror
            $result = [GDI32]::BitBlt(
                $mirrorDesktop_DC,
                0,
                0,
                $screenBounds.Width,    
                $screenBounds.Height,
                $desktop_DC,
                $screenBounds.Location.X,
                $screenBounds.Location.Y,
                $SRCCOPY
            )        

            if (-not $result)
            {
                continue
            }
                
            $updated = $false

            for ($y = 0; $y -lt $vertBlockCount; $y++)    
            {                             
                for ($x = 0; $x -lt $horzBlockCount; $x++)
                {                                                                       
                    $null = [GDI32]::BitBlt(
                        $spaceBlock_DC,
                        0,
                        0,
                        $BlockSize,
                        $BlockSize,
                        $mirrorDesktop_DC,
                        ($x * $BlockSize),
                        ($y * $BlockSize),
                        $SRCCOPY
                    );
                                
                    if ($firstIteration)
                    {
                        # Big bang occurs, tangent univers is getting created, where is Donnie?
                        $SpaceGrid[$y][$x] = [Runtime.InteropServices.Marshal]::AllocHGlobal($blockMemSize)
                                                                                                
                        [Kernel32]::CopyMemory($SpaceGrid[$y][$x], $spaceBlock_Ptr, $ptrBlockMemSize)                        
                    }
                    else
                    {                                                                        
                        if ([MSVCRT]::memcmp($spaceBlock_Ptr, $SpaceGrid[$y][$x], $ptrBlockMemSize) -ne [IntPtr]::Zero)
                        {
                            [Kernel32]::CopyMemory($SpaceGrid[$y][$x], $spaceBlock_Ptr, $ptrBlockMemSize) 
                            
                            if (-not $updated)
                            {                  
                                # Initialize with the first dirty block coordinates                  
                                $topLeftBlock.X = $x
                                $topLeftBlock.Y = $y

                                $bottomRightBlock = $topLeftBlock

                                $updated = $true
                            }
                            else
                            {    
                                if ($x -lt $topLeftBlock.X)
                                {
                                    $topLeftBlock.X = $x
                                }

                                if ($y -lt $topLeftBlock.Y)
                                {
                                    $topLeftBlock.Y = $y
                                }

                                if ($x -gt $bottomRightBlock.X)
                                {
                                    $bottomRightBlock.X = $x
                                }

                                if ($y -gt $bottomRightBlock.Y)
                                {
                                    $bottomRightBlock.Y = $y
                                }   
                            }                                                              
                        }                        
                    }                                             
                }                            
            }     
            
            if ($updated)
            {                
                # Create new updated rectangle pointing to the dirty region (since last snapshot)
                $dirtyRect.X = $topLeftBlock.X * $BlockSize
                $dirtyRect.Y = $topLeftBlock.Y * $BlockSize

                $dirtyRect.Width = (($bottomRightBlock.X * $BlockSize) + $BlockSize) - $dirtyRect.Left
                $dirtyRect.Height = (($bottomRightBlock.Y * $BlockSize) + $BlockSize) - $dirtyRect.Top                
            }            
            
            if ($updated -or $firstIteration)
            {                           
                try
                {
                    $dirtyRect_hBmp = [GDI32]::CreateCompatibleBitmap(
                        $mirrorDesktop_DC,
                        $dirtyRect.Width,
                        $dirtyRect.Height
                    )

                    $null = [GDI32]::SelectObject($dirtyRect_DC, $dirtyRect_hBmp)

                    $null = [GDI32]::BitBlt(
                        $dirtyRect_DC,
                        0,
                        0,
                        $dirtyRect.Width,
                        $dirtyRect.Height,
                        $mirrorDesktop_DC,
                        $dirtyRect.X,
                        $dirtyRect.Y,
                        $SRCCOPY
                    )

                    # TODO: Find a faster alternative
                    [System.Drawing.Bitmap] $updatedDesktop = [System.Drawing.Image]::FromHBitmap($dirtyRect_hBmp) 
                
                    $desktopStream = New-Object System.IO.MemoryStream                

                    $updatedDesktop.Save($desktopStream, $encoder, $encoderParameters)                                 

                    $desktopStream.Position = 0
                    
                    try 
                    {         
                        # One call please  
                        [System.Runtime.InteropServices.Marshal]::WriteInt32($struct, 0x0, $desktopStream.Length)
                        [System.Runtime.InteropServices.Marshal]::WriteInt32($struct, 0x4, $dirtyRect.Left)
                        [System.Runtime.InteropServices.Marshal]::WriteInt32($struct, 0x8, $dirtyRect.Top)

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
                    if ($dirtyRect_hBmp -ne [IntPtr]::Zero)
                    {
                        $null = [GDI32]::DeleteObject($dirtyRect_hBmp)
                    }

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

            <#
            $fps++
            if ($Stopwatch.ElapsedMilliseconds -ge 1000)
            {
                $HostSyncHash.host.ui.WriteLine($fps)
                $fps = 0

                $Stopwatch.Restart()
            }
            #>
        }
    }
    finally
    {       
        # Free allocated resources 
        if ($mirrorDesktop_DC -ne [IntPtr]::Zero)
        {
            $null = [GDI32]::DeleteDC($mirrorDesktop_DC)
        }
    
        if ($mirrorDesktop_hBmp -ne [IntPtr]::Zero)
        {
            $null = [GDI32]::DeleteObject($mirrorDesktop_hBmp)
        }     

        if ($spaceBlock_DC -ne [IntPtr]::Zero)      
        {
            $null = [GDI32]::DeleteDC($spaceBlock_DC)
        }

        if ($spaceBlock_hBmp -ne [IntPtr]::Zero)
        {
            $null = [GDI32]::DeleteObject($spaceBlock_hBmp)
        }

        if ($dirtyRect_DC -ne [IntPtr]::Zero)
        {
            $null = [GDI32]::DeleteDC($dirtyRect_DC)
        }

        if ($pBitmapInfoHeader -ne [IntPtr]::Zero)
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pBitmapInfoHeader)
        }

        if ($desktop_DC -ne [IntPtr]::Zero)
        {
            $null = [User32]::ReleaseDC([User32]::GetDesktopWindow(), $desktop_DC)    
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
    
    $SM_CXSCREEN = 0
    $SM_CYSCREEN = 1

    function Set-MouseCursorPos
    {
        param(
            [int] $X = 0,
            [int] $Y = 0
        )

        $x_screen = [User32]::GetSystemMetrics($SM_CXSCREEN)
        $y_screen = [User32]::GetSystemMetrics($SM_CYSCREEN)

        [User32]::mouse_event(
            [int][MouseFlags]::MOUSEEVENTF_MOVE -bor [int][MouseFlags]::MOUSEEVENTF_ABSOLUTE,
            (65535 * $X) / $x_screen,
            (65535 * $Y) / $y_screen,
            0,
            0
        );
            
    }    

    while ($true)                    
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

                [System.Windows.Forms.SendKeys]::SendWait($aEvent.Keys)  

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
                        #[User32]::SetCursorPos($aEvent.X, $aEvent.Y)   
                        Set-MouseCursorPos -X $aEvent.X -Y $aEvent.Y

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

                        #[User32]::SetCursorPos($aEvent.X, $aEvent.Y)
                        Set-MouseCursorPos -X $aEvent.X -Y $aEvent.Y

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
        DesktopActive = 0x4
        DesktopInactive = 0x5     
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
                Type: Enum
                Default: None
                Description: The event to send to remote viewer.

            .PARAMETER Data
                Type: PSCustomObject
                Default: None
                Description: Additional information about the event.
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
    
    # Feature not yet available
    #$desktopIsActive = [User32]::GetForegroundWindow() -ne [IntPtr]::Zero

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

                # Clipboard Update Detection
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

                # Desktop Active / Inactive Detection
                <#$desktopActiveProbe = [User32]::GetForegroundWindow() -ne [IntPtr]::Zero
                if ($desktopIsActive -ne $desktopActiveProbe)
                {
                    if ($desktopActiveProbe)
                    {
                        $aEvent = [OutputEvent]::DesktopActive
                    }
                    else
                    {
                        $aEvent = [OutputEvent]::DesktopInactive
                    }

                    #if (-not (Send-Event -AEvent $aEvent))
                    #{ break }

                    $desktopIsActive = $desktopActiveProbe

                    #$eventTriggered = $true
                }#>
                
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
        # Update Frequently (Maximum probe time to be efficient: 50ms)
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

        Start-Sleep -Milliseconds 50 
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
            Type: ScriptBlock
            Default: None
            Description: Instructions to execute in new runspace.

        .PARAMETER Param
            Type: PSCustomObject
            Default: None
            Description: Object to attach in runspace context.

        .PARAMETER LogonUI
            Type: Boolean
            Default: False
            Description: 
                New thread will attach its desktop to LogonUI / Winlogon 
                (Requires SYSTEM Privilege on active session)

        .EXAMPLE
            New-RunSpace -Client $newClient -ScriptBlock { Start-Sleep -Seconds 10 }
    #>

    param(
        [Parameter(Mandatory=$True)]
        [ScriptBlock] $ScriptBlock,

        [PSCustomObject] $Param = $null,
        [bool] $LogonUI = $false
    )   

    $runspace = [RunspaceFactory]::CreateRunspace()
    $runspace.ThreadOptions = "UseNewThread"
    $runspace.ApartmentState = "STA"
    $runspace.Open()                   

    if ($Param)
    {
        $runspace.SessionStateProxy.SetVariable("Param", $Param) 
    }

    $runspace.SessionStateProxy.SetVariable("HostSyncHash", $global:HostSyncHash)    
    
    $powershell = [PowerShell]::Create()

    if ($LogonUI)
    {
        # Runspace prelude to update new thread desktop before something happens.  
        # This code will switch new thread desktop from "WinSta0/default" to "WinSta0/winlogon".
        # It requires to be "NT AUTHORITY/SYSTEM"
        $null = $powershell.AddScript({    
            $MAXIMUM_ALLOWED = 0x02000000;   

            $winLogonDesktop = [User32]::OpenDesktop("winlogon", 0, $false, $MAXIMUM_ALLOWED);
            if ($winLogonDesktop -eq [IntPtr]::Zero)
            {                
                return  
            }
            
            if (-not [User32]::SetThreadDesktop($winLogonDesktop))
            {
                [User32]::CloseDesktop($winLogonDesktop)

                return
            }                    
        })
    }

    $null = $powershell.AddScript($ScriptBlock)

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
                Type: SecureString
                Default: None
                Description: Secure String object containing the password.                

            .EXAMPLE
                .Authentify((ConvertTo-SecureString -String "urCompl3xP@ssw0rd" -AsPlainText -Force))
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
                Description: Maximum period of time to wait for reading data.
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
                Type: Integer
                Description:
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
    [int] $ImageCompressionQuality = 100    
    [PacketSize] $PacketSize = [PacketSize]::Size9216
    [BlockSize] $BlockSize = [BlockSize]::Size64        

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
    [bool] $LogonUI = $false
    
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
                Type: String
                Description: A session id to compare with current session object.
        #>
        return ($this.Id -ceq $Id)
    }

    [void] NewDesktopWorker([ClientIO] $Client)
    {
        <#
            .SYNOPSIS
                Create a new desktop streaming worker (Runspace/Thread).

            .PARAMETER Client
                Type: ClientIO
                Description: Established connection with a remote peer.
        #>
        $param = New-Object -TypeName PSCustomObject -Property @{                      
            Client = $Client            
            SafeHash = $this.SafeHash
        }
        
        $this.WorkerThreads.Add((New-RunSpace -ScriptBlock $global:DesktopStreamScriptBlock -Param $param -LogonUI $this.LogonUI))       
        
        ###

        $this.Clients.Add($Client)
    }

    [void] NewEventWorker([ClientIO] $Client)
    {
        <#
            .SYNOPSIS
                Create a new egress / ingress worker (Runspace/Thread) to process outgoing / incomming events.

            .PARAMETER Client
                Type: ClientIO
                Description: Established connection with a remote peer.
        #>

        $param = New-Object -TypeName PSCustomObject -Property @{                                                                           
            Writer = $Client.Writer
            Clipboard = $this.Clipboard
            SafeHash = $this.SafeHash
        }

        $this.WorkerThreads.Add((New-RunSpace -ScriptBlock $global:EgressEventScriptBlock -Param $param -LogonUI $this.LogonUI))    
        
        ###

        $param = New-Object -TypeName PSCustomObject -Property @{                                                                           
            Reader = $Client.Reader   
            Clipboard = $this.Clipboard
            ViewOnly = $this.ViewOnly   
            SafeHash = $this.SafeHash       
        }
                        
        $this.WorkerThreads.Add((New-RunSpace -ScriptBlock $global:IngressEventScriptBlock -Param $param -LogonUI $this.LogonUI)) 

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
                Type: String
                Description: SessionId to retrieve from session pool.
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

            $session = [ServerSession]::New(
                $this.ViewOnly,
                $this.Clipboard,
                $client.RemoteAddress()
            )

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

            if ($viewerExpectation.PSobject.Properties.name -contains "LogonUI")
            {
                $session.LogonUI = $viewerExpectation.LogonUI

                if ($session.LogonUI)
                {
                    if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
                    {
                        $client.WriteLine(([ProtocolCommand]::LogonUIWrongSession))

                        throw "Can't attach to Winlogon when current process session id is equal to zero."
                    }

                    if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
                    {
                        $client.WriteLine(([ProtocolCommand]::LogonUIAccessDenied))

                        throw "Attach to Winlogon requires ""NT AUTHORITY/System"" privilege."
                    }
                }
            }         

            Write-Verbose "New session successfully created."

            $this.Sessions.Add($session)    
            
            $client.WriteLine(([ProtocolCommand]::Success))
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

            throw "Could not locate session."
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
        <#
            .SYNOPSIS
                Process server client queue and dispatch accordingly.
        #>   
        while ($true)
        {          
            if (-not $this.Server -or -not $this.Server.Active())
            {
                throw "A server must be active to listen for new workers."
            }

            try
            {                
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
        <#
            .SYNOPSIS
                Check if existing server sessions integrity is respected.
                Use this method to free dead/half-dead sessions.
        #>
        foreach ($session in $this.Sessions)
        {
            $session.CheckSessionIntegrity()
        }
    }

    [void] CloseSessions()
    {
        <#
            .SYNOPSIS
                Terminate existing server sessions.
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
                Terminate existing server sessions then release server.
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
            Check if current user is administrator.
    #>
    $windowsPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    
    return $windowsPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )    
}

class ValidateFileAttribute : System.Management.Automation.ValidateArgumentsAttribute
{
    <#
        .SYNOPSIS
            Check if file argument exists on disk.
    #>

    [void]Validate([System.Object] $arguments, [System.Management.Automation.EngineIntrinsics] $engineIntrinsics)
    {
        if(-not (Test-Path -Path $arguments))
        {
            throw [System.IO.FileNotFoundException]::new()
        }      
    }
}

class ValidateBase64StringAttribute : System.Management.Automation.ValidateArgumentsAttribute
{
    <#
        .SYNOPSIS
            Check if string argument is a valid Base64 String.
    #>

    [void]Validate([System.Object] $arguments, [System.Management.Automation.EngineIntrinsics] $engineIntrinsics)
    {
        [Convert]::FromBase64String($arguments)
    }
}

function Invoke-RemoteDesktopServer
{
    <#
        .SYNOPSIS
            Create and start a new PowerRemoteDesktop Server.

        .DESCRIPTION
            Notices: 
            
                1- Prefer using SecurePassword over plain-text password even if a plain-text password is getting converted to SecureString anyway.

                2- Not specifying a custom certificate using CertificateFile or EncodedCertificate result in generating a default 
                self-signed certificate (if not already generated) that will get installed on local machine thus requiring administrator privilege.
                If you want to run the server as a non-privileged account, specify your own certificate location.

                3- If you don't specify a SecurePassword or Password, a random complex password will be generated and displayed on terminal 
                (this password is temporary)

        .PARAMETER ListenAddress
            Type: String
            Default: 0.0.0.0
            Description: IP Address that represents the local IP address.

        .PARAMETER ListenPort
            Type: Integer
            Default: 2801 (0 - 65535)
            Description: The port on which to listen for incoming connection.

        .PARAMETER SecurePassword
            Type: SecureString
            Default: None
            Description: SecureString object containing password used to authenticate remote viewer (Recommended)

        .PARAMETER Password
            Type: String
            Default: None
            Description: Plain-Text Password used to authenticate remote viewer (Not recommended, use SecurePassword instead)

        .PARAMETER CertificateFile
            Type: String
            Default: None
            Description: A file containing valid certificate information (x509), must include the private key.
            
        .PARAMETER EncodedCertificate
            Type: String (Base64 Encoded)
            Default: None
            Description: A base64 representation of the whole certificate file, must include the private key.            

        .PARAMETER UseTLSv1_3
            Type: Switch
            Default: False
            Description: If present, TLS v1.3 will be used instead of TLS v1.2 (Recommended if applicable to both systems)

        .PARAMETER DisableVerbosity
            Type: Switch
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

        .PARAMETER ViewOnly (Default: None)
            Type: Swtich
            Default: False
            Description: If present, remote viewer is only allowed to view the desktop (Mouse and Keyboard are not authorized)

        .PARAMETER PreventComputerToSleep
            Type: Switch
            Default: False
            Description: If present, this option will prevent computer to enter in sleep mode while server is active and waiting for new connections.

        .PARAMETER CertificatePassword
            Type: SecureString
            Default: None
            Description: Specify the password used to open a password-protected x509 Certificate provided by user.

        .EXAMPLE
            Invoke-RemoteDesktopServer -ListenAddress "0.0.0.0" -ListenPort 2801 -SecurePassword (ConvertTo-SecureString -String "urCompl3xP@ssw0rd" -AsPlainText -Force)
            Invoke-RemoteDesktopServer -ListenAddress "0.0.0.0" -ListenPort 2801 -SecurePassword (ConvertTo-SecureString -String "urCompl3xP@ssw0rd" -AsPlainText -Force) -CertificateFile "c:\certs\phrozen.p12"
    #>

    param (
        [string] $ListenAddress = "0.0.0.0", 

        [ValidateRange(0, 65535)]
        [int] $ListenPort = 2801,   

        [SecureString] $SecurePassword = $null,
        [string] $Password = "",           
        [String] $CertificateFile = $null,           
        [string] $EncodedCertificate = "",
        [switch] $UseTLSv1_3,        
        [switch] $DisableVerbosity,
        [ClipboardMode] $Clipboard = [ClipboardMode]::Both,
        [switch] $ViewOnly,
        [switch] $PreventComputerToSleep,
        [SecureString] $CertificatePassword = $null
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

        if ($CertificateFile -or $EncodedCertificate)
        {
            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            try
            {
                if ($CertificateFile)
                {
                    if(-not (Test-Path -Path $CertificateFile))
                    {
                        throw [System.IO.FileNotFoundException]::new()
                    }

                    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertificateFile, $CertificatePassword
                }
                else
                {
                    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ([Convert]::FromBase64String($EncodedCertificate)), $CertificatePassword
                }
            }
            catch
            {
                $message =  "Could not open provided x509 Certificate. Possible Reasons:`r`n" +
                            "* Provided certificate is not a valid x509 Certificate.`r`n" +
                            "* Certificate is corrupted.`r`n"                        

                if (-not $CertificatePassword)
                {
                    $message += "* Certificate is protected by a password.`r`n"
                }
                else
                {
                    $message += "* Provided certificate password is not valid.`r`n"     
                }    
                
                $message += "More detail: $($_)"

                throw $message
            }

            if (-not $Certificate.HasPrivateKey)
            {
                throw "Provided Certificate must have private-key included."
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