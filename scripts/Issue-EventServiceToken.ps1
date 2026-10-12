param(
    [Parameter(Mandatory)][ValidateSet('mis-worker','mis-inventory-relay')][string]$Service,
    [Parameter(Mandatory)][string]$Subject,
    [ValidateSet('dev','qa','main')][string]$Environment='dev',
    [ValidateRange(60,3600)][int]$Ttl=3600,
    [switch]$Register
)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -lt 7) { throw 'Se requiere PowerShell 7.' }
$security=Split-Path $PSScriptRoot
$workspace=Split-Path $security
$canonical=[guid]::Parse($Subject).ToString()
if($Subject -cne $canonical -or $canonical -eq [guid]::Empty.ToString()) { throw 'Subject UUID canonico requerido.' }
$suffix=if($Environment -eq 'dev') { '' } else { "/$Environment" }
$keys="$security/secrets$suffix"
$config=@{}
foreach($line in Get-Content -LiteralPath "$security/env/$Environment.env") {
    if($line -match '^([A-Z_]+)=(.*)$') { $config[$Matches[1]]=$Matches[2] }
}
if(-not $config.SECURITY_KEY_ID) { throw 'Falta SECURITY_KEY_ID del ambiente.' }
$audience=if($Service -eq 'mis-worker') { 'mis-api' } else { 'mis-events' }
$roles=if($Service -eq 'mis-worker') { @('INVENTORY') } else { @() }
$destination=if($Service -eq 'mis-worker') { 'mis-worker' } else { 'mis-inventory-api' }
$folder="$workspace/$destination/secrets/$Environment/$Service"
$registry="$keys/$Service-identity.json"
$identity=@{subject=$Subject;service=$Service;environment=$Environment;keyId=$config.SECURITY_KEY_ID;audience=$audience}
if(Test-Path -LiteralPath $registry) {
    $stored=Get-Content -LiteralPath $registry -Raw | ConvertFrom-Json
    foreach($name in @('subject','service','environment','keyId','audience')) {
        if($stored.$name -cne $identity[$name]) { throw 'Identidad cambiada: requiere rotacion aprobada.' }
    }
} elseif(-not $Register) { throw 'Registre primero la identidad desde Seguridad con -Register.' }
# No reutilizar identidades entre servicios o ambientes, incluido Workflow.
foreach($record in Get-ChildItem -LiteralPath "$security/secrets" -Filter '*-identity.json' -Recurse -File) {
    if($record.FullName -eq [IO.Path]::GetFullPath($registry)) { continue }
    $other=Get-Content -LiteralPath $record.FullName -Raw | ConvertFrom-Json
    if($other.subject -eq $Subject) { throw 'Subject ya registrado para otro servicio o ambiente.' }
}
if(Test-Path -LiteralPath "$folder/private.pem") { throw 'Material privado inesperado en el consumidor.' }
if((Test-Path -LiteralPath "$folder/public.pem") -and
   (Get-FileHash "$folder/public.pem").Hash -ne (Get-FileHash "$keys/public.pem").Hash) {
    throw 'Clave publica del consumidor ajena al ambiente.'
}
if(-not ('MediStockSecurityEventSigner' -as [type])) {
    Add-Type -TypeDefinition @'
using System.IO;
using System.Security.Cryptography;
public static class MediStockSecurityEventSigner {
    public static byte[] Sign(string privatePath, string publicPath, byte[] data) {
        using var signer = RSA.Create(); using var verifier = RSA.Create();
        signer.ImportFromPem(File.ReadAllText(privatePath));
        verifier.ImportFromPem(File.ReadAllText(publicPath));
        if (signer.KeySize < 2048) throw new CryptographicException("Weak RSA key");
        var signature = signer.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (!verifier.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            throw new CryptographicException("RSA key mismatch");
        return signature;
    }
}
'@
}
function B64($bytes) { [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$header=@{alg='RS256';typ='JWT';kid=$identity.keyId} | ConvertTo-Json -Compress
$claims=@{sub=$Subject;iss='mis-security';aud=$audience;roles=@($roles);service=$Service;environment=$Environment;iat=$now;exp=$now+$Ttl;jti=[guid]::NewGuid().ToString()} | ConvertTo-Json -Compress
$inputValue=(B64 ([Text.Encoding]::UTF8.GetBytes($header)))+'.'+(B64 ([Text.Encoding]::UTF8.GetBytes($claims)))
try { $signature=[MediStockSecurityEventSigner]::Sign("$keys/private.pem","$keys/public.pem",[Text.Encoding]::UTF8.GetBytes($inputValue)) }
catch { throw 'Fallo la emision en Seguridad; no se muestran claves.' }
New-Item -ItemType Directory -Path $folder -Force | Out-Null
if(-not (Test-Path -LiteralPath $registry)) {
    [IO.File]::WriteAllText($registry,($identity | ConvertTo-Json -Compress),[Text.Encoding]::ASCII)
}
Copy-Item -LiteralPath "$keys/public.pem" -Destination "$folder/public.pem"
$temporary=Join-Path $folder ([guid]::NewGuid().ToString('N')+'.tmp')
try {
    [IO.File]::WriteAllText($temporary,$inputValue+'.'+(B64 $signature),[Text.Encoding]::ASCII)
    [IO.File]::Move($temporary,"$folder/service.jwt",$true)
} finally { if(Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
Write-Output "Seguridad emitio JWT $Service ${Environment}: vence en $Ttl segundos; subject conservado."
