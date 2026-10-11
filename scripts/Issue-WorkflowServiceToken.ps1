param([ValidateSet('dev','qa','main')][string]$Environment='dev',[ValidateRange(60,3600)][int]$Ttl=3600,[switch]$Register)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -lt 7) { throw 'Se requiere PowerShell 7.' }
$security=Split-Path $PSScriptRoot
$workspace=Split-Path $security
$suffix=if($Environment -eq 'dev') { '' } else { "/$Environment" }
$keys="$security/secrets$suffix"
$folder="$workspace/mis-workflow/secrets/$Environment"
function Settings($path) {
    $result=@{}
    foreach($line in Get-Content -LiteralPath $path) {
        if($line -match '^([A-Z_]+)=(.*)$') { $result[$Matches[1]]=$Matches[2] }
    }
    return $result
}
$workflow=Settings "$workspace/mis-workflow/env/$Environment.env"
$config=Settings "$security/env/$Environment.env"
$subject=[guid]::Parse($workflow.WORKFLOW_SERVICE_SUBJECT).ToString()
if($subject -ne $workflow.WORKFLOW_SERVICE_SUBJECT -or
   -not $config.SECURITY_KEY_ID -or $workflow.WORKFLOW_KEY_ID -ne $config.SECURITY_KEY_ID -or
   $workflow.WORKFLOW_CREDENTIALS_PATH -ne "../secrets/$Environment") { throw 'Identidad workflow invalida.' }
if((Get-FileHash "$folder/public.pem").Hash -ne (Get-FileHash "$keys/public.pem").Hash) {
    throw 'Clave publica workflow ajena al ambiente.'
}
# El registro requiere un administrador local con acceso a las claves de Seguridad.
$registry="$keys/workflow-identity.json"
if(-not (Test-Path -LiteralPath $registry)) {
    if(-not $Register) { throw 'Registre primero la identidad desde Seguridad con -Register.' }
    $identity=@{subject=$subject;service='mis-workflow';environment=$Environment;keyId=$config.SECURITY_KEY_ID}
    [IO.File]::WriteAllText($registry,($identity | ConvertTo-Json -Compress),[Text.Encoding]::ASCII)
}
$identity=Get-Content -LiteralPath $registry -Raw | ConvertFrom-Json
if($identity.subject -ne $subject -or $identity.service -ne 'mis-workflow' -or
   $identity.environment -ne $Environment -or $identity.keyId -ne $config.SECURITY_KEY_ID) {
    throw 'Identidad cambiada: requiere rotacion aprobada, no registro silencioso.'
}
if(-not ('MediStockSecurityWorkflowSigner' -as [type])) {
    Add-Type -TypeDefinition @'
using System.IO;
using System.Security.Cryptography;
public static class MediStockSecurityWorkflowSigner {
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
$claims=@{sub=$identity.subject;iss='mis-security';aud='mis-api';roles=@('INVENTORY');service='mis-workflow';iat=$now;exp=$now+$Ttl;jti=[guid]::NewGuid().ToString()} | ConvertTo-Json -Compress
$inputValue=(B64 ([Text.Encoding]::UTF8.GetBytes($header)))+'.'+(B64 ([Text.Encoding]::UTF8.GetBytes($claims)))
try { $signature=[MediStockSecurityWorkflowSigner]::Sign("$keys/private.pem","$keys/public.pem",[Text.Encoding]::UTF8.GetBytes($inputValue)) }
catch { throw 'Fallo la emision en Seguridad; no se muestran claves.' }
$temporary=Join-Path $folder ([guid]::NewGuid().ToString('N')+'.tmp')
try {
    [IO.File]::WriteAllText($temporary,$inputValue+'.'+(B64 $signature),[Text.Encoding]::ASCII)
    [IO.File]::Move($temporary,"$folder/service.jwt",$true)
} finally { if(Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
Write-Output "Seguridad emitio JWT workflow ${Environment}: vence en $Ttl segundos; subject conservado."
