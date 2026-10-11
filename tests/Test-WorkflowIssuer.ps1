$ErrorActionPreference='Stop'
$source=Join-Path (Split-Path $PSScriptRoot) 'scripts/Issue-WorkflowServiceToken.ps1'
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('mis-issuer-test-'+[guid]::NewGuid().ToString('N'))
function Check($condition,$message) { if(-not $condition) { throw $message } }
function Reject($action) {
    $failed=$false
    try { & $action | Out-Null } catch { $failed=$true }
    Check $failed 'Se esperaba rechazo.'
}
New-Item -ItemType Directory -Path "$fixture/mis-security/scripts" -Force | Out-Null
Copy-Item -LiteralPath $source -Destination "$fixture/mis-security/scripts/Issue-WorkflowServiceToken.ps1"
$issuer="$fixture/mis-security/scripts/Issue-WorkflowServiceToken.ps1"
try {
    foreach($envName in @('dev','qa','main')) {
        $suffix=if($envName -eq 'dev') { '' } else { "/$envName" }
        $keys="$fixture/mis-security/secrets$suffix"
        $target="$fixture/mis-workflow/secrets/$envName"
        New-Item -ItemType Directory -Force -Path $keys,$target,"$fixture/mis-security/env","$fixture/mis-workflow/env" | Out-Null
        $rsa=[Security.Cryptography.RSA]::Create(2048)
        [IO.File]::WriteAllText("$keys/private.pem",$rsa.ExportPkcs8PrivateKeyPem())
        [IO.File]::WriteAllText("$keys/public.pem",$rsa.ExportSubjectPublicKeyInfoPem())
        Copy-Item -LiteralPath "$keys/public.pem" -Destination "$target/public.pem"
        $subject=[guid]::NewGuid().ToString()
        $config="WORKFLOW_SERVICE_SUBJECT=$subject`nWORKFLOW_KEY_ID=key-$envName`nWORKFLOW_CREDENTIALS_PATH=../secrets/$envName`n"
        [IO.File]::WriteAllText("$fixture/mis-workflow/env/$envName.env",$config)
        [IO.File]::WriteAllText("$fixture/mis-security/env/$envName.env","SECURITY_KEY_ID=key-$envName`n")
        Reject { & $issuer -Environment $envName }
        & $issuer -Environment $envName -Register -Ttl 60 | Out-Null
        $first=[IO.File]::ReadAllText("$target/service.jwt")
        & $issuer -Environment $envName -Ttl 3600 | Out-Null
        $second=[IO.File]::ReadAllText("$target/service.jwt")
        Check ($first -ne $second) 'La renovacion debe cambiar jti.'
        $parts=$second.Split('.')
        function Decode($value) { [Convert]::FromBase64String($value.Replace('-','+').Replace('_','/')+('='*((4-$value.Length%4)%4))) }
        $claims=[Text.Encoding]::UTF8.GetString((Decode $parts[1])) | ConvertFrom-Json
        Check ($claims.sub -eq $subject -and $claims.service -eq 'mis-workflow' -and
               $claims.iss -eq 'mis-security' -and $claims.aud -eq 'mis-api' -and
               @($claims.roles).Count -eq 1 -and $claims.roles[0] -eq 'INVENTORY' -and
               $claims.exp-$claims.iat -eq 3600) 'Claims incorrectos.'
        Check ($rsa.VerifyData([Text.Encoding]::UTF8.GetBytes($parts[0]+'.'+$parts[1]),(Decode $parts[2]),
               [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'Firma incorrecta.'
        Reject { & $issuer -Environment $envName -Ttl 3601 }
        [IO.File]::WriteAllText("$fixture/mis-workflow/env/$envName.env",$config.Replace($subject,[guid]::NewGuid().ToString()))
        Reject { & $issuer -Environment $envName -Register }
        Check ([IO.File]::ReadAllText("$target/service.jwt") -eq $second) 'Un rechazo cambio el JWT.'
        [IO.File]::WriteAllText("$fixture/mis-workflow/env/$envName.env",$config)
        [IO.File]::WriteAllText("$target/public.pem",'wrong-public-key')
        Reject { & $issuer -Environment $envName }
        Check ([IO.File]::ReadAllText("$target/service.jwt") -eq $second) 'Clave ajena cambio el JWT.'
        Copy-Item -LiteralPath "$keys/public.pem" -Destination "$target/public.pem"
        $other=[Security.Cryptography.RSA]::Create(2048)
        [IO.File]::WriteAllText("$keys/private.pem",$other.ExportPkcs8PrivateKeyPem())
        Reject { & $issuer -Environment $envName }
        Check ([IO.File]::ReadAllText("$target/service.jwt") -eq $second) 'Par RSA inconsistente cambio el JWT.'
        Check (@(Get-ChildItem -LiteralPath $target | Where-Object Name -notin @('public.pem','service.jwt')).Count -eq 0) 'Material privado o temporal en Workflow.'
        $other.Dispose()
        $rsa.Dispose()
    }
    Write-Output 'Emisor verificado con claves sinteticas: dev, qa, main; firma, identidad, TTL y rechazos.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or
       (Split-Path $resolved -Leaf) -notlike 'mis-issuer-test-*') { throw 'Limpieza fuera del fixture.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
