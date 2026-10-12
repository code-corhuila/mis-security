$ErrorActionPreference='Stop'
$source=Join-Path (Split-Path $PSScriptRoot) 'scripts/Issue-EventServiceToken.ps1'
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('mis-event-issuer-test-'+[guid]::NewGuid().ToString('N'))
function Check($condition,$message) { if(-not $condition) { throw $message } }
function Reject($action) {
    $failed=$false
    try { & $action | Out-Null } catch { $failed=$true }
    Check $failed 'Se esperaba rechazo.'
}
function Decode($value) { [Convert]::FromBase64String($value.Replace('-','+').Replace('_','/')+('='*((4-$value.Length%4)%4))) }
New-Item -ItemType Directory -Path "$fixture/mis-security/scripts","$fixture/mis-security/env" -Force | Out-Null
Copy-Item -LiteralPath $source -Destination "$fixture/mis-security/scripts/Issue-EventServiceToken.ps1"
$issuer="$fixture/mis-security/scripts/Issue-EventServiceToken.ps1"
$subjects=@()
try {
    foreach($envName in @('dev','qa','main')) {
        $suffix=if($envName -eq 'dev') { '' } else { "/$envName" }
        $keys="$fixture/mis-security/secrets$suffix"
        New-Item -ItemType Directory -Force -Path $keys | Out-Null
        $rsa=[Security.Cryptography.RSA]::Create(2048)
        try {
            [IO.File]::WriteAllText("$keys/private.pem",$rsa.ExportPkcs8PrivateKeyPem())
            [IO.File]::WriteAllText("$keys/public.pem",$rsa.ExportSubjectPublicKeyInfoPem())
            [IO.File]::WriteAllText("$fixture/mis-security/env/$envName.env","SECURITY_KEY_ID=key-$envName`n")
            foreach($service in @('mis-worker','mis-inventory-relay')) {
                $subject=[guid]::NewGuid().ToString()
                $subjects+=$subject
                $destination=if($service -eq 'mis-worker') { 'mis-worker' } else { 'mis-inventory-api' }
                $target="$fixture/$destination/secrets/$envName/$service"
                $arguments=@{Service=$service;Subject=$subject;Environment=$envName}
                Reject { & $issuer @arguments }
                & $issuer @arguments -Register -Ttl 60 | Out-Null
                $first=[IO.File]::ReadAllText("$target/service.jwt")
                & $issuer @arguments -Ttl 3600 | Out-Null
                $second=[IO.File]::ReadAllText("$target/service.jwt")
                Check ($first -ne $second) 'Renovacion debe cambiar jti.'
                $parts=$second.Split('.')
                $header=[Text.Encoding]::UTF8.GetString((Decode $parts[0])) | ConvertFrom-Json
                $claims=[Text.Encoding]::UTF8.GetString((Decode $parts[1])) | ConvertFrom-Json
                $audience=if($service -eq 'mis-worker') { 'mis-api' } else { 'mis-events' }
                $roleCount=if($service -eq 'mis-worker') { 1 } else { 0 }
                Check ($claims.sub -eq $subject -and $claims.service -eq $service -and
                    $claims.environment -eq $envName -and $claims.iss -eq 'mis-security' -and
                    $claims.aud -eq $audience -and @($claims.roles).Count -eq $roleCount -and
                    $claims.exp-$claims.iat -eq 3600 -and $header.kid -eq "key-$envName" -and
                    $header.alg -eq 'RS256') 'Claims incorrectos.'
                if($roleCount) { Check ($claims.roles[0] -eq 'INVENTORY') 'Rol incorrecto.' }
                Check ($rsa.VerifyData([Text.Encoding]::UTF8.GetBytes($parts[0]+'.'+$parts[1]),(Decode $parts[2]),
                    [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'Firma incorrecta.'
                Reject { & $issuer @arguments -Ttl 3601 }
                Reject { & $issuer -Service $service -Subject ([guid]::NewGuid().ToString()) -Environment $envName -Register }
                [IO.File]::WriteAllText("$target/public.pem",'wrong-public-key')
                Reject { & $issuer @arguments }
                Copy-Item -LiteralPath "$keys/public.pem" -Destination "$target/public.pem"
                [IO.File]::WriteAllText("$target/private.pem",'unexpected')
                Reject { & $issuer @arguments }
                Remove-Item -LiteralPath "$target/private.pem"
                [IO.File]::WriteAllText("$fixture/mis-security/env/$envName.env",'')
                Reject { & $issuer @arguments }
                [IO.File]::WriteAllText("$fixture/mis-security/env/$envName.env","SECURITY_KEY_ID=key-$envName`n")
                $weak=[Security.Cryptography.RSA]::Create(1024)
                try {
                    [IO.File]::WriteAllText("$keys/private.pem",$weak.ExportPkcs8PrivateKeyPem())
                    [IO.File]::WriteAllText("$keys/public.pem",$weak.ExportSubjectPublicKeyInfoPem())
                    Copy-Item -LiteralPath "$keys/public.pem" -Destination "$target/public.pem"
                    Reject { & $issuer @arguments }
                } finally { $weak.Dispose() }
                [IO.File]::WriteAllText("$keys/public.pem",$rsa.ExportSubjectPublicKeyInfoPem())
                Copy-Item -LiteralPath "$keys/public.pem" -Destination "$target/public.pem"
                $other=[Security.Cryptography.RSA]::Create(2048)
                try { [IO.File]::WriteAllText("$keys/private.pem",$other.ExportPkcs8PrivateKeyPem()) } finally { $other.Dispose() }
                Reject { & $issuer @arguments }
                [IO.File]::WriteAllText("$keys/private.pem",$rsa.ExportPkcs8PrivateKeyPem())
                Check ([IO.File]::ReadAllText("$target/service.jwt") -eq $second) 'Rechazo cambio el JWT.'
                Check (@(Get-ChildItem -LiteralPath $target | Where-Object Name -notin @('public.pem','service.jwt')).Count -eq 0) 'Material privado o temporal exportado.'
            }
            Reject { & $issuer -Service mis-worker -Subject ([guid]::Empty.ToString()) -Environment $envName -Register }
        } finally { $rsa.Dispose() }
    }
    # Intento de registrar una identidad dev como relay en otro ambiente sin registro previo.
    Remove-Item -LiteralPath "$fixture/mis-security/secrets/main/mis-inventory-relay-identity.json"
    Reject { & $issuer -Service mis-inventory-relay -Subject $subjects[0] -Environment main -Register }
    Check (-not (Test-Path "$fixture/mis-security/secrets/main/mis-inventory-relay-identity.json")) 'Rechazo registro una identidad.'
    Write-Output 'Emisor de eventos verificado: seis identidades, firma RSA, TTL, renovacion y rechazos.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path $resolved -Leaf) -notlike 'mis-event-issuer-test-*') { throw 'Limpieza fuera del fixture.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
