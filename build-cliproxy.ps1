$ErrorActionPreference = "Stop"

# ---- helpers ----
function Get-Sha256Hex([string]$s) {
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
    $hash  = $sha.ComputeHash($bytes)
    -join ($hash | ForEach-Object { $_.ToString("x2") })
}

function Decode-JwtPayload([string]$jwt) {
    $p = $jwt.Split('.')[1]
    switch ($p.Length % 4) { 2 {$p += '=='} 3 {$p += '='} }
    $json = [System.Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($p.Replace('-','+').Replace('_','/')))
    $json | ConvertFrom-Json
}

# ---- load source account ----
$inPath = "h:\Tải\json\kiro-accounts-2026-06-19.json"
$acc = (Get-Content -Raw -Path $inPath | ConvertFrom-Json)[0]
Write-Host "Account:" $acc.email

# ---- step 1: refresh -> access_token ----
Write-Host "[1/3] Refreshing token at Microsoft ..."
$tokResp = Invoke-RestMethod -Method Post -Uri $acc.tokenEndpoint `
    -ContentType "application/x-www-form-urlencoded" -Body @{
        grant_type    = "refresh_token"
        client_id     = $acc.clientId
        refresh_token = $acc.refreshToken
        scope         = $acc.scopes
    }
$accessToken  = $tokResp.access_token
$refreshToken = if ($tokResp.refresh_token) { $tokResp.refresh_token } else { $acc.refreshToken }
$expiresIn    = [int]$tokResp.expires_in
$claims       = Decode-JwtPayload $accessToken
$issuerUrl    = $claims.iss
$username     = if ($claims.preferred_username) { $claims.preferred_username } else { $acc.email }
Write-Host "      access_token OK, user:" $username

# ---- step 2: ListAvailableProfiles -> profile_arn ----
Write-Host "[2/3] Resolving profile ARN (TokenType: EXTERNAL_IDP) ..."
$region    = "us-east-1"
$kiroVer   = "0.10.32"
$machineId = Get-Sha256Hex $accessToken
$invId     = Get-Sha256Hex ("$accessToken|$region|list-profiles")
$ua        = "aws-sdk-js/1.0.0 ua/2.1 os/windows#10.0.26200 lang/js md/nodejs#22.21.1 api/codewhispererruntime#1.0.0 m/N,E KiroIDE-$kiroVer-$machineId"
$xamzUa    = "aws-sdk-js/1.0.0 KiroIDE-$kiroVer-$machineId"

$headers = @{
    "Accept"                       = "application/x-amz-json-1.0"
    "Authorization"                = "Bearer $accessToken"
    "X-Amz-Target"                 = "AmazonCodeWhispererService.ListAvailableProfiles"
    "amz-sdk-invocation-id"        = $invId
    "amz-sdk-request"              = "attempt=1; max=1"
    "x-amzn-kiro-agent-mode"       = "vibe"
    "x-amzn-codewhisperer-optout"  = "true"
    "x-amz-user-agent"             = $xamzUa
    "TokenType"                    = "EXTERNAL_IDP"
}
$cwUrl = "https://codewhisperer.$region.amazonaws.com/"
$profResp = Invoke-RestMethod -Method Post -Uri $cwUrl -Headers $headers `
    -UserAgent $ua -ContentType "application/x-amz-json-1.0" -Body "{}"

$profileArn = ($profResp.profiles | Where-Object { $_.arn } | Select-Object -First 1).arn
if (-not $profileArn) { throw "Khong tim thay profile ARN (tai khoan chua duoc cap quyen Kiro?)" }
Write-Host "      profile_arn:" $profileArn

# region tu ARN neu co
$arnParts = $profileArn.Split(':')
if ($arnParts.Length -ge 4 -and $arnParts[3]) { $region = $arnParts[3] }

# ---- step 3: assemble CLIProxyAPI json ----
Write-Host "[3/3] Writing CLIProxyAPI json ..."
$expiredUtc = (Get-Date).ToUniversalTime().AddSeconds($expiresIn).ToString("yyyy-MM-ddTHH:mm:ssZ")
$timestamp  = [long]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())

$obj = [ordered]@{
    access_token   = $accessToken
    auth_method    = "external_idp"
    client_id      = $acc.clientId
    disabled       = $false
    expired        = $expiredUtc
    issuer_url     = $issuerUrl
    profile_arn    = $profileArn
    refresh_token  = $refreshToken
    region         = $region
    scopes         = $acc.scopes
    timestamp      = $timestamp
    token_endpoint = $acc.tokenEndpoint
    type           = "kiro"
}

$safeName = ($username -replace '[^A-Za-z0-9._-]', '-').Trim('-')
$outPath  = "h:\Tải\json\CLIProxyAPI_$safeName.json"
$obj | ConvertTo-Json -Depth 5 | Set-Content -Path $outPath -Encoding UTF8

Write-Host "----------------------------------------"
Write-Host "DONE. Saved:" $outPath
