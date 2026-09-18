# ---------------------------------------------------------------------------
# DocuTrust end-to-end demonstration against a running backend.
#
#   Upload -> Sign -> Download -> Verify (VALID)
#          -> Tamper -> Verify (TAMPERED)
#          -> Audit chain integrity
#
# Usage:  .\scripts\demo-flow.ps1
# Requires the backend running on http://localhost:8080.
#
# Uses System.Net.Http directly because Windows PowerShell 5.1 has no -Form
# parameter for multipart uploads.
# ---------------------------------------------------------------------------

param(
    [string]$BaseUrl  = 'http://localhost:8080/api/v1',
    [string]$Email    = 'demo@docutrust.local',
    [string]$Password = $env:DOCUTRUST_DEMO_USER_PASSWORD,
    [string]$SamplePdf = "$PSScriptRoot\..\samples\employment-contract-sample.pdf"
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

function Write-Step($text) {
    Write-Host ''
    Write-Host ('-' * 70) -ForegroundColor DarkGray
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ('-' * 70) -ForegroundColor DarkGray
}

function Invoke-Upload {
    param($Url, $Token, [byte[]]$Bytes, $FileName)

    $client  = New-Object System.Net.Http.HttpClient
    $client.DefaultRequestHeaders.Authorization =
        New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $Token)

    $content  = New-Object System.Net.Http.MultipartFormDataContent
    $filePart = New-Object System.Net.Http.ByteArrayContent(, $Bytes)
    $filePart.Headers.ContentType =
        [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/pdf')
    $content.Add($filePart, 'file', $FileName)

    $response = $client.PostAsync($Url, $content).Result
    $body     = $response.Content.ReadAsStringAsync().Result
    $client.Dispose()

    if (-not $response.IsSuccessStatusCode) {
        throw "Request to $Url failed: $($response.StatusCode) $body"
    }
    return $body | ConvertFrom-Json
}

# --------------------------------------------------------------- 1. Sign in
Write-Step '1. Authenticating'

if (-not $Password) {
    throw 'Set DOCUTRUST_DEMO_USER_PASSWORD, or pass -Password.'
}

$login = Invoke-RestMethod -Uri "$BaseUrl/auth/login" -Method Post `
    -ContentType 'application/json' `
    -Body (@{ email = $Email; password = $Password } | ConvertTo-Json)

$token   = $login.token
$headers = @{ Authorization = "Bearer $token" }
Write-Host "  Signed in as $($login.email) with role $($login.role)" -ForegroundColor Green

# --------------------------------------------------------------- 2. Upload
Write-Step '2. Uploading the employment contract'

$originalBytes = [System.IO.File]::ReadAllBytes($SamplePdf)
$document = Invoke-Upload "$BaseUrl/documents" $token $originalBytes 'employment-contract.pdf'

Write-Host "  Document ID : $($document.id)"
Write-Host "  Pages       : $($document.pageCount)"
Write-Host "  Size        : $($document.sizeBytes) bytes"
Write-Host "  SHA-256     : $($document.sha256)" -ForegroundColor Yellow
Write-Host "  State       : $($document.signatureState)"

# ----------------------------------------------------------------- 3. Sign
Write-Step '3. Applying a PAdES digital signature'

$signBody = @{
    reason            = 'I approve this employment agreement'
    location          = 'Bengaluru, IN'
    signerDisplayName = 'Demo Signer'
} | ConvertTo-Json

$signature = Invoke-RestMethod -Uri "$BaseUrl/documents/$($document.id)/sign" -Method Post `
    -Headers $headers -ContentType 'application/json' -Body $signBody

Write-Host "  Signer      : $($signature.signerCommonName)"
Write-Host "  Subject     : $($signature.certificateSubject)"
Write-Host "  Issuer      : $($signature.certificateIssuer)"
Write-Host "  Serial      : $($signature.certificateSerialNumber)"
Write-Host "  Algorithm   : $($signature.signatureAlgorithm)"
Write-Host "  Digest      : $($signature.digestAlgorithm)"
Write-Host "  Format      : $($signature.signatureFormat)" -ForegroundColor Green
Write-Host "  Provider    : $($signature.providerName)"

# ------------------------------------------------------------- 4. Download
Write-Step '4. Downloading the signed PDF'

$signedPath = Join-Path $env:TEMP 'docutrust-signed.pdf'
Invoke-WebRequest -Uri "$BaseUrl/documents/$($document.id)/download" `
    -Headers $headers -OutFile $signedPath | Out-Null

$signedBytes = [System.IO.File]::ReadAllBytes($signedPath)
Write-Host "  Signed PDF  : $($signedBytes.Length) bytes (original was $($originalBytes.Length))"

# --------------------------------------------------------------- 5. Verify
Write-Step '5. Verifying the untouched signed document'

$verified = Invoke-Upload "$BaseUrl/verification" $token $signedBytes 'signed.pdf'
$sig = $verified.signatures[0]

Write-Host "  Verdict     : $($verified.verdict)" -ForegroundColor Green
Write-Host "  Headline    : $($verified.headline)"
Write-Host "  Integrity   : $($sig.integrity)"
Write-Host "  Signature   : $($sig.signature)"
Write-Host "  Certificate : $($sig.certificate.status)"
Write-Host "  Chain       : $($sig.certificate.chainStatus)"
Write-Host "  Revocation  : $($sig.certificate.revocationStatus)" -ForegroundColor Yellow
Write-Host "  Timestamp   : $($sig.timestamp)" -ForegroundColor Yellow
Write-Host "  ByteRange   : $($sig.byteRange -join ', ')"

# --------------------------------------------------------------- 6. Tamper
Write-Step '6. Altering the salary in the signed PDF, then verifying again'

$target      = [System.Text.Encoding]::ASCII.GetBytes('800,000')
$replacement = [System.Text.Encoding]::ASCII.GetBytes('900,000')

$index = -1
for ($i = 0; $i -le $signedBytes.Length - $target.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $target.Length; $j++) {
        if ($signedBytes[$i + $j] -ne $target[$j]) { $match = $false; break }
    }
    if ($match) { $index = $i; break }
}

if ($index -lt 0) { throw 'Could not locate the salary figure in the signed PDF.' }

$tampered = $signedBytes.Clone()
[Array]::Copy($replacement, 0, $tampered, $index, $replacement.Length)

Write-Host "  Changed 'INR 800,000' to 'INR 900,000' at byte offset $index"
Write-Host "  File size is unchanged: $($tampered.Length) bytes"

$tamperResult = Invoke-Upload "$BaseUrl/verification" $token $tampered 'tampered.pdf'
$tsig = $tamperResult.signatures[0]

Write-Host ''
Write-Host "  Verdict     : $($tamperResult.verdict)" -ForegroundColor Red
Write-Host "  Headline    : $($tamperResult.headline)"
Write-Host "  Integrity   : $($tsig.integrity)" -ForegroundColor Red
Write-Host "  Signature   : $($tsig.signature)" -ForegroundColor Red
Write-Host "  Certificate : $($tsig.certificate.status)" -ForegroundColor Green
Write-Host "  Chain       : $($tsig.certificate.chainStatus)" -ForegroundColor Green
Write-Host "  Class       : $($tsig.tamperAnalysis.modificationType)"
Write-Host "  Proven      : $($tsig.tamperAnalysis.cryptographicallyProven)"

# ---------------------------------------------------------------- 7. Audit
Write-Step '7. Audit trail and chain integrity'

$audit = Invoke-RestMethod -Uri "$BaseUrl/documents/$($document.id)/audit" -Headers $headers
Write-Host "  Events recorded for this document: $($audit.Count)"
foreach ($event in $audit) {
    Write-Host ("    #{0}  {1,-22} {2}" -f $event.sequence, $event.eventType, $event.details)
}

$summary = Invoke-RestMethod -Uri "$BaseUrl/dashboard/summary" -Headers $headers
Write-Host ''
Write-Host "  Audit chain intact : $($summary.auditChainIntact)" -ForegroundColor Green
Write-Host "  $($summary.auditChainExplanation)"
Write-Host "  Signing material   : $($summary.signingMaterialDescription)"
Write-Host "  Development PKI    : $($summary.developmentPki)" -ForegroundColor Yellow
Write-Host "  Tampering detected : $($summary.tamperingDetected)"

Write-Host ''
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Host '  Demonstration complete.' -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor DarkGray
