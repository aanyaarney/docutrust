# ---------------------------------------------------------------------------
# Tamper with a signed PDF, for demonstrations.
#
#   .\scripts\tamper.ps1 "C:\Users\You\Downloads\employment-contract.pdf"
#
# Replaces a salary figure inside the file with one of the SAME LENGTH, so
# every byte offset is preserved. The result is still a perfectly well-formed
# PDF that any reader will open - it simply is no longer the file that was
# signed.
#
# That is the whole point of the demonstration: the forgery is invisible to a
# reader and obvious to a verifier.
# ---------------------------------------------------------------------------

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,

    [string]$Find    = '800,000',
    [string]$Replace = '900,000',

    [string]$OutPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Path)) {
    throw "File not found: $Path"
}

if ($Find.Length -ne $Replace.Length) {
    throw "The replacement must be the same length as the text being replaced, " +
          "otherwise every byte offset after it shifts and the PDF structure breaks. " +
          "'$Find' is $($Find.Length) characters, '$Replace' is $($Replace.Length)."
}

if (-not $OutPath) {
    $directory = Split-Path -Parent (Resolve-Path $Path)
    $name      = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $OutPath   = Join-Path $directory "$name-TAMPERED.pdf"
}

$bytes       = [System.IO.File]::ReadAllBytes($Path)
$findBytes   = [System.Text.Encoding]::ASCII.GetBytes($Find)
$replaceBytes = [System.Text.Encoding]::ASCII.GetBytes($Replace)

# Locate the text in the raw file bytes.
$index = -1
for ($i = 0; $i -le $bytes.Length - $findBytes.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $findBytes.Length; $j++) {
        if ($bytes[$i + $j] -ne $findBytes[$j]) { $match = $false; break }
    }
    if ($match) { $index = $i; break }
}

if ($index -lt 0) {
    Write-Host ''
    Write-Host "Could not find '$Find' in that file." -ForegroundColor Yellow
    Write-Host 'Two common reasons:' -ForegroundColor Yellow
    Write-Host '  - The PDF compresses its text, so the words are not readable in the raw bytes.'
    Write-Host '    The sample contracts in .\samples are written uncompressed so this works.'
    Write-Host '  - The document simply does not contain that text. Try -Find with something else.'
    exit 1
}

$tampered = $bytes.Clone()
[Array]::Copy($replaceBytes, 0, $tampered, $index, $replaceBytes.Length)
[System.IO.File]::WriteAllBytes($OutPath, $tampered)

Write-Host ''
Write-Host ('=' * 68) -ForegroundColor DarkGray
Write-Host '  DOCUMENT ALTERED' -ForegroundColor Red
Write-Host ('=' * 68) -ForegroundColor DarkGray
Write-Host "  Changed      : '$Find'  ->  '$Replace'"
Write-Host "  At byte      : $index"
Write-Host "  Original size: $($bytes.Length) bytes"
Write-Host "  New size     : $($tampered.Length) bytes  (identical, by design)"
Write-Host ''
Write-Host "  Saved to     : $OutPath" -ForegroundColor Cyan
Write-Host ''
Write-Host '  Now upload this file on the Verify page.' -ForegroundColor Cyan
Write-Host '  It will open normally in any PDF reader - and fail verification.'
Write-Host ('=' * 68) -ForegroundColor DarkGray
