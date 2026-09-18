# ---------------------------------------------------------------------------
# DocuTrust - development environment bootstrap (Windows / PowerShell)
#
# Dot-source this before running builds in a fresh shell:
#     . .\scripts\env.ps1
#
# Needed because Windows installers update the machine environment block, but
# already-running shells (and their children) keep the stale copy until restart.
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'

# Refresh PATH from the registry (machine + user)
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
            [Environment]::GetEnvironmentVariable('Path', 'User')

# JAVA_HOME - prefer the persisted value, otherwise discover a JDK 21
if (-not $env:JAVA_HOME -or -not (Test-Path $env:JAVA_HOME)) {
    $candidate = Get-ChildItem 'C:\Program Files\Microsoft' -Directory -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like 'jdk-21*' } |
                 Sort-Object Name -Descending |
                 Select-Object -First 1
    if ($candidate) { $env:JAVA_HOME = $candidate.FullName }
}

Write-Host 'DocuTrust dev environment' -ForegroundColor Cyan
Write-Host ("  JAVA_HOME : {0}" -f $env:JAVA_HOME)

foreach ($tool in 'java', 'mvn', 'node', 'npm', 'git') {
    $cmd = Get-Command $tool -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Host ("  {0,-9}: {1}" -f $tool, $cmd.Source) -ForegroundColor Green
    } else {
        Write-Host ("  {0,-9}: NOT FOUND" -f $tool) -ForegroundColor Red
    }
}
