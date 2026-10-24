# ---------------------------------------------------------------------------
# Bundle the backend source into one document.
#
#   .\scripts\bundle-source.ps1                 # backend main + resources
#   .\scripts\bundle-source.ps1 -IncludeTests   # add the test suite
#   .\scripts\bundle-source.ps1 -Frontend       # frontend instead
#
# Produces a single Markdown file with a contents list and every source file
# under a path heading, grouped by module. Intended for project reports and
# printed submissions, where a reader needs the code in reading order rather
# than as a directory tree.
# ---------------------------------------------------------------------------

param(
    [switch]$IncludeTests,
    [switch]$Frontend,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot

if ($Frontend) {
    $roots   = @("$projectRoot\frontend\src")
    $include = '*.ts', '*.tsx'
    $title   = 'DocuTrust - Frontend Source Code'
    if (-not $OutFile) { $OutFile = "$projectRoot\frontend-source-code.md" }
} else {
    $roots = @("$projectRoot\backend\src\main")
    if ($IncludeTests) { $roots += "$projectRoot\backend\src\test" }
    $include = '*.java', '*.yml', '*.sql', '*.xml'
    $title   = 'DocuTrust - Backend Source Code'
    if (-not $OutFile) { $OutFile = "$projectRoot\backend-source-code.md" }
}

$files = foreach ($root in $roots) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Recurse -File -Include $include
    }
}

# Sort so related classes sit together: by directory, then by name.
$files = $files | Sort-Object DirectoryName, Name

if (-not $Frontend) {
    # Include the build file first; a reader wants dependencies up front.
    $pom = Get-Item "$projectRoot\backend\pom.xml" -ErrorAction SilentlyContinue
    if ($pom) { $files = @($pom) + $files }
}

$builder = [System.Text.StringBuilder]::new()
$null = $builder.AppendLine("# $title")
$null = $builder.AppendLine()
$null = $builder.AppendLine("Generated $(Get-Date -Format 'd MMMM yyyy')")
$null = $builder.AppendLine()
$null = $builder.AppendLine("Repository: https://github.com/aanyaarney/docutrust")
$null = $builder.AppendLine()

$totalLines = 0
foreach ($file in $files) {
    $totalLines += (Get-Content $file.FullName | Measure-Object -Line).Lines
}

$null = $builder.AppendLine("**$($files.Count) files, $('{0:N0}' -f $totalLines) lines**")
$null = $builder.AppendLine()
$null = $builder.AppendLine('---')
$null = $builder.AppendLine()

# ----------------------------- contents -----------------------------------
$null = $builder.AppendLine('## Contents')
$null = $builder.AppendLine()

$index = 1
foreach ($file in $files) {
    $relative = $file.FullName.Substring($projectRoot.Length + 1).Replace('\', '/')
    $null = $builder.AppendLine("$index. ``$relative``")
    $index++
}

$null = $builder.AppendLine()
$null = $builder.AppendLine('---')
$null = $builder.AppendLine()

# ------------------------------ sources ------------------------------------
$index = 1
$lastDirectory = ''

foreach ($file in $files) {
    $relative  = $file.FullName.Substring($projectRoot.Length + 1).Replace('\', '/')
    $directory = Split-Path $relative -Parent

    # A heading whenever the package changes, so the document has structure.
    if ($directory -ne $lastDirectory) {
        $null = $builder.AppendLine()
        $null = $builder.AppendLine("## $directory")
        $null = $builder.AppendLine()
        $lastDirectory = $directory
    }

    $language = switch ($file.Extension) {
        '.java' { 'java' }
        '.ts'   { 'typescript' }
        '.tsx'  { 'tsx' }
        '.sql'  { 'sql' }
        '.yml'  { 'yaml' }
        '.xml'  { 'xml' }
        default { '' }
    }

    $lineCount = (Get-Content $file.FullName | Measure-Object -Line).Lines

    $null = $builder.AppendLine("### $index. $($file.Name)")
    $null = $builder.AppendLine()
    $null = $builder.AppendLine("``$relative`` - $lineCount lines")
    $null = $builder.AppendLine()
    $null = $builder.AppendLine('```' + $language)
    $null = $builder.AppendLine((Get-Content $file.FullName -Raw).TrimEnd())
    $null = $builder.AppendLine('```')
    $null = $builder.AppendLine()

    $index++
}

[System.IO.File]::WriteAllText($OutFile, $builder.ToString())

Write-Host ''
Write-Host ('=' * 66) -ForegroundColor DarkGray
Write-Host '  SOURCE BUNDLE CREATED' -ForegroundColor Cyan
Write-Host ('=' * 66) -ForegroundColor DarkGray
Write-Host ("  Files  : {0}" -f $files.Count)
Write-Host ("  Lines  : {0:N0}" -f $totalLines)
Write-Host ("  Size   : {0:N0} KB" -f ((Get-Item $OutFile).Length / 1KB))
Write-Host ("  Output : {0}" -f $OutFile) -ForegroundColor Cyan
Write-Host ('=' * 66) -ForegroundColor DarkGray
