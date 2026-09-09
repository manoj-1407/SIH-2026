$src = 'D:\SIH_FINAL_v5'
$dest = 'D:\SIH_FINAL_v5\SIH_2026_SUBMISSION_v2.zip'

# Remove old zip if exists
if (Test-Path $dest) { Remove-Item $dest -Force }

# Exclusion rules
$excludeDirs  = @('.git', '__pycache__', '.pytest_cache', '.mypy_cache', 'node_modules', '.venv', 'venv')
$excludeExts  = @('.priv', '.key', '.pem', '.raw', '.img', '.jsonl', '.env', '.pyc')
$excludeNames = @('SIH_2026_FINAL_SUBMISSION_PACKAGE.zip', 'SIH_2026_SUBMISSION_v2.zip', 'benchmark_results.json', 'make_zip.ps1')

# Walk and filter
$files = Get-ChildItem -Path $src -Recurse -File | Where-Object {
    $path = $_.FullName
    $rel  = $path.Substring($src.Length + 1)  # relative to root

    # Exclude paths containing excluded directory names as path components
    $inExcludeDir = $false
    foreach ($d in $excludeDirs) {
        $parts = $rel -split '\\'
        if ($parts -contains $d) {
            $inExcludeDir = $true
            break
        }
    }
    if ($inExcludeDir) { return $false }

    # Exclude by extension
    if ($excludeExts -contains $_.Extension.ToLower()) { return $false }

    # Exclude specific filenames
    if ($excludeNames -contains $_.Name) { return $false }

    return $true
}

Write-Host "Collected $($files.Count) files to zip..."

# Create zip using .NET
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($dest, 'Create')

foreach ($f in $files) {
    $rel = $f.FullName.Substring($src.Length + 1)
    [void]$zip.CreateEntryFromFile($f.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal)
}

$zip.Dispose()

$sizeKB = [math]::Round((Get-Item $dest).Length / 1KB, 1)
Write-Host "Done! ZIP: $dest"
Write-Host "Size: $sizeKB KB | Files included: $($files.Count)"
