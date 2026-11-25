# Builds the Lambda for AWS (Linux, ARM64) from Windows PowerShell.
# Run from anywhere:  powershell -ExecutionPolicy Bypass -File scripts\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    New-Item -ItemType Directory -Force -Path build | Out-Null
    $env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
    go build -tags lambda.norpc -trimpath -ldflags "-s -w" -o build/bootstrap .
    if ($LASTEXITCODE -ne 0) { throw "go build failed" }
    Write-Host "OK: built build/bootstrap (Terraform zips it during apply)"
}
finally {
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}
