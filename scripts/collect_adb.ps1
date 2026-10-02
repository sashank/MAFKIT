param(
  [string]$Out = "adb-acquisition",
  [string]$Package = ""
)
$ErrorActionPreference = "Stop"
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) { throw "adb not found. Install Android SDK Platform-Tools and add adb to PATH." }
$argsList = @("-m","mafkit.cli","collect-adb","-o",$Out)
if ($Package) { $argsList += @("--package",$Package) }
& python @argsList
Write-Host "ADB acquisition saved to: $Out"
