# SPDX-License-Identifier: AGPL-3.0-only
param([Parameter(Mandatory)][string]$WorkerManifest)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Only the guarded hosted fixture invokes this immutable bootstrap. Do not
# echo arguments, exception objects or environment values on failure.
try {
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or $env:ImageOS -cnotin @('win25','win25-vs2026')){throw 'Unsupported fixture.'}
    $root=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($WorkerManifest))
    if(-not [IO.Path]::IsPathFullyQualified($WorkerManifest) -or $root -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetFileName($root) -notmatch '^zrotext-native-[a-f0-9]{32}$' -or [IO.Path]::GetFileName($WorkerManifest) -cne 'manifest.json'){throw 'Invalid fixture.'}
    $worker=Join-Path $root 'bin/windows_native_ci.ps1'
    $marker=Join-Path $root 'results/bootstrap-stage.txt'
    foreach($path in @($WorkerManifest,$worker,$marker)) {
        $cursor=$path
        while($cursor) {
            if(Test-Path -LiteralPath $cursor) {
                if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse fixture.'}
            }
            $cursor=[IO.Path]::GetDirectoryName($cursor)
        }
    }
    if([IO.Path]::GetFullPath($PSScriptRoot) -cne (Join-Path $root 'bin')){throw 'Wrong bootstrap location.'}
    [IO.File]::WriteAllText($marker,'bootstrap-entered')
    & $worker -WorkerManifest $WorkerManifest
    exit $LASTEXITCODE
} catch {
    exit 1
}
