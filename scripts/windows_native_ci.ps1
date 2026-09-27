# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding(DefaultParameterSetName='Inspect')]
param(
    [Parameter(ParameterSetName='SelfTest',Mandatory)][switch]$SelfTest,
    [Parameter(ParameterSetName='Compile',Mandatory)][switch]$CompileOnly,
    [Parameter(ParameterSetName='Provision',Mandatory)][switch]$ProvisionEphemeralGithubHostedAccount,
    [Parameter(ParameterSetName='Worker',Mandatory)][string]$WorkerManifest
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$workerStages=@('worker-start','worker-manifest','worker-ownership','worker-helper-compile','worker-eligibility','worker-test-prepare','worker-test-launch','worker-test-wait','worker-test-output','worker-test-result','worker-results','worker-cleanup','worker-complete','worker-failed')

function Write-WorkerCheckpoint([string]$Value) {
    if($Value -cnotin $workerStages){throw 'Unknown worker checkpoint.'}
    $script:workerStage=$Value
    [IO.File]::WriteAllText($script:checkpointPath,$Value)
}

function Assert-CiHost([hashtable]$Values) {
    foreach($pair in @(@('GITHUB_ACTIONS','true'),@('RUNNER_ENVIRONMENT','github-hosted'),@('RUNNER_OS','Windows'))) {
        $script:stage='host-field-'+$pair[0]
        if($Values[$pair[0]] -cne $pair[1]) {throw 'Disposable hosted Windows fixture required.'}
    }
    $script:stage='host-field-ImageOS'
    if($Values['ImageOS'] -cnotin @('win25','win25-vs2026')) {throw 'Unsupported hosted Windows image.'}
}
function Quote-FixedArgument([string]$Value) {
    if([string]::IsNullOrEmpty($Value) -or $Value.IndexOfAny([char[]]@([char]0,[char]10,[char]13,[char]34)) -ge 0 -or $Value.EndsWith('\')) {throw 'Unsupported fixed argument.'}
    return '"'+$Value+'"'
}
function Assert-PlainPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if(-not [IO.Path]::IsPathFullyQualified($Path) -or $full -notmatch '^[A-Za-z]:\\' -or $full.StartsWith('\\')) {throw 'Unsupported fixture path.'}
    $cursor=$full
    while($cursor) {
        if(Test-Path -LiteralPath $cursor) {
            if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Fixture path contains a reparse point.'}
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}
function Assert-ChildPath([string]$Path,[string]$Parent) {
    $full=Assert-PlainPath $Path
    $root=(Assert-PlainPath $Parent).TrimEnd('\')+'\'
    if(-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) {throw 'Fixture path escapes parent.'}
    return $full
}
function Select-TestArtifacts([object[]]$Records,[string]$TargetRoot,[hashtable]$PackageIds) {
    $wanted=@{'zrotext_root_bundle'=20;'zrotext_root_terminal'=25;'zrotext-owner'=2}
    $selected=@{}
    foreach($record in $Records) {
        if($record.reason -ne 'compiler-artifact') {continue}
        if(-not $record.profile.test -or -not $record.executable) {continue}
        $name=[string]$record.target.name
        if(-not $wanted.ContainsKey($name)) {continue}
        if($record.package_id -cne $PackageIds[$name]) {throw 'Unexpected native artifact package.'}
        if($selected.ContainsKey($name)) {throw 'Duplicate native test artifact.'}
        $path=Assert-ChildPath ([string]$record.executable) $TargetRoot
        if([IO.Path]::GetExtension($path) -cne '.exe' -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {throw 'Invalid native test executable.'}
        $selected[$name]=@{Name=$name;Source=$path;Passed=$wanted[$name]}
    }
    if($selected.Count -ne 3) {throw 'Expected exactly three native test executables.'}
    return @($selected.Values | Sort-Object Name)
}
function Set-FixtureAcl([string]$Path,[Security.Principal.SecurityIdentifier]$Owner,[Security.Principal.SecurityIdentifier]$FixtureSid,[bool]$Writable) {
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($Owner)
    $inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $prop=[Security.AccessControl.PropagationFlags]::None
    foreach($sid in @([Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,$prop,'Allow'))
    }
    $rights=if($Writable){'FullControl'}else{'ReadAndExecute'}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($FixtureSid,$rights,$inherit,$prop,'Allow'))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-NoReparseDescendants([string]$Root) {
    $pending=[Collections.Generic.Stack[string]]::new();$pending.Push((Assert-PlainPath $Root))
    while($pending.Count) {
        foreach($item in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse entry prevents cleanup.'}
            if($item.PSIsContainer){$pending.Push($item.FullName)}
        }
    }
}
function Test-PureGuards {
    $parseTokens=$null;$parseErrors=$null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows_native_ci_bootstrap.ps1'),[ref]$parseTokens,[ref]$parseErrors) | Out-Null
    if($parseErrors.Count){throw 'Bootstrap syntax regression.'}
    $good=@{GITHUB_ACTIONS='true';RUNNER_ENVIRONMENT='github-hosted';RUNNER_OS='Windows';ImageOS='win25'}
    Assert-CiHost $good
    $variant=$good.Clone();$variant.ImageOS='win25-vs2026';Assert-CiHost $variant
    foreach($key in @($good.Keys)) {
        $bad=$good.Clone();$bad[$key]='unsupported';$rejected=$false
        try{Assert-CiHost $bad}catch{$rejected=$true}
        if(-not $rejected){throw 'Host refusal regression.'}
    }
    if((Quote-FixedArgument 'fixture with spaces\suite.exe') -cne '"fixture with spaces\suite.exe"'){throw 'Quoting regression.'}
    foreach($value in @('',"bad`nvalue",'bad"value','trailing\',("bad"+[char]0))) {
        $rejected=$false;try{Quote-FixedArgument $value | Out-Null}catch{$rejected=$true}
        if(-not $rejected){throw 'Argument refusal regression.'}
    }
    # Validation fixtures only: empty temporary files, never executable launch,
    # local accounts, credentials, ACL changes or native helper invocation.
    if($IsWindows) {
        Add-Type -Path (Join-Path $PSScriptRoot 'windows_native_ci.cs')
        [ZrotextCi.Native]::TestAclFilter()
        [ZrotextCi.Native]::TestDiagnostics()
        $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
        $root=Join-Path $temp ('zrotext-ci-guards-'+[Guid]::NewGuid().ToString('N'))
        $created=@();$junction=$null
        [IO.Directory]::CreateDirectory($root) | Out-Null
        try {
            $script:checkpointPath=Join-Path $root 'worker-stage.txt';$created+=$script:checkpointPath
            foreach($value in $workerStages) {
                Write-WorkerCheckpoint $value
                if([IO.File]::ReadAllText($script:checkpointPath) -cne $value -or (Get-Item -LiteralPath $script:checkpointPath).Length -gt 64){throw 'Checkpoint regression.'}
            }
            $rejected=$false;try{Write-WorkerCheckpoint 'unapproved-stage'}catch{$rejected=$true}
            if(-not $rejected -or [IO.File]::ReadAllText($script:checkpointPath) -cne $workerStages[-1]){throw 'Checkpoint refusal regression.'}
            $ids=@{'zrotext_root_bundle'='bundle-fixture';'zrotext_root_terminal'='terminal-fixture';'zrotext-owner'='owner-fixture'}
            $records=@()
            foreach($name in $ids.Keys) {
                $file=Join-Path $root ($name+'.exe');[IO.File]::WriteAllBytes($file,[byte[]]@());$created+=$file
                $records+=@{reason='compiler-artifact';profile=@{test=$true};target=@{name=$name};package_id=$ids[$name];executable=$file}
            }
            if(@(Select-TestArtifacts $records $root $ids).Count -ne 3){throw 'Artifact selection regression.'}
            foreach($case in @('missing','duplicate','package','escape')) {
                $candidate=@($records | ForEach-Object {$_.Clone()})
                switch($case) {
                    missing {$candidate=@($candidate[0],$candidate[1])}
                    duplicate {$candidate+=@($candidate[0])}
                    package {$candidate[0].package_id='unapproved-package'}
                    escape {$candidate[0].executable=Join-Path $temp 'outside.exe'}
                }
                $rejected=$false;try{Select-TestArtifacts $candidate $root $ids | Out-Null}catch{$rejected=$true}
                if(-not $rejected){throw 'Artifact refusal regression.'}
            }
            $rejected=$false;try{Assert-ChildPath (Join-Path $root '..\outside') $root | Out-Null}catch{$rejected=$true}
            if(-not $rejected){throw 'Path escape regression.'}
            $junction=Join-Path $root 'junction'
            New-Item -ItemType Junction -Path $junction -Target $temp | Out-Null
            $rejected=$false;try{Assert-PlainPath $junction | Out-Null}catch{$rejected=$true}
            if(-not $rejected){throw 'Reparse refusal regression.'}
        } finally {
            if([IO.Path]::GetDirectoryName($root) -cne $temp){throw 'Guard fixture cleanup boundary.'}
            if($junction -and (Test-Path -LiteralPath $junction)){Remove-Item -LiteralPath $junction -Force}
            foreach($file in $created){Remove-Item -LiteralPath $file -Force}
            Remove-Item -LiteralPath $root -Force
        }
    }
    Write-Output 'Native CI host, quoting, artifact, path and reparse guards: PASS'
}
if($SelfTest){Test-PureGuards;exit 0}
if($PSCmdlet.ParameterSetName -eq 'Inspect'){throw 'Choose SelfTest, CompileOnly, or explicit disposable CI provisioning.'}
if(-not $IsWindows){throw 'Windows is required.'}
if($CompileOnly){Add-Type -Path (Join-Path $PSScriptRoot 'windows_native_ci.cs');Write-Output 'Native CI helper compilation: PASS';exit 0}

if($WorkerManifest) {
    $workerStage='worker-manifest'
    $workerFailed=$false;$privateTemp=$null
    try {
        $checkpointRoot=Assert-PlainPath ([IO.Path]::GetDirectoryName($WorkerManifest))
        if([IO.Path]::GetFileName($checkpointRoot) -notmatch '^zrotext-native-[a-f0-9]{32}$'){throw 'Worker checkpoint boundary failed.'}
        $script:checkpointPath=Assert-ChildPath (Join-Path $checkpointRoot 'results/worker-stage.txt') $checkpointRoot
        Write-WorkerCheckpoint 'worker-start'
        Assert-CiHost @{GITHUB_ACTIONS=$env:GITHUB_ACTIONS;RUNNER_ENVIRONMENT=$env:RUNNER_ENVIRONMENT;RUNNER_OS=$env:RUNNER_OS;ImageOS=$env:ImageOS}
        $root=Assert-PlainPath ([IO.Path]::GetDirectoryName($WorkerManifest))
        if([IO.Path]::GetFileName($root) -notmatch '^zrotext-native-[a-f0-9]{32}$' -or (Assert-PlainPath $env:TEMP) -cne (Join-Path $root 'temp')){throw 'Worker fixture boundary failed.'}
        Write-WorkerCheckpoint 'worker-manifest'
        $manifest=Get-Content -LiteralPath (Assert-ChildPath $WorkerManifest $root) -Raw | ConvertFrom-Json
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent().User
        if($identity.Value -cne $manifest.Sid){throw 'Wrong worker identity.'}
        Write-WorkerCheckpoint 'worker-ownership'
        foreach($part in @('temp','results')) {
            $directory=Assert-ChildPath (Join-Path $root $part) $root
            $acl=Get-Acl -LiteralPath $directory
            $acl.SetOwner($identity)
            Set-Acl -LiteralPath $directory -AclObject $acl
            if((Get-Acl -LiteralPath $directory).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $manifest.Sid){throw 'Worker directory ownership failed.'}
        }
        Write-WorkerCheckpoint 'worker-helper-compile'
        Add-Type -Path (Assert-ChildPath (Join-Path $root 'bin/windows_native_ci.cs') $root)
        Write-WorkerCheckpoint 'worker-eligibility'
        [ZrotextCi.Native]::CheckWorker([string]$manifest.Sid)
        $privateTemp=Assert-ChildPath (Join-Path $root 'temp') $root
        $results=@()
        foreach($test in $manifest.Tests) {
            Write-WorkerCheckpoint 'worker-test-prepare'
            $exe=Assert-ChildPath ([string]$test.Executable) (Join-Path $root 'bin')
            if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $test.Hash){throw 'Fixture executable changed.'}
            $log=Assert-ChildPath (Join-Path $root ('results/'+$test.Name+'.log')) $root
            $start=[Diagnostics.ProcessStartInfo]::new()
            $start.FileName=$exe;$start.ArgumentList.Add('--test-threads=1')
            $start.WorkingDirectory=$root;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
            $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
            $process=[Diagnostics.Process]::new();$process.StartInfo=$start
            try {
                Write-WorkerCheckpoint 'worker-test-launch'
                if(-not $process.Start()){throw 'Native suite launch failed.'}
                $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
                Write-WorkerCheckpoint 'worker-test-wait'
                if(-not $process.WaitForExit(90000)){$process.Kill($true);$process.WaitForExit();throw 'Native suite timed out.'}
                $code=$process.ExitCode
                Write-WorkerCheckpoint 'worker-test-output'
                $text=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
                if($text.Length -gt 1048576){throw 'Native suite output exceeded fixture bound.'}
                Set-Content -LiteralPath $log -Value $text
            } finally {$process.Dispose()}
            Write-WorkerCheckpoint 'worker-test-result'
            $summary='test result: ok. '+$test.Passed+' passed; 0 failed; 0 ignored;'
            if($code -ne 0 -or -not $text.Contains($summary)){throw 'Native suite failed or expected count changed.'}
            $results+=@{Name=$test.Name;Passed=$test.Passed;ExitCode=$code}
        }
        Write-WorkerCheckpoint 'worker-results'
        $results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'results/result.json')
    } catch {
        # Never render exception objects or bound arguments.
        Write-Output "Native CI worker failed at $workerStage."
        $workerFailed=$true
    } finally {
        if($privateTemp) {
            try {
                Write-WorkerCheckpoint 'worker-cleanup'
                $checked=Assert-ChildPath $privateTemp $root
                if([IO.Path]::GetFileName($checked) -cne 'temp'){throw 'Worker cleanup boundary failed.'}
                Assert-NoReparseDescendants $checked
                foreach($item in Get-ChildItem -LiteralPath $checked -Force) {Remove-Item -LiteralPath $item.FullName -Recurse -Force}
                if(@(Get-ChildItem -LiteralPath $checked -Force).Count){throw 'Worker temporary data remains.'}
            } catch {$workerFailed=$true;Write-Output 'Native CI worker temporary cleanup failed.'}
        }
    }
    if($workerFailed){exit 1}
    Write-WorkerCheckpoint 'worker-complete'
    exit 0
}

$stage='host-guard'
$fixture=$null;$account=$null;$password=$null;$username=$null;$sid=$null
$cleanupFailures=[Collections.Generic.List[string]]::new()
$failed=$false
try {
    Assert-CiHost @{GITHUB_ACTIONS=$env:GITHUB_ACTIONS;RUNNER_ENVIRONMENT=$env:RUNNER_ENVIRONMENT;RUNNER_OS=$env:RUNNER_OS;ImageOS=$env:ImageOS}
    $stage='runner-temp-path'
    $runnerTemp=Assert-PlainPath $env:RUNNER_TEMP
    $stage='workspace-path'
    $workspace=Assert-PlainPath $env:GITHUB_WORKSPACE
    if(-not (Test-Path -LiteralPath $runnerTemp -PathType Container) -or -not (Test-Path -LiteralPath $workspace -PathType Container)){throw 'Runner directories unavailable.'}
    $stage='native-helper-compile'
    Add-Type -Path (Join-Path $PSScriptRoot 'windows_native_ci.cs')
    if(-not [ZrotextCi.Native]::ParentElevated()){throw 'Provisioning requires the disposable runner administrator.'}
    [ZrotextCi.Native]::CheckSession()
    $stage='compile-tests'
    Push-Location $workspace
    try {
        $build=@(& cargo test --locked --no-run --message-format=json -p zrotext-root-bundle -p zrotext-root-terminal -p zrotext-owner)
        if($LASTEXITCODE -ne 0){throw 'Native test compilation failed.'}
        $metadata=(& cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json)
        if($LASTEXITCODE -ne 0){throw 'Native metadata failed.'}
    } finally {Pop-Location}
    $packageIds=@{}
    foreach($pair in @(@('zrotext-root-bundle','zrotext_root_bundle'),@('zrotext-root-terminal','zrotext_root_terminal'),@('zrotext-owner','zrotext-owner'))) {
        $package=@($metadata.packages | Where-Object name -eq $pair[0])
        if($package.Count -ne 1){throw 'Ambiguous native package.'}
        Assert-ChildPath $package[0].manifest_path $workspace | Out-Null
        $packageIds[$pair[1]]=$package[0].id
    }
    $artifacts=Select-TestArtifacts @($build | ForEach-Object {$_ | ConvertFrom-Json}) (Join-Path $workspace 'target') $packageIds
    $stage='account-create'
    $username='ztci'+[Guid]::NewGuid().ToString('N').Substring(0,12)
    $stage='account-name-check'
    if(Get-LocalUser -Name $username -ErrorAction SilentlyContinue){throw 'Fixture username collision.'}
    $stage='account-password-buffer'
    $password=[Security.SecureString]::new()
    $random=[byte[]]::new(48)
    try {
        [Security.Cryptography.RandomNumberGenerator]::Fill($random)
        foreach($c in 'Aa1!'.ToCharArray()){$password.AppendChar($c)}
        $alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        foreach($b in $random){$password.AppendChar($alphabet[$b -band 63])}
        $password.MakeReadOnly()
    } finally {[Array]::Clear($random,0,$random.Length);$b=0}
    $stage='account-new-local-user'
    $account=New-LocalUser -Name $username -Password $password -Description 'Disposable native test fixture' -AccountNeverExpires
    $sid=$account.SID
    $users=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $stage='account-users-membership'
    if(-not @(Get-LocalGroupMember -SID $users | Where-Object SID -eq $sid).Count){Add-LocalGroupMember -SID $users -Member $account}
    $stage='account-groups-verify'
    $groups=@(Get-LocalGroup | Where-Object {@(Get-LocalGroupMember -SID $_.SID | Where-Object SID -eq $sid).Count -ne 0})
    if($groups.Count -ne 1 -or $groups[0].SID.Value -cne 'S-1-5-32-545'){throw 'Fixture group membership is not standard Users only.'}
    $stage='fixture-files'
    $fixture=Join-Path $runnerTemp ('zrotext-native-'+[Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($fixture) | Out-Null
    $fixture=Assert-ChildPath $fixture $runnerTemp
    $admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    Set-FixtureAcl $fixture $admin $sid $false
    foreach($part in @('bin','temp','results')) {
        $directory=Join-Path $fixture $part
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        # The standard user takes ownership of writable children itself; the
        # administrator does not enable privileges to assign another owner.
        Set-FixtureAcl $directory $admin $sid ($part -ne 'bin')
    }
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $fixture 'bin/windows_native_ci.ps1')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_native_ci.cs') -Destination (Join-Path $fixture 'bin/windows_native_ci.cs')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_native_ci_bootstrap.ps1') -Destination (Join-Path $fixture 'bin/windows_native_ci_bootstrap.ps1')
    $tests=@()
    foreach($artifact in $artifacts) {
        $destination=Join-Path $fixture ('bin/'+$artifact.Name+'.exe')
        Copy-Item -LiteralPath $artifact.Source -Destination $destination
        $tests+=@{Name=$artifact.Name;Executable=$destination;Hash=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash;Passed=$artifact.Passed}
    }
    $manifest=Join-Path $fixture 'manifest.json'
    @{Sid=$sid.Value;Tests=$tests} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest
    $stage='standard-user-run'
    $pwsh=Assert-PlainPath (Get-Process -Id $PID).Path
    if([IO.Path]::GetFileName($pwsh) -ne 'pwsh.exe' -or -not (Test-Path -LiteralPath $pwsh -PathType Leaf)){throw 'Unexpected fixture executable.'}
    $fixture=Assert-PlainPath $fixture
    if(-not (Test-Path -LiteralPath $fixture -PathType Container)){throw 'Fixture working directory unavailable.'}
    Write-Output 'Native CI executable and working directory: verified'
    $arguments=@($pwsh,'-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $fixture 'bin/windows_native_ci_bootstrap.ps1'),'-WorkerManifest',$manifest)
    $command=($arguments | ForEach-Object {Quote-FixedArgument $_}) -join ' '
    $environment='GITHUB_ACTIONS=true'+[char]0+"ImageOS=$env:ImageOS"+[char]0+'RUNNER_ENVIRONMENT=github-hosted'+[char]0+'RUNNER_OS=Windows'+[char]0+"SystemRoot=$env:SystemRoot"+[char]0+"TEMP=$(Join-Path $fixture 'temp')"+[char]0+"TMP=$(Join-Path $fixture 'temp')"+[char]0+[char]0
    $probe=@($tests | Where-Object Name -CEQ 'zrotext_root_bundle')
    if($probe.Count -ne 1){throw 'Ambiguous native startup probe.'}
    $probeExe=Assert-ChildPath $probe[0].Executable (Join-Path $fixture 'bin')
    if((Get-FileHash -LiteralPath $probeExe -Algorithm SHA256).Hash -cne $probe[0].Hash){throw 'Native startup probe changed.'}
    $code=[ZrotextCi.Native]::Run($username,$sid.Value,$password,$pwsh,$command,$environment,$fixture,$probeExe)
    if($code -ne 0){throw 'Standard-user native worker failed.'}
    $result=Get-Content -LiteralPath (Join-Path $fixture 'results/result.json') -Raw | ConvertFrom-Json
    if($result.Count -ne 3){throw 'Incomplete native suite results.'}
    foreach($test in $tests) {
        $matching=@($result | Where-Object Name -eq $test.Name)
        if($matching.Count -ne 1 -or $matching[0].ExitCode -ne 0 -or $matching[0].Passed -ne $test.Passed){throw 'Unexpected native suite result.'}
        Write-Output ('Native CI '+$test.Name+': '+$test.Passed+' passed, zero failed/ignored; actual standard user.')
    }
} catch {
    $failed=$true
    Write-Output "Native CI fixture failed at $stage."
    if('ZrotextCi.Native' -as [type]){Write-Output ('Native stage: '+[ZrotextCi.Native]::Stage+'; OS code: '+[ZrotextCi.Native]::ErrorCode)}
    if('ZrotextCi.Native' -as [type]){Write-Output ('Native CI process classes: '+[ZrotextCi.Native]::LaunchState+'; resume='+[ZrotextCi.Native]::ResumeState+'; wait='+[ZrotextCi.Native]::WaitState+'; exit='+[ZrotextCi.Native]::ExitState)}
    if('ZrotextCi.Native' -as [type]){Write-Output ('Native CI startup probe: '+[ZrotextCi.Native]::ProbeState+'; native cleanup='+[ZrotextCi.Native]::CleanupState)}
    if('ZrotextCi.Native' -as [type]){Write-Output ('Native CI job images at timeout: '+[ZrotextCi.Native]::JobState+'; diagnostic launches: '+[ZrotextCi.Native]::DiagnosticState)}
    if($fixture) {
        try {
            $bootstrap=Assert-ChildPath (Join-Path $fixture 'results/bootstrap-stage.txt') $fixture
            if(Test-Path -LiteralPath $bootstrap -PathType Leaf) {
                if((Get-Item -LiteralPath $bootstrap).Length -gt 64 -or [IO.File]::ReadAllText($bootstrap) -cne 'bootstrap-entered'){throw 'Invalid bootstrap marker.'}
                Write-Output 'Native CI bootstrap: entered'
            } else {Write-Output 'Native CI bootstrap: unavailable'}
        } catch {Write-Output 'Native CI bootstrap marker refused.'}
        try {
            $checkpoint=Assert-ChildPath (Join-Path $fixture 'results/worker-stage.txt') $fixture
            if(Test-Path -LiteralPath $checkpoint -PathType Leaf) {
                if((Get-Item -LiteralPath $checkpoint).Length -gt 64){throw 'Checkpoint exceeds bound.'}
                $lastStage=[IO.File]::ReadAllText($checkpoint)
                if($lastStage -cnotin $workerStages){throw 'Unknown worker checkpoint.'}
                Write-Output ('Native CI worker checkpoint: '+$lastStage)
            } else {Write-Output 'Native CI worker checkpoint: unavailable'}
        } catch {Write-Output 'Native CI worker checkpoint refused.'}
        foreach($name in @('zrotext_root_bundle','zrotext_root_terminal','zrotext-owner')) {
            $log=Join-Path $fixture ('results/'+$name+'.log')
            if(Test-Path -LiteralPath $log -PathType Leaf) {
                # Only synthetic test output; credentials never enter the worker.
                try {
                    $checkedLog=Assert-ChildPath $log $fixture
                    Get-Content -LiteralPath $checkedLog -Tail 30 | ForEach-Object {Write-Output $_}
                } catch {Write-Output 'Native CI fixture log refused.'}
            }
        }
    }
} finally {
    if($password){$password.Dispose()}
    if($account) {
        try {
            $profile=@(Get-CimInstance Win32_UserProfile | Where-Object SID -eq $sid.Value)
            if($profile.Count -gt 1){throw 'Ambiguous fixture profile.'}
            if($profile.Count -eq 1){
                if([ZrotextCi.Native]::CleanupState -cne 'passed'){throw 'Native cleanup not verified.'}
                [ZrotextCi.Native]::DeleteProfile($sid.Value)
                if(@(Get-CimInstance Win32_UserProfile | Where-Object SID -eq $sid.Value).Count){throw 'Fixture profile remains.'}
                Write-Output 'Native CI profile cleanup: deleted and verified absent'
            } else {Write-Output 'Native CI profile cleanup: absent'}
        } catch {$cleanupFailures.Add('profile');Write-Output 'Native CI profile cleanup: failed'}
        try {
            $current=Get-LocalUser -Name $username
            if($current.SID.Value -cne $sid.Value){throw 'Fixture user changed.'}
            Remove-LocalUser -SID $sid
            if(Get-LocalUser -Name $username -ErrorAction SilentlyContinue){throw 'Fixture user remains.'}
        } catch {$cleanupFailures.Add('account')}
    }
    if($fixture) {
        try {
            $resolved=Assert-ChildPath $fixture $runnerTemp
            if([IO.Path]::GetDirectoryName($resolved) -cne $runnerTemp.TrimEnd('\') -or [IO.Path]::GetFileName($resolved) -notmatch '^zrotext-native-[a-f0-9]{32}$'){throw 'Fixture cleanup boundary failed.'}
            # Check descendants before recursive deletion; never follow reparse targets.
            Assert-NoReparseDescendants $resolved
            Remove-Item -LiteralPath $resolved -Recurse -Force
            if(Test-Path -LiteralPath $resolved){throw 'Fixture directory remains.'}
        } catch {$cleanupFailures.Add('files')}
    }
    if($cleanupFailures.Count){$failed=$true;Write-Output ('Native CI cleanup failed: '+($cleanupFailures -join ', '))}
    else {Write-Output 'Native CI account/profile/files cleanup: PASS'}
}
if($failed){exit 1}
exit 0
