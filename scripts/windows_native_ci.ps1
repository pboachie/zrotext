# SPDX-License-Identifier: AGPL-3.0-only
[CmdletBinding(DefaultParameterSetName='Inspect')]
param(
    [Parameter(ParameterSetName='SelfTest',Mandatory)][switch]$SelfTest,
    [Parameter(ParameterSetName='Compile',Mandatory)][switch]$CompileOnly,
    [Parameter(ParameterSetName='Provision',Mandatory)][switch]$ProvisionEphemeralGithubHostedAccount
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

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
function Test-SuiteSummary([string]$Text,[int]$Passed) {
    return $Text.Contains('test result: ok. '+$Passed+' passed; 0 failed; 0 ignored;')
}
function Test-PureGuards {
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
    if(-not (Test-SuiteSummary "x`ntest result: ok. 20 passed; 0 failed; 0 ignored; 0 measured" 20)){throw 'Summary acceptance regression.'}
    foreach($text in @('test result: ok. 19 passed; 0 failed; 0 ignored;','test result: ok. 20 passed; 0 failed; 1 ignored;','test result: FAILED. 20 passed; 1 failed; 0 ignored;','')) {
        if(Test-SuiteSummary $text 20){throw 'Summary refusal regression.'}
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
    $tests=@()
    foreach($artifact in $artifacts) {
        $destination=Join-Path $fixture ('bin\'+$artifact.Name+'.exe')
        Copy-Item -LiteralPath $artifact.Source -Destination $destination
        $tests+=@{Name=$artifact.Name;Executable=$destination;Hash=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash;Passed=$artifact.Passed;Log=(Join-Path $fixture ('results\'+$artifact.Name+'.log'))}
    }
    $stage='standard-user-run'
    $fixture=Assert-PlainPath $fixture
    if(-not (Test-Path -LiteralPath $fixture -PathType Container)){throw 'Fixture working directory unavailable.'}
    # Steps run directly as the fixture user: PowerShell hosts never reached
    # their first line under the secondary-logon token, while cmd.exe and the
    # native suites did. The fixture user takes ownership of its writable
    # directories itself; the administrator enables no privilege to assign it.
    $system=Assert-PlainPath ([Environment]::SystemDirectory)
    $icacls=Assert-ChildPath (Join-Path $system 'icacls.exe') $system
    $cmd=Assert-ChildPath (Join-Path $system 'cmd.exe') $system
    $apps=[Collections.Generic.List[string]]::new();$commands=[Collections.Generic.List[string]]::new();$timeouts=[Collections.Generic.List[int]]::new()
    foreach($part in @('temp','results')) {
        $apps.Add($icacls);$timeouts.Add(30000)
        $commands.Add('icacls.exe '+(Quote-FixedArgument (Join-Path $fixture $part))+' /setowner *'+$sid.Value+' /q')
    }
    foreach($test in $tests) {
        $exe=Assert-ChildPath $test.Executable (Join-Path $fixture 'bin')
        if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $test.Hash){throw 'Fixture executable changed.'}
        $log=Assert-ChildPath $test.Log (Join-Path $fixture 'results')
        $apps.Add($cmd);$timeouts.Add(90000)
        $commands.Add('cmd.exe /d /s /c "'+(Quote-FixedArgument $exe)+' --test-threads=1 >'+(Quote-FixedArgument $log)+' 2>&1"')
    }
    Write-Output 'Native CI executables and working directory: verified'
    $environment='GITHUB_ACTIONS=true'+[char]0+"ImageOS=$env:ImageOS"+[char]0+'RUNNER_ENVIRONMENT=github-hosted'+[char]0+'RUNNER_OS=Windows'+[char]0+"SystemRoot=$env:SystemRoot"+[char]0+"TEMP=$(Join-Path $fixture 'temp')"+[char]0+"TMP=$(Join-Path $fixture 'temp')"+[char]0+[char]0
    # The terminal suite is the one that loads user32; probe its startup.
    $probe=@($tests | Where-Object Name -CEQ 'zrotext_root_terminal')
    if($probe.Count -ne 1){throw 'Ambiguous native startup probe.'}
    $probeExe=Assert-ChildPath $probe[0].Executable (Join-Path $fixture 'bin')
    $codes=@([ZrotextCi.Native]::Run($username,$sid.Value,$password,$apps.ToArray(),$commands.ToArray(),$timeouts.ToArray(),$environment,$fixture,$probeExe))
    $stage='ownership-verify'
    if($codes.Count -lt 2 -or $codes[0] -ne 0 -or $codes[1] -ne 0){throw 'Fixture ownership step failed.'}
    foreach($part in @('temp','results')) {
        if((Get-Acl -LiteralPath (Join-Path $fixture $part)).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid.Value){throw 'Fixture directory ownership failed.'}
    }
    $stage='suite-results'
    for($i=0;$i -lt $tests.Count;$i++) {
        $test=$tests[$i]
        if($codes.Count -le $i+2){throw 'Native suite did not run.'}
        $log=Assert-ChildPath $test.Log (Join-Path $fixture 'results')
        if((Get-Item -LiteralPath $log).Length -gt 1048576){throw 'Native suite output exceeded fixture bound.'}
        if($codes[$i+2] -ne 0 -or -not (Test-SuiteSummary ([IO.File]::ReadAllText($log)) $test.Passed)){throw 'Native suite failed or expected count changed.'}
        Write-Output ('Native CI '+$test.Name+': '+$test.Passed+' passed, zero failed/ignored; actual standard user.')
    }
} catch {
    $failed=$true
    Write-Output "Native CI fixture failed at $stage."
    if('ZrotextCi.Native' -as [type]){Write-Output ('Native stage: '+[ZrotextCi.Native]::Stage+'; OS code: '+[ZrotextCi.Native]::ErrorCode)}
    if('ZrotextCi.Native' -as [type]){Write-Output ('Native CI process classes: '+[ZrotextCi.Native]::LaunchState+'; resume='+[ZrotextCi.Native]::ResumeState+'; wait='+[ZrotextCi.Native]::WaitState+'; exit='+[ZrotextCi.Native]::ExitState)}
    if('ZrotextCi.Native' -as [type]){Write-Output ('Native CI startup probe: '+[ZrotextCi.Native]::ProbeState+'; native cleanup='+[ZrotextCi.Native]::CleanupState)}
    if('ZrotextCi.Native' -as [type]){Write-Output ('Native CI job images at timeout: '+[ZrotextCi.Native]::JobState+'; station='+[ZrotextCi.Native]::StationClass+'; dialogs before='+[ZrotextCi.Native]::DialogsBefore+' at-timeout='+[ZrotextCi.Native]::DialogsAtTimeout+' codes='+[ZrotextCi.Native]::DialogSummary+'; labels '+[ZrotextCi.Native]::LabelState)}
    if($fixture) {
        foreach($name in @('zrotext_root_bundle','zrotext_root_terminal','zrotext-owner')) {
            $log=Join-Path $fixture ('results/'+$name+'.log')
            if(Test-Path -LiteralPath $log -PathType Leaf) {
                # Only synthetic test output; credentials never reach the fixture user.
                try {
                    $checkedLog=Assert-ChildPath $log $fixture
                    Write-Output ('Native CI '+$name+' log bytes: '+(Get-Item -LiteralPath $checkedLog).Length)
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
