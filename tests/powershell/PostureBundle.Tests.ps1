# Posture bundle / retrieval tests (Pester v5)
# Covers scripts/powershell/Export-PostureBundle.ps1 and Collect-PostureReports.ps1. Nothing here
# touches the network or a remote host: Export runs against a fixture folder of fake report files,
# and Collect is exercised with -Method Local copying from one local folder to another, so the
# suite also runs on CI. The script contract itself is checked by ScriptContract.Tests.ps1.

BeforeAll {
    $script:exportScript = (Resolve-Path (Join-Path $PSScriptRoot '../../scripts/powershell/Export-PostureBundle.ps1')).Path
    $script:collectScript = (Resolve-Path (Join-Path $PSScriptRoot '../../scripts/powershell/Collect-PostureReports.ps1')).Path

    function Write-FakeReport {
        # Writes a fake report file and stamps its LastWriteTimeUtc so "newest" is deterministic.
        param([string]$Path, [string]$Content = 'x', [datetime]$WhenUtc)
        Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
        if ($WhenUtc) { (Get-Item -LiteralPath $Path).LastWriteTimeUtc = $WhenUtc }
    }

    $script:postureJson = '{"schema":"cc.posture.report/1","summary":{"total":2,"pass":1,"fail":1,"error":0,"scorePct":50}}'
}

Describe 'Export-PostureBundle' {

    BeforeEach {
        $script:src = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:out = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:src
        $null = New-Item -ItemType Directory -Path $script:out

        $old = [datetime]::new(2026, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        $new = [datetime]::new(2026, 1, 2, 0, 0, 0, [DateTimeKind]::Utc)
        # An older posture set (3 files) ...
        Write-FakeReport -Path (Join-Path $script:src 'posture-HOSTA-20260101T000000Z.json') -Content $script:postureJson -WhenUtc $old
        Write-FakeReport -Path (Join-Path $script:src 'posture-HOSTA-20260101T000000Z.ndjson') -WhenUtc $old
        Write-FakeReport -Path (Join-Path $script:src 'posture-HOSTA-20260101T000000Z.csv') -WhenUtc $old
        # ... a newer posture set (3 files) ...
        Write-FakeReport -Path (Join-Path $script:src 'posture-HOSTA-20260102T000000Z.json') -Content $script:postureJson -WhenUtc $new
        Write-FakeReport -Path (Join-Path $script:src 'posture-HOSTA-20260102T000000Z.ndjson') -WhenUtc $new
        Write-FakeReport -Path (Join-Path $script:src 'posture-HOSTA-20260102T000000Z.csv') -WhenUtc $new
        # ... and an AD posture report.
        Write-FakeReport -Path (Join-Path $script:src 'adposture-HOSTA-20260101T000000Z.json') -Content $script:postureJson -WhenUtc $old
    }

    It 'produces a correctly-named zip and manifest' {
        & $script:exportScript -SourcePath $script:src -OutputPath $script:out -Quiet | Out-Null

        $zip = @(Get-ChildItem -Path $script:out -Filter 'posture-bundle-*.zip')
        $manifest = @(Get-ChildItem -Path $script:out -Filter 'posture-bundle-*.manifest.json')
        $zip.Count | Should -Be 1
        $manifest.Count | Should -Be 1
        # The zip and manifest share the same posture-bundle-<HOST>-<UTC> base name.
        $zip[0].BaseName | Should -Be ($manifest[0].Name -replace '\.manifest\.json$', '')
    }

    It 'records the bundled files and the newest summary in the manifest' {
        & $script:exportScript -SourcePath $script:src -OutputPath $script:out -Quiet | Out-Null
        $manifest = Get-Content -Raw (Get-ChildItem -Path $script:out -Filter 'posture-bundle-*.manifest.json')[0].FullName | ConvertFrom-Json

        $manifest.schema | Should -Be 'cc.posture.bundle/1'
        $manifest.fileCount | Should -Be 7
        $manifest.summary.pass | Should -Be 1
        $manifest.summary.fail | Should -Be 1
        $manifest.summary.scorePct | Should -Be 50
    }

    It 'bundles only the newest set per report type with -Latest' {
        & $script:exportScript -SourcePath $script:src -OutputPath $script:out -Latest -Quiet | Out-Null
        $manifest = Get-Content -Raw (Get-ChildItem -Path $script:out -Filter 'posture-bundle-*.manifest.json')[0].FullName | ConvertFrom-Json

        $files = @($manifest.files)
        # Newest posture set (3) + the single AD posture set (1); the older posture set is excluded.
        $files.Count | Should -Be 4
        ($files | Where-Object { $_ -like 'posture-HOSTA-20260102T*' }).Count | Should -Be 3
        ($files | Where-Object { $_ -like 'posture-HOSTA-20260101T*' }).Count | Should -Be 0
        ($files | Where-Object { $_ -like 'adposture-HOSTA-20260101T*' }).Count | Should -Be 1
    }

    It 'never bundles a previous bundle or its manifest' {
        # First run leaves a bundle + manifest in the source folder.
        & $script:exportScript -SourcePath $script:src -OutputPath $script:src -Quiet | Out-Null
        # Second run must ignore posture-bundle-* when gathering.
        & $script:exportScript -SourcePath $script:src -OutputPath $script:out -Quiet | Out-Null
        $manifest = Get-Content -Raw (Get-ChildItem -Path $script:out -Filter 'posture-bundle-*.manifest.json')[0].FullName | ConvertFrom-Json

        @($manifest.files | Where-Object { $_ -like 'posture-bundle-*' }).Count | Should -Be 0
    }
}

Describe 'Collect-PostureReports -Method Local' {

    BeforeEach {
        $script:remote = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:dest = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:remote
        Write-FakeReport -Path (Join-Path $script:remote 'posture-WKSTN07-20260102T000000Z.json') -Content $script:postureJson
        Write-FakeReport -Path (Join-Path $script:remote 'adposture-WKSTN07-20260102T000000Z.json')
        Write-FakeReport -Path (Join-Path $script:remote 'posture-bundle-WKSTN07-20260102T000000Z.zip')
        Write-FakeReport -Path (Join-Path $script:remote 'notes.txt')
    }

    It 'copies matching files into <Destination>\<asset>\' {
        $result = & $script:collectScript -Asset 'WKSTN07' -Method Local -RemotePath $script:remote -Destination $script:dest -Pattern 'posture-*', 'adposture-*'

        $assetDir = Join-Path $script:dest 'WKSTN07'
        Test-Path -LiteralPath $assetDir | Should -BeTrue
        $copied = @(Get-ChildItem -Path $assetDir -File)
        # posture-*.json + posture-bundle-*.zip (also matches posture-*) + adposture-*.json = 3; notes.txt excluded.
        $copied.Count | Should -Be 3
        ($copied | Where-Object { $_.Name -eq 'notes.txt' }).Count | Should -Be 0
        (@($result).Where({ $_.Asset -eq 'WKSTN07' })[0]).Status | Should -Be 'ok'
    }

    It 'de-duplicates files matched by more than one pattern' {
        # Default patterns include both posture-* and posture-bundle-*, which overlap on the zip.
        $result = & $script:collectScript -Asset 'WKSTN07' -Method Local -RemotePath $script:remote -Destination $script:dest
        $assetDir = Join-Path $script:dest 'WKSTN07'
        # posture-*.json + adposture-*.json + posture-bundle-*.zip, each copied once.
        @(Get-ChildItem -Path $assetDir -File).Count | Should -Be 3
        (@($result)[0]).FilesCopied | Should -Be 3
    }

    It 'warns and continues when an asset path is unreachable' {
        $missing = Join-Path $TestDrive 'does-not-exist'
        $result = & $script:collectScript -Asset 'GHOST' -Method Local -RemotePath $missing -Destination $script:dest 3>$null
        (@($result)[0]).Status | Should -Be 'unreachable'
        (@($result)[0]).FilesCopied | Should -Be 0
    }
}
