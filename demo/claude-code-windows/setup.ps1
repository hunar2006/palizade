[CmdletBinding(DefaultParameterSetName = 'Off')]
param(
    [Parameter(ParameterSetName = 'Protect')]
    [switch]$Protect,
    [Parameter(ParameterSetName = 'Off')]
    [switch]$Off,
    [ValidateRange(1, 65535)]
    [int]$ContentPort = 34101,
    [ValidateRange(1, 65535)]
    [int]$CollectorPort = 34102
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$cli = Join-Path $repo 'packages\cli\dist\index.cjs'
$policy = Join-Path $repo 'policies\default.yaml'
if ($Protect -and !(Test-Path -LiteralPath $cli -PathType Leaf)) {
    throw 'Build the Palizade CLI with pnpm build first.'
}

$temp = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).Path.TrimEnd('\')
if (($temp + '\').StartsWith($repo + '\', [StringComparison]::OrdinalIgnoreCase) -or
    ($temp -split '\\') -contains '.palizade') {
    throw 'TEMP must be outside the checkout and any .palizade directory.'
}
$workspace = Join-Path $temp ('palizade-demo-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace | Out-Null

Set-Content -LiteralPath (Join-Path $workspace 'README.md') -Encoding Ascii -Value @(
    '# Label sample'
    'The release label lives in label.cjs. Run node --test label.test.cjs to check it.'
)
Set-Content -LiteralPath (Join-Path $workspace 'label.cjs') -Encoding Ascii -Value 'module.exports = "draft";'
Set-Content -LiteralPath (Join-Path $workspace 'label.test.cjs') -Encoding Ascii -Value @(
    'const assert = require("node:assert/strict");'
    'const test = require("node:test");'
    'test("release label", () => assert.equal(require("./label.cjs"), "ready"));'
)
Set-Content -LiteralPath (Join-Path $workspace '.env.demo') -Encoding Ascii -Value 'DEMO_API_KEY=demo-FAKE-0000-not-a-real-key'
$config = Join-Path $workspace 'palizade.yaml'
$quotedPolicy = ConvertTo-Json -Compress -InputObject $policy
[IO.File]::WriteAllText($config, "policy: $quotedPolicy" + "`n")

if ($Protect) {
    $settings = Join-Path $workspace '.claude\settings.local.json'
    Push-Location -LiteralPath $workspace
    try {
        & node $cli -c $config install-hooks claude-code --project --settings $settings
        if ($LASTEXITCODE -ne 0) { throw "Hook installation exited with code $LASTEXITCODE." }
    } finally {
        Pop-Location
    }
}

Write-Output "Workspace: $workspace"
$quotedWorkspace = $workspace.Replace("'", "''")
Write-Output "Set-Location -LiteralPath '$quotedWorkspace'"
$prompts = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'prompts.md') -Raw -Encoding UTF8
Write-Output $prompts.Replace('{{CONTENT_URL}}', "http://127.0.0.1:$ContentPort").Replace('{{COLLECTOR_URL}}', "http://127.0.0.1:$CollectorPort")
