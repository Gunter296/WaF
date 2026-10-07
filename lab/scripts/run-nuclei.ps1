param(
  [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$')][string]$RunName,
  [Parameter(Mandatory)][ValidateSet('localhost','direct.localhost','patched.localhost')][string]$HostName,
  [Parameter(Mandatory)][string[]]$Templates,
  [ValidateSet('On','DetectionOnly','N/A')][string]$WafMode = 'On',
  [ValidateSet('nuclei','nuclei-us')][string]$Client = 'nuclei',
  [ValidateRange(1,10)][int]$RateLimit = 2
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$composeFile = Join-Path $repoRoot 'lab/docker-compose.yml'
$templateRoot = Join-Path $repoRoot 'lab/nuclei-templates'
$resultsRoot = Join-Path $repoRoot 'lab/runtime/results'
$rawDirectory = Join-Path $resultsRoot "raw/$RunName"
$manifestFile = Join-Path $resultsRoot "$RunName.manifest.json"

foreach ($template in $Templates) {
  if ([IO.Path]::GetFileName($template) -ne $template -or -not (Test-Path (Join-Path $templateRoot $template))) {
    throw "Template không hợp lệ hoặc không có trong lab/nuclei-templates: $template"
  }
}
if ($HostName -eq 'direct.localhost' -and $WafMode -ne 'N/A') {
  throw 'direct.localhost đi thẳng tới origin; hãy đặt -WafMode N/A.'
}
if ($HostName -ne 'direct.localhost' -and $WafMode -eq 'N/A') {
  throw 'Host này đi qua WAF/failover; hãy ghi chế độ On hoặc DetectionOnly.'
}

New-Item -ItemType Directory -Force -Path $resultsRoot, (Split-Path $rawDirectory) | Out-Null
$appVersion = if ($HostName -eq 'patched.localhost') { 'Next.js 16.2.11' } else { 'Next.js 16.2.10' }
$route = if ($HostName -eq 'direct.localhost') { 'bypass; expect backend finance_direct/server finance' } elseif ($HostName -eq 'patched.localhost') { 'waf; expect backend finance_patched_waf/server waf' } else { 'waf unless failover; verify lab.backend and lab.server' }
$templateHashes = @{}
foreach ($template in $Templates) {
  $templateHashes[$template] = (Get-FileHash (Join-Path $templateRoot $template) -Algorithm SHA256).Hash
}
$manifest = [ordered]@{
  run_name = $RunName
  started_at = (Get-Date).ToUniversalTime().ToString('o')
  target_host = $HostName
  application_version = $appVersion
  nuclei_image = 'projectdiscovery/nuclei:v3.4.10'
  templates = $Templates
  template_revision = 'repository files; automatic updates disabled'
  template_sha256 = $templateHashes
  waf_mode = $WafMode
  expected_route = $route
  client_profile = $Client
  rate_limit_per_second = $RateLimit
  jsonl = "lab/runtime/results/$RunName.jsonl"
  raw_request_response_directory = "lab/runtime/results/raw/$RunName"
  request_id_correlation = 'X-Request-ID in raw HTTP response; use that ID in Kibana across HAProxy, WAF and app events'
  completed = $false
}

$nucleiArgs = @('-f', $composeFile, '--profile', 'scanner', 'run', '--rm', $Client,
  '-u', 'http://edge:8080', '-H', "Host: $HostName")
foreach ($template in $Templates) { $nucleiArgs += @('-t', "/templates/$template") }
$nucleiArgs += @('-rl', "$RateLimit", '-c', '1', '-pc', '1', '-ni', '-duc', '-j',
  '-o', "/results/$RunName.jsonl", '-sresp', '-srd', "/results/raw/$RunName")

try {
  & docker compose @nucleiArgs
  if ($LASTEXITCODE -ne 0) { throw "Nuclei/Compose kết thúc với exit code $LASTEXITCODE" }
  $manifest.completed = $true
} finally {
  $manifest.finished_at = (Get-Date).ToUniversalTime().ToString('o')
  $manifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 $manifestFile
}
Write-Host "Đã ghi JSONL, raw request/response và manifest cho lượt '$RunName'."
