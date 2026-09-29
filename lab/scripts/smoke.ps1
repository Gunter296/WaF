$ErrorActionPreference = "Stop"
$base = "http://127.0.0.1:8080"

function Assert-Body([string]$Name, [string]$Uri, [string]$HostName, [string]$Marker) {
  $response = & curl.exe --silent --show-error --include -H "Host: $HostName" $Uri
  if ($LASTEXITCODE -ne 0) { throw "${Name}: curl failed with exit code $LASTEXITCODE" }
  $content = $response -join "`n"
  if ($content -notmatch [regex]::Escape($Marker)) {
    throw "${Name}: marker '$Marker' was not found; response=$($response[0])"
  }
  Write-Host "PASS $Name ($($response[0]))"
}

Assert-Body "Direct origin health" "$base/healthz" "direct.localhost" "ok"
Assert-Body "Direct SQLi fixture" "$base/api/lab/search?q=%27%20OR%201%3D1--" "direct.localhost" "LAB_SQLI_MARKER"
Assert-Body "Direct SSRF canary fixture" "$base/lab/ssrf/canary/marker" "direct.localhost" "LAB_CANARY_REACHED_ONLY"
Assert-Body "Patched origin health through WAF" "$base/healthz" "patched.localhost" "ok"
Write-Host "Smoke checks passed. The WAF CVE and policy checks require Docker logs and Nuclei runs described in lab/README.md."
