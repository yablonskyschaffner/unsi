# AntiStealer — Test / Quality projects

This directory contains the quality-assurance layer for `AntiStealerOneExe`:

| Section | Project / File                 | Purpose                                                                     |
|---------|--------------------------------|-----------------------------------------------------------------------------|
| I1      | `AntiStealer.Tests`            | xUnit unit tests on `Analyzer`, `ReportWriter`, `AnalysisResult`.           |
| I2      | fixtures inside each test      | Synthetic PE-ish and archive fixtures created in `%TEMP%` per test.         |
| I3      | `RegexSafetyTests.cs`          | FsCheck property-based fuzzing of IOC regexes — guards against ReDoS.       |
| I4      | `ArchiveScanningTests.cs`      | Integration tests: nested ZIPs, zip-slip, deep entry paths.                 |
| I5      | `coverlet.collector`           | Code-coverage output (Cobertura) — `dotnet test --collect:"XPlat Code Coverage"`. |
| I6      | `AntiStealer.Benchmarks`       | BenchmarkDotNet project for hot paths (full-file Analyze, small vs medium). |
| I7      | `stryker-config.json`          | Stryker.NET mutation-testing config at the repo root.                       |

## Running the tests

```
dotnet test AntiStealer.Tests/AntiStealer.Tests.csproj -c Release
```

## Coverage (I5)

```
dotnet test AntiStealer.Tests/AntiStealer.Tests.csproj `
    --collect:"XPlat Code Coverage" `
    --results-directory coverage
# Coverage reports land in coverage/<guid>/coverage.cobertura.xml.
# Convert to HTML with ReportGenerator:
dotnet tool install --global dotnet-reportgenerator-globaltool
reportgenerator "-reports:coverage/**/coverage.cobertura.xml" "-targetdir:coverage/html" "-reporttypes:Html;Cobertura"
```

## Benchmarks (I6)

```
dotnet run -c Release --project AntiStealer.Benchmarks -- --filter '*'
# BenchmarkDotNet results go to BenchmarkDotNet.Artifacts/.
```

## Mutation testing (I7)

```
dotnet tool install -g dotnet-stryker
dotnet-stryker       # reads stryker-config.json at repo root
# HTML report goes to StrykerOutput/.
```

## Notes

- Tests reference the WinForms project directly rather than a split core — so `TargetFramework` is
  `net8.0-windows`. Tests themselves never touch any UI type; they only drive static analyzers.
- Tests on Windows CI are expected to be fast (all-in < 30s); archive tests assert a wall-time
  budget so regressions in archive handling surface as test failures, not slow builds.
