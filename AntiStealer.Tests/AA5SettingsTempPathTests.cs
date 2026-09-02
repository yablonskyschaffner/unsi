using System;
using System.IO;
using System.Text.Json;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    /// <summary>
    /// AA5 — <see cref="AnalyzerUiSettings"/> persists to
    /// <c>%TEMP%\antistealer.json</c> instead of the old
    /// <c>AppContext.BaseDirectory + settings.json</c> location.
    ///
    /// These tests reach for the internal <c>SettingsPath</c> / <c>LegacySettingsPath</c>
    /// properties via <see cref="System.Runtime.CompilerServices.InternalsVisibleToAttribute"/>
    /// declared on AntiStealer.Core so we don't have to touch the public surface
    /// just to prove file-layout decisions in regression tests.
    /// </summary>
    public class AA5SettingsTempPathTests : IDisposable
    {
        // Snapshot the existing file (if any) before each test, restore on dispose,
        // so we don't trash a developer's real saved UI settings when running
        // `dotnet test` locally.
        private readonly string _savedTempCopy;
        private readonly string _savedLegacyCopy;
        private readonly string _settingsPath;
        private readonly string _legacyPath;

        public AA5SettingsTempPathTests()
        {
            _settingsPath    = AnalyzerUiSettings.SettingsPath;
            _legacyPath      = AnalyzerUiSettings.LegacySettingsPath;
            _savedTempCopy   = File.Exists(_settingsPath) ? File.ReadAllText(_settingsPath) : null!;
            _savedLegacyCopy = File.Exists(_legacyPath)   ? File.ReadAllText(_legacyPath)   : null!;
            // Start each test from a clean slate.
            SafeDelete(_settingsPath);
            SafeDelete(_legacyPath);
        }

        public void Dispose()
        {
            SafeDelete(_settingsPath);
            SafeDelete(_legacyPath);
            if (_savedTempCopy   != null) File.WriteAllText(_settingsPath, _savedTempCopy);
            if (_savedLegacyCopy != null) File.WriteAllText(_legacyPath,   _savedLegacyCopy);
        }

        private static void SafeDelete(string p)
        {
            try { if (File.Exists(p)) File.Delete(p); } catch { }
        }

        [Fact]
        public void SettingsPath_is_under_Path_GetTempPath_and_named_antistealer_json()
        {
            // The two contractual properties of the new path: it lives under
            // %TEMP% (Path.GetTempPath() — cross-platform) and is named
            // exactly "antistealer.json" (the legacy file was "settings.json").
            string expected = Path.Combine(Path.GetTempPath(), "antistealer.json");
            Assert.Equal(expected, AnalyzerUiSettings.SettingsPath);
            Assert.Equal("antistealer.json", Path.GetFileName(AnalyzerUiSettings.SettingsPath));
            Assert.StartsWith(Path.GetTempPath().TrimEnd('/', '\\'),
                              Path.GetDirectoryName(AnalyzerUiSettings.SettingsPath)!,
                              StringComparison.Ordinal);
        }

        [Fact]
        public void Save_writes_antistealer_json_into_temp_dir()
        {
            var s = new AnalyzerUiSettings
            {
                MaxArchiveDepth = 7,
                Locale          = "ru",
                LayoutPreset    = "compact",
            };
            s.Save();

            Assert.True(File.Exists(_settingsPath),
                "Save() should produce %TEMP%/antistealer.json");
            // Sanity-check the on-disk format: still indented JSON of the
            // AnalyzerUiSettings type, so backwards-compatible at the wire level.
            var roundTripped = JsonSerializer.Deserialize<AnalyzerUiSettings>(File.ReadAllText(_settingsPath))!;
            Assert.Equal(7,         roundTripped.MaxArchiveDepth);
            Assert.Equal("ru",      roundTripped.Locale);
            Assert.Equal("compact", roundTripped.LayoutPreset);
        }

        [Fact]
        public void Load_returns_defaults_when_no_file_exists()
        {
            // SafeDelete was already called in the ctor — both files are absent.
            var s = AnalyzerUiSettings.Load();
            Assert.NotNull(s);
            // Defaults from the property initialisers.
            Assert.True(s.RecursiveScan);
            Assert.Equal(3,  s.MaxArchiveDepth);
            Assert.Equal(64, s.MaxInputFileSizeMb);
        }

        [Fact]
        public void Load_migrates_from_legacy_settings_json_when_temp_file_absent()
        {
            // Simulate an old install: only the legacy file exists, with a
            // non-default MaxArchiveDepth so we can verify the migration moved
            // the actual values across (not just an empty defaults object).
            var legacy = new AnalyzerUiSettings { MaxArchiveDepth = 9, Locale = "uk" };
            File.WriteAllText(_legacyPath,
                JsonSerializer.Serialize(legacy, JsonOptionsRegistry.Indented));

            var loaded = AnalyzerUiSettings.Load();
            Assert.Equal(9,   loaded.MaxArchiveDepth);
            Assert.Equal("uk", loaded.Locale);

            // The migration step should have rewritten the file into the
            // new %TEMP% location so we don't read the legacy file on every
            // subsequent boot.
            Assert.True(File.Exists(_settingsPath),
                "After Load() sees a legacy file, %TEMP%/antistealer.json must exist.");
        }

        [Fact]
        public void Save_deletes_legacy_settings_json_after_writing_new_file()
        {
            // Pre-condition: there is a legacy file on disk (from before the
            // upgrade) AND the user has just changed something in the dialog,
            // triggering Save().
            File.WriteAllText(_legacyPath,
                JsonSerializer.Serialize(new AnalyzerUiSettings(),
                                         JsonOptionsRegistry.Indented));
            Assert.True(File.Exists(_legacyPath));

            new AnalyzerUiSettings { MaxArchiveDepth = 4 }.Save();

            Assert.True (File.Exists(_settingsPath),
                "Save() must create the new %TEMP%/antistealer.json file.");
            Assert.False(File.Exists(_legacyPath),
                "Save() must clean up the legacy settings.json after migration.");
        }
    }
}
