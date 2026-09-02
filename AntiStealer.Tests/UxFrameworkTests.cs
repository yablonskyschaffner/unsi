using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests
{
    public class UxFrameworkTests
    {
        // ----------------------------------------------------------------
        // 8.5 — I18n
        // ----------------------------------------------------------------

        [Fact]
        public void I18n_ReturnsKnownStrings_ForAllSupportedLocales()
        {
            foreach (var loc in I18n.SupportedLocales)
            {
                Assert.False(string.IsNullOrEmpty(I18n.Get("btn.add_files", loc)));
                Assert.False(string.IsNullOrEmpty(I18n.Get("menu.compact", loc)));
                Assert.False(string.IsNullOrEmpty(I18n.Get("dnd.hint", loc)));
            }
        }

        [Fact]
        public void I18n_DropsDarkThemeKey()
        {
            // The dark-theme menu entry was removed in the UX cleanup pass.
            // Confirm the key now falls back to its own name (i.e. is missing
            // from the catalogue) so accidental re-introductions are caught.
            Assert.Equal("menu.dark_theme", I18n.Get("menu.dark_theme", "ru"));
            Assert.Equal("menu.dark_theme", I18n.Get("menu.dark_theme", "en"));
        }

        [Fact]
        public void I18n_RuAndEnDiffer_ForTranslatedKeys()
        {
            Assert.NotEqual(I18n.Get("btn.scan", "ru"), I18n.Get("btn.scan", "en"));
            Assert.Equal("Сканировать", I18n.Get("btn.scan", "ru"));
            Assert.Equal("Scan",         I18n.Get("btn.scan", "en"));
        }

        [Fact]
        public void I18n_UnknownLocaleFallsBackToEn()
        {
            Assert.Equal(I18n.Get("btn.clear", "en"), I18n.Get("btn.clear", "de"));
        }

        [Fact]
        public void I18n_MissingKey_ReturnsKeyItself()
        {
            Assert.Equal("nope.does.not.exist", I18n.Get("nope.does.not.exist", "ru"));
        }

        [Fact]
        public void I18n_PartialUkraineCatalog_FallsBackGracefully()
        {
            // "menu.about" is intentionally en-only ; ensure UK falls back.
            var uk = I18n.Get("menu.about", "uk");
            Assert.False(string.IsNullOrEmpty(uk));
        }

        // ----------------------------------------------------------------
        // 8.6 — ThemePalette (single light variant)
        // ----------------------------------------------------------------

        [Fact]
        public void ThemePalette_Light_HasNonZeroTokens()
        {
            // After the dark variant was removed there is exactly one
            // palette — sanity-check that every token is populated so the
            // WinForms host can't accidentally bind black-on-black.
            var l = ThemePalette.Light();
            Assert.NotEqual(0, l.WindowBg);
            Assert.NotEqual(0, l.PanelBg);
            Assert.NotEqual(0, l.GridBg);
            Assert.NotEqual(0, l.Accent);
            Assert.NotEqual(0, l.RiskHigh);
            Assert.NotEqual(0, l.RiskMedium);
            Assert.NotEqual(0, l.RiskLow);
            Assert.NotEqual(0, l.DnDHighlight);
        }

        // ----------------------------------------------------------------
        // 8.4 — LayoutAdapter
        // ----------------------------------------------------------------

        [Fact]
        public void LayoutAdapter_AllocatesMoreGridSpace_InCompactPreset()
        {
            var classic = LayoutAdapter.Compute(900, LayoutPreset.Classic);
            var compact = LayoutAdapter.Compute(900, LayoutPreset.Compact);
            Assert.True(compact.GridHeight > classic.GridHeight);
        }

        [Fact]
        public void LayoutAdapter_NeverCollapsesEitherPanel()
        {
            // Even at a tiny window size, both grid and details must keep
            // a sensible minimum.
            var m = LayoutAdapter.Compute(200, LayoutPreset.Classic);
            Assert.True(m.GridHeight    >= 120);
            Assert.True(m.DetailsHeight >= 80);
        }

        [Fact]
        public void LayoutAdapter_ToolbarAndFilterShrinkInCompact()
        {
            var c = LayoutAdapter.Compute(900, LayoutPreset.Classic);
            var k = LayoutAdapter.Compute(900, LayoutPreset.Compact);
            Assert.True(k.ToolbarHeight <  c.ToolbarHeight);
            Assert.True(k.FilterHeight  <= c.FilterHeight);
            Assert.True(k.Padding       <= c.Padding);
        }

        [Fact]
        public void LayoutAdapter_HidesFilter_WhenWindowTinyAndCompact()
        {
            var m = LayoutAdapter.Compute(400, LayoutPreset.Compact);
            Assert.False(m.ShowFilter);
        }

        // ----------------------------------------------------------------
        // 8.3 — MVU dispatcher + 8.7 — D&D state
        // ----------------------------------------------------------------

        [Fact]
        public void Mvu_Dispatch_AppliesReducer_AndFiresChanged()
        {
            int fired = 0;
            var d = new MvuDispatcher<UxAppModel, UxAppMsg>(new UxAppModel(), UxAppReducer.Update);
            d.Changed += _ => fired++;

            d.Dispatch(new UxAppMsg.SetLocale("en"));
            Assert.Equal("en", d.Model.Locale);
            Assert.Equal(1, fired);

            // Dispatching the same value is a no-op (record equality keeps
            // the model identical, so MvuDispatcher must not re-fire).
            d.Dispatch(new UxAppMsg.SetLocale("en"));
            Assert.Equal(1, fired);
        }

        [Fact]
        public void Mvu_StartAndStopScan_TogglesStatusKey()
        {
            var d = new MvuDispatcher<UxAppModel, UxAppMsg>(new UxAppModel(), UxAppReducer.Update);
            d.Dispatch(new UxAppMsg.StartScan());
            Assert.True(d.Model.IsScanning);
            Assert.Equal("status.scanning", d.Model.LastStatusKey);

            d.Dispatch(new UxAppMsg.StopScan());
            Assert.False(d.Model.IsScanning);
            Assert.Equal("status.done", d.Model.LastStatusKey);
        }

        [Fact]
        public void Mvu_FileLoaded_NeverDropsBelowZero()
        {
            var d = new MvuDispatcher<UxAppModel, UxAppMsg>(new UxAppModel { LoadedFileCount = 2 }, UxAppReducer.Update);
            d.Dispatch(new UxAppMsg.FileLoaded(-5));
            Assert.Equal(0, d.Model.LoadedFileCount);
        }

        [Fact]
        public void Mvu_DragEnter_AndLeave_TogglesHighlight()
        {
            var d = new MvuDispatcher<UxAppModel, UxAppMsg>(new UxAppModel(), UxAppReducer.Update);
            d.Dispatch(new UxAppMsg.DragEnter());
            Assert.True(d.Model.IsDragHighlighting);
            d.Dispatch(new UxAppMsg.DragLeave());
            Assert.False(d.Model.IsDragHighlighting);
        }

        [Fact]
        public void Mvu_SetLocaleAndPreset_RoundTripsThroughModel()
        {
            var d = new MvuDispatcher<UxAppModel, UxAppMsg>(new UxAppModel(), UxAppReducer.Update);
            d.Dispatch(new UxAppMsg.SetLocale("uk"));
            d.Dispatch(new UxAppMsg.SetPreset(LayoutPreset.Wide));
            Assert.Equal("uk", d.Model.Locale);
            Assert.Equal(LayoutPreset.Wide, d.Model.Preset);
        }
    }
}
