// PR 10 — Section 8.3 .. 8.7 (UX uplift):
//
//   8.3  Model-View-Update (MVU) dispatcher. A tiny generic
//        Update / dispatch loop that the WinForms front-end (or any
//        future UI surface — REST, console, Avalonia) plugs into.
//        Decouples state changes from the view so we can unit-test the
//        application's behaviour without spinning up a Form.
//   8.4  LayoutAdapter — derives panel sizes from window dimensions
//        and saved layout preset (classic / compact / wide). Keeps the
//        WinForms control hierarchy in sync with the persisted
//        AnalyzerUiSettings.
//   8.5  I18n — string catalog (currently RU primary, with EN and UK
//        fallbacks) keyed by stable identifiers. The WinForms shell
//        reads every label/menu/button/tooltip through I18n.Get(key)
//        so adding a new locale is a one-line catalog entry.
//   8.6  ThemePalette — named colour tokens for the dark / light themes
//        consumed by the form, the row context menu, the grid styling,
//        and the future tabbed views. All references go through the
//        token map so we can re-skin without touching call sites.
//   8.7  Drag-and-drop highlight — pure state primitive (IsHighlighting
//        on the MVU model) the form binds to a border-redraw. Sits in
//        Core so it can be unit-tested in isolation.

using System;
using System.Collections.Generic;
using System.Globalization;

namespace AntiStealerOneExe
{
    // -----------------------------------------------------------------
    // 8.5  I18n
    // -----------------------------------------------------------------

    public static class I18n
    {
        // Catalog is keyed (key, locale) -> string. Locales:
        //   "ru" — primary (most strings authored in Russian),
        //   "en" — English fallback,
        //   "uk" — Ukrainian fallback (kept partial; falls back to ru/en).
        // Missing key/locale combinations fall back to en, then ru, then
        // the literal key so the UI never shows a blank label.
        private static readonly Dictionary<string, Dictionary<string, string>> _cat = Build();

        public static IReadOnlyList<string> SupportedLocales => new[] { "ru", "en", "uk" };

        public static string Get(string key, string? locale = null)
        {
            locale ??= CurrentLocale;
            if (_cat.TryGetValue(key, out var byLocale))
            {
                if (byLocale.TryGetValue(locale, out var s) && !string.IsNullOrEmpty(s)) return s;
                if (byLocale.TryGetValue("en", out s) && !string.IsNullOrEmpty(s)) return s;
                if (byLocale.TryGetValue("ru", out s) && !string.IsNullOrEmpty(s)) return s;
            }
            return key;
        }

        public static string CurrentLocale { get; set; } = DefaultLocale();

        private static string DefaultLocale()
        {
            try
            {
                var n = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName?.ToLowerInvariant();
                return n switch
                {
                    "ru" => "ru",
                    "uk" => "uk",
                    _    => "en",
                };
            }
            catch { return "en"; }
        }

        private static Dictionary<string, Dictionary<string, string>> Build()
        {
            var d = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);

            void Add(string key, string ru, string en, string? uk = null)
            {
                var m = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ru"] = ru,
                    ["en"] = en,
                };
                if (!string.IsNullOrEmpty(uk)) m["uk"] = uk!;
                d[key] = m;
            }

            // Window chrome
            Add("app.title",            "AntiStealer One EXE Pro",                                       "AntiStealer One EXE Pro");
            Add("app.subtitle",         "Коммерческий статический анализатор",                          "Commercial static malware analyzer");

            // Main buttons
            Add("btn.add_files",        "Добавить файлы…",                                              "Add files…",        "Додати файли…");
            Add("btn.add_folder",       "Добавить папку…",                                              "Add folder…",       "Додати теку…");
            Add("btn.clear",            "Очистить",                                                     "Clear",             "Очистити");
            Add("btn.stop",             "Стоп",                                                         "Stop",              "Стоп");
            Add("btn.scan",             "Сканировать",                                                  "Scan",              "Сканувати");

            // Menu
            Add("menu.file",            "Файл",                                                         "File",              "Файл");
            Add("menu.view",            "Вид",                                                          "View",              "Вигляд");
            Add("menu.help",            "Справка",                                                      "Help",              "Довідка");
            Add("menu.language",        "Язык интерфейса",                                              "Interface language");
            Add("menu.compact",         "Компактный режим",                                             "Compact layout",    "Компактний режим");
            Add("menu.about",           "О программе…",                                                 "About…",            "Про програму…");

            // Filter row
            Add("filter.text",          "Текстовый фильтр",                                             "Text filter",       "Текстовий фільтр");
            Add("filter.risk",          "Уровень риска",                                                "Risk level",        "Рівень ризику");
            Add("filter.signed",        "только подписанные",                                           "signed only",       "лише підписані");
            Add("filter.packed",        "только упакованные",                                           "packed only",       "лише упаковані");

            // Drag-and-drop hint
            Add("dnd.hint",             "Перетащите файлы или папки сюда",                              "Drop files or folders here", "Перетягніть файли або теки сюди");
            Add("dnd.active",           "Отпустите, чтобы добавить",                                    "Release to add",    "Відпустіть, щоб додати");

            // Status / summary
            Add("status.ready",         "Готово",                                                       "Ready",             "Готово");
            Add("status.scanning",      "Сканирование…",                                                "Scanning…",         "Сканування…");
            Add("status.done",          "Анализ завершён",                                              "Analysis complete", "Аналіз завершено");
            Add("summary.files",        "файлов",                                                       "files");
            Add("summary.high",         "высокий риск",                                                 "high risk");
            Add("summary.medium",       "средний риск",                                                 "medium risk");
            Add("summary.low",          "низкий риск",                                                  "low risk");

            // Errors
            Add("err.no_files",         "Не выбраны файлы для сканирования.",                           "No files selected for scanning.");
            Add("err.access_denied",    "Нет доступа к файлу",                                          "Access denied");

            return d;
        }
    }

    // -----------------------------------------------------------------
    // 8.6  ThemePalette
    // -----------------------------------------------------------------

    public sealed class ThemePalette
    {
        // Named colour tokens (24-bit RGB packed as 0xRRGGBB).
        // Tokens are deliberately UI-agnostic — same names whether the
        // host is WinForms today, Avalonia tomorrow, or a web report.
        //
        // The framework intentionally exposes only a single (light)
        // palette: the dark variant was removed so every host — desktop
        // shell, HTML/PDF report, batch index — renders identically.
        public int WindowBg     { get; init; }
        public int WindowFg     { get; init; }
        public int PanelBg      { get; init; }
        public int PanelBorder  { get; init; }
        public int GridBg       { get; init; }
        public int GridFg       { get; init; }
        public int GridAltBg    { get; init; }
        public int GridGridLine { get; init; }
        public int Accent       { get; init; }
        public int AccentFg     { get; init; }
        public int RiskHigh     { get; init; }
        public int RiskMedium   { get; init; }
        public int RiskLow      { get; init; }
        public int DnDHighlight { get; init; }     // 8.7

        public static ThemePalette Light() => new()
        {
            WindowBg     = 0xF5F8FC,
            WindowFg     = 0x111111,
            PanelBg      = 0xFFFFFF,
            PanelBorder  = 0xCBD3DE,
            GridBg       = 0xFFFFFF,
            GridFg       = 0x111111,
            GridAltBg    = 0xF1F5F9,
            GridGridLine = 0xDDE3EC,
            Accent       = 0x1F6FEB,
            AccentFg     = 0xFFFFFF,
            RiskHigh     = 0xC62828,
            RiskMedium   = 0xEF6C00,
            RiskLow      = 0x2E7D32,
            DnDHighlight = 0x1F6FEB,
        };
    }

    // -----------------------------------------------------------------
    // 8.4  LayoutAdapter
    // -----------------------------------------------------------------

    public enum LayoutPreset
    {
        Classic = 0,
        Compact = 1,
        Wide    = 2,
    }

    public sealed class LayoutMetrics
    {
        public int GridHeight    { get; init; }
        public int DetailsHeight { get; init; }
        public int FilterHeight  { get; init; }
        public int ToolbarHeight { get; init; }
        public int Padding       { get; init; }
        public bool ShowFilter   { get; init; } = true;
    }

    public static class LayoutAdapter
    {
        // The form's height budget — toolbar + filter + grid + details +
        // status. We pick a percentage split per preset and clamp grid/details
        // to a reasonable minimum so neither side ever collapses.
        public static LayoutMetrics Compute(int windowHeight, LayoutPreset preset)
        {
            int toolbar = preset == LayoutPreset.Compact ? 32 : 40;
            int filter  = preset == LayoutPreset.Compact ? 28 : 36;
            int padding = preset == LayoutPreset.Compact ? 4  : 8;
            int statusBudget = 28 + padding * 4;
            int content = Math.Max(0, windowHeight - toolbar - filter - statusBudget);

            double gridFraction = preset switch
            {
                LayoutPreset.Compact => 0.75,
                LayoutPreset.Wide    => 0.80,
                _                    => 0.65,
            };
            int grid = (int)(content * gridFraction);
            int details = content - grid;
            grid    = Math.Max(120, grid);
            details = Math.Max(80,  details);

            return new LayoutMetrics
            {
                GridHeight    = grid,
                DetailsHeight = details,
                FilterHeight  = filter,
                ToolbarHeight = toolbar,
                Padding       = padding,
                ShowFilter    = preset != LayoutPreset.Compact || windowHeight >= 600,
            };
        }
    }

    // -----------------------------------------------------------------
    // 8.3  Model-View-Update dispatcher
    //
    // Pure-data generic dispatcher: callers supply an immutable Update
    // function (Model, Msg) -> Model. The dispatcher fires `Changed`
    // when the model identity moves; views re-render on that event.
    // -----------------------------------------------------------------

    public sealed class MvuDispatcher<TModel, TMsg>
    {
        private readonly Func<TModel, TMsg, TModel> _update;
        private TModel _model;

        public MvuDispatcher(TModel initial, Func<TModel, TMsg, TModel> update)
        {
            _model = initial;
            _update = update ?? throw new ArgumentNullException(nameof(update));
        }

        public TModel Model => _model;
        public event Action<TModel>? Changed;

        public void Dispatch(TMsg msg)
        {
            var prev = _model;
            var next = _update(prev, msg);
            _model = next;
            if (!EqualityComparer<TModel>.Default.Equals(prev, next))
                Changed?.Invoke(next);
        }
    }

    // -----------------------------------------------------------------
    // 8.7  D&D state primitive (model record used by the form's dispatcher)
    // -----------------------------------------------------------------

    public sealed record UxAppModel
    {
        public string Locale           { get; init; } = "ru";
        public LayoutPreset Preset     { get; init; } = LayoutPreset.Classic;
        public bool IsScanning         { get; init; }
        public bool IsDragHighlighting { get; init; }   // 8.7
        public int LoadedFileCount     { get; init; }
        public int CompletedFileCount  { get; init; }
        public string LastStatusKey    { get; init; } = "status.ready";
    }

    public abstract record UxAppMsg
    {
        public sealed record SetLocale(string Locale) : UxAppMsg;
        public sealed record SetPreset(LayoutPreset Preset) : UxAppMsg;
        public sealed record StartScan() : UxAppMsg;
        public sealed record StopScan() : UxAppMsg;
        public sealed record FileLoaded(int Delta) : UxAppMsg;
        public sealed record FileCompleted(int Delta) : UxAppMsg;
        public sealed record DragEnter() : UxAppMsg;
        public sealed record DragLeave() : UxAppMsg;
        public sealed record SetStatus(string Key) : UxAppMsg;
    }

    public static class UxAppReducer
    {
        public static UxAppModel Update(UxAppModel m, UxAppMsg msg) => msg switch
        {
            UxAppMsg.SetLocale x       => m with { Locale = x.Locale },
            UxAppMsg.SetPreset x       => m with { Preset = x.Preset },
            UxAppMsg.StartScan _       => m with { IsScanning = true,  LastStatusKey = "status.scanning" },
            UxAppMsg.StopScan _        => m with { IsScanning = false, LastStatusKey = "status.done" },
            UxAppMsg.FileLoaded x      => m with { LoadedFileCount = Math.Max(0, m.LoadedFileCount + x.Delta) },
            UxAppMsg.FileCompleted x   => m with { CompletedFileCount = Math.Max(0, m.CompletedFileCount + x.Delta) },
            UxAppMsg.DragEnter _       => m with { IsDragHighlighting = true },
            UxAppMsg.DragLeave _       => m with { IsDragHighlighting = false },
            UxAppMsg.SetStatus x       => m with { LastStatusKey = x.Key },
            _                          => m,
        };
    }
}
