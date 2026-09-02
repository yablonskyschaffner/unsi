// AA5: extracted from AntiStealerOneExe/Program.cs into AntiStealer.UI.dll.
// MainForm / SettingsForm + their nested helpers live here so the WinForms
// surface ships as a side-by-side library, mirroring the Engine.dll split.
// Namespace kept as AntiStealerOneExe for type-name compatibility with the
// exe Program.cs (it constructs `new MainForm()` exactly as before).
using System.IO.Compression;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Reflection.PortableExecutable;
using AntiStealer.Engine;

namespace AntiStealerOneExe
{
    public sealed class MainForm : Form
    {
        private readonly DataGridView _grid = new();
        private readonly TextBox _details = new();
        private readonly Button _btnAddFiles = new();
        private readonly Button _btnAddFolder = new();
        private readonly Button _btnClear = new();
        private readonly Button _btnStop = new();
        private readonly Label _hint = new();
        private readonly Label _summary = new();
        private readonly Label _status = new();
        private readonly ProgressBar _progress = new();
        private readonly CheckBox _recursive = new();
        private readonly MenuStrip _menu = new();

        // D4: filter row.
        private readonly TextBox _filterText = new();
        private readonly ComboBox _filterRisk = new();
        private readonly CheckBox _filterSigned = new();
        private readonly CheckBox _filterPacked = new();
        // D9: row context menu.
        private ContextMenuStrip? _rowMenu;
        // D11: scan-speed tracking.
        private DateTime _scanStartedAt;
        private long _scanBytesTotal;
        private long _scanBytesDone;

        // M12: column index map so grid lookups don't depend on column order.
        private static class Col
        {
            public const int File = 0, Type = 1, Arch = 2, Risk = 3, Level = 4, Family = 5, Conf = 6,
                Net = 7, Packed = 8, Signed = 9, Heur = 10, URLs = 11, APIs = 12, IOCs = 13,
                SHA256 = 14, Why = 15;
        }

        // F1: _loadedFiles is accessed concurrently during parallel scans; guard with a dedicated lock.
        private readonly HashSet<string> _loadedFiles = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _loadedFilesLock = new();

        private bool TryRegisterFile(string key)
        {
            lock (_loadedFilesLock) return _loadedFiles.Add(key);
        }
        private AnalyzerUiSettings _settings = AnalyzerUiSettings.Load();
        // AA4: the WinForms shell drives the scanner exclusively through the
        // public AntiStealer.Engine.IAntiStealerEngine facade. The instance is
        // rebuilt whenever the user saves the Settings dialog so cloud-API key
        // and parser-limit changes take effect immediately.
        private IAntiStealerEngine _engine;
        private CancellationTokenSource? _scanCts;
        private bool _isScanning;

        // Section 8.3 (PR 10) — MVU dispatcher backing the WinForms shell.
        // Pure state lives in UxAppModel; the form rebinds visible elements
        // when Changed fires.
        private MvuDispatcher<UxAppModel, UxAppMsg> _ux = null!;

        public MainForm()
        {
            // AA4: build the engine facade with the just-loaded settings so the
            // first scan picks up cloud API keys / parser limits without needing
            // the settings dialog to be opened first.
            _engine = AntiStealerEngineFactory.Create(new EngineOptions
            {
                AdvancedSettings      = _settings,
                EnableCloudEnrichment = true,
            });

            // 8.5 — load the persisted locale before any control string is
            // resolved through I18n.Get.
            if (!string.IsNullOrEmpty(_settings.Locale)) I18n.CurrentLocale = _settings.Locale;

            // 8.3 — initial MVU model mirrors the persisted settings.
            _ux = new MvuDispatcher<UxAppModel, UxAppMsg>(
                new UxAppModel
                {
                    Locale = string.IsNullOrEmpty(_settings.Locale) ? I18n.CurrentLocale : _settings.Locale,
                    Preset = ParsePreset(_settings.LayoutPreset),
                },
                UxAppReducer.Update);
            _ux.Changed += OnUxModelChanged;

            Text = I18n.Get("app.title") + " — " + I18n.Get("app.subtitle");
            Width = 1500;
            Height = 900;
            MinimumSize = new System.Drawing.Size(1200, 700);
            BackColor = System.Drawing.Color.FromArgb(245, 248, 252);

            BuildMenu();
            ConfigureControls();
            BuildRowContextMenu();  // D9
            BindDragDrop();
            BindKeyboardShortcuts();  // D13
            ApplySettingsToUi();
            RestoreWindowState();     // D7
            ApplyTheme();             // D1
            ApplyLayout();            // 8.4
            UpdateSummary();

            FormClosing += (_, _) => PersistWindowState();  // D7
        }

        // D7: push persisted geometry back to the form (if we have any saved).
        private void RestoreWindowState()
        {
            if (_settings.WindowWidth > 300 && _settings.WindowHeight > 200)
            {
                Width = _settings.WindowWidth;
                Height = _settings.WindowHeight;
            }
            if (_settings.WindowLeft >= 0 && _settings.WindowTop >= 0)
            {
                StartPosition = FormStartPosition.Manual;
                Left = _settings.WindowLeft;
                Top = _settings.WindowTop;
            }
            if (_settings.WindowMaximized) WindowState = FormWindowState.Maximized;
        }

        private void PersistWindowState()
        {
            try
            {
                _settings.WindowMaximized = WindowState == FormWindowState.Maximized;
                if (WindowState == FormWindowState.Normal)
                {
                    _settings.WindowWidth = Width;
                    _settings.WindowHeight = Height;
                    _settings.WindowLeft = Left;
                    _settings.WindowTop = Top;
                }
                _settings.Save();
            }
            catch { }
        }

        private static LayoutPreset ParsePreset(string s) =>
            (s ?? "").ToLowerInvariant() switch
            {
                "compact" => LayoutPreset.Compact,
                "wide"    => LayoutPreset.Wide,
                _         => LayoutPreset.Classic,
            };

        // 8.3 — view-rebind. Called whenever the MVU dispatcher moves to a
        // new immutable model. We mirror the new values back to the host
        // form / persisted settings.
        private void OnUxModelChanged(UxAppModel m)
        {
            try
            {
                if (_settings.Locale != m.Locale)
                {
                    _settings.Locale = m.Locale;
                    I18n.CurrentLocale = m.Locale;
                    Text = I18n.Get("app.title") + " — " + I18n.Get("app.subtitle");
                    _settings.Save();
                }
                var presetName = m.Preset.ToString().ToLowerInvariant();
                if (_settings.LayoutPreset != presetName)
                {
                    _settings.LayoutPreset = presetName;
                    _settings.Save();
                    ApplyLayout();
                }
                // 8.7 — D&D border highlight.
                Padding = m.IsDragHighlighting
                    ? new Padding(3)
                    : new Padding(0);
                BackColor = m.IsDragHighlighting
                    ? RgbColor(ThemePalette.Light().DnDHighlight)
                    : RgbColor(ThemePalette.Light().WindowBg);
            }
            catch { /* never block the dispatcher */ }
        }

        // 8.4 — apply the layout preset by adjusting the grid / details
        // split row sizes if a TableLayoutPanel is in play. Implementation
        // is intentionally tolerant of the existing dock-based layout: it
        // just resizes the details panel if it can find one.
        private void ApplyLayout()
        {
            var metrics = LayoutAdapter.Compute(Height, ParsePreset(_settings.LayoutPreset));
            try
            {
                if (_details != null)
                {
                    _details.Height = metrics.DetailsHeight;
                }
            }
            catch { }
        }

        private static System.Drawing.Color RgbColor(int rgb) =>
            System.Drawing.Color.FromArgb(
                (rgb >> 16) & 0xFF,
                (rgb >> 8)  & 0xFF,
                rgb         & 0xFF);

        // 8.6: apply the (single, light) themed colour tokens to all
        // known controls. The dark variant was removed — operators get one
        // consistent palette, sized for high-contrast review use.
        private void ApplyTheme()
        {
            var p     = ThemePalette.Light();
            var bg    = RgbColor(p.WindowBg);
            var panel = RgbColor(p.PanelBg);
            var fg    = RgbColor(p.WindowFg);
            var grid  = RgbColor(p.GridBg);

            BackColor = bg;
            ForeColor = fg;
            foreach (Control c in Controls) ApplyThemeToControl(c, bg, panel, fg);

            _grid.BackgroundColor = grid;
            _grid.DefaultCellStyle.BackColor = grid;
            _grid.DefaultCellStyle.ForeColor = fg;
            _grid.ColumnHeadersDefaultCellStyle.BackColor = panel;
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = fg;
            _grid.EnableHeadersVisualStyles = true;
            _grid.GridColor = System.Drawing.SystemColors.ControlDark;

            _details.BackColor = panel;
            _details.ForeColor = fg;

            _menu.BackColor = panel;
            _menu.ForeColor = fg;
        }

        private static void ApplyThemeToControl(Control c, System.Drawing.Color bg, System.Drawing.Color panel, System.Drawing.Color fg)
        {
            if (c is Button || c is TextBox || c is ComboBox || c is CheckBox || c is Label || c is ProgressBar)
            {
                c.BackColor = (c is Button || c is TextBox || c is ComboBox) ? panel : bg;
                c.ForeColor = fg;
            }
            else
            {
                c.BackColor = bg;
                c.ForeColor = fg;
            }
            foreach (Control child in c.Controls)
                ApplyThemeToControl(child, bg, panel, fg);
        }

        // D13: keyboard shortcuts.
        private void BindKeyboardShortcuts()
        {
            KeyPreview = true;
            KeyDown += async (_, e) =>
            {
                if (e.Control && e.KeyCode == Keys.O && !e.Shift) { await PickFilesAsync(); e.Handled = true; }
                else if (e.Control && e.Shift && e.KeyCode == Keys.O) { await PickFolderAsync(); e.Handled = true; }
                else if (e.Control && e.KeyCode == Keys.E) { ExportCsv(); e.Handled = true; }
                else if (e.Control && e.KeyCode == Keys.J) { ExportAll(".json"); e.Handled = true; }
                else if (e.Control && e.KeyCode == Keys.H) { ExportAll(".html"); e.Handled = true; }
                else if (e.KeyCode == Keys.F5 && !_isScanning) { /* reserved for rescan */ }
                else if (e.KeyCode == Keys.Escape && _isScanning) { RequestStop(); e.Handled = true; }
                else if (e.KeyCode == Keys.Delete && _grid.CurrentRow != null)
                {
                    if (!_isScanning)
                    {
                        var row = _grid.CurrentRow;
                        if (row.Tag is AnalysisResult r)
                            lock (_loadedFilesLock) _loadedFiles.Remove(r.FilePath);
                        _grid.Rows.Remove(row);
                        UpdateSummary();
                        e.Handled = true;
                    }
                }
            };
        }
        private void BuildMenu()
        {
            var fileMenu = new ToolStripMenuItem("Файл");
            var miAddFiles = new ToolStripMenuItem("Добавить файлы…", null, async (_, _) => await PickFilesAsync());
            var miAddFolder = new ToolStripMenuItem("Добавить папку…", null, async (_, _) => await PickFolderAsync());
            var miExportRow = new ToolStripMenuItem("Экспорт отчета выбранной строки…", null, (_, _) => ExportSelectedReport());
            var miExportAll = new ToolStripMenuItem("Экспорт сводки CSV…", null, (_, _) => ExportCsv());
            // E1–E6: new export formats.
            var miExportJson  = new ToolStripMenuItem("Экспорт JSON…",  null, (_, _) => ExportAll(".json"));
            var miExportHtml  = new ToolStripMenuItem("Экспорт HTML…",  null, (_, _) => ExportAll(".html"));
            var miExportPdf   = new ToolStripMenuItem("Экспорт PDF…",   null, (_, _) => ExportAll(".pdf"));
            var miExportStix  = new ToolStripMenuItem("Экспорт STIX 2.1 bundle…", null, (_, _) => ExportAll(".stix.json"));
            var miExportSarif = new ToolStripMenuItem("Экспорт SARIF…", null, (_, _) => ExportAll(".sarif"));
            var miExportBatch = new ToolStripMenuItem("Сводный batch-отчёт (HTML index)…", null, (_, _) => ExportBatch());
            var miExit = new ToolStripMenuItem("Выход", null, (_, _) => Close());
            fileMenu.DropDownItems.AddRange(new ToolStripItem[]
            {
                miAddFiles, miAddFolder, new ToolStripSeparator(),
                miExportRow, miExportAll, new ToolStripSeparator(),
                miExportJson, miExportHtml, miExportPdf, miExportStix, miExportSarif, miExportBatch,
                new ToolStripSeparator(), miExit,
            });

            var settingsMenu = new ToolStripMenuItem("Настройки", null, (_, _) => ShowSettingsDialog());
            // 8.6: dark-theme toggle was removed — the app ships a single
            // high-contrast light palette.
            //
            // AA5: "Вид" (View) menu removed by request — compact-layout toggle,
            // language submenu and Dashboard launcher are no longer reachable
            // from the menu strip. Compact / locale preferences continue to be
            // honoured at startup from the persisted AnalyzerUiSettings, and
            // ShowDashboard() is kept private so it can be re-exposed later
            // without re-introducing the View tab. UxAppMsg.SetPreset /
            // SetLocale dispatchers are still invoked by the underlying MVU
            // pipeline; only the menu-strip surface is gone.

            var helpMenu = new ToolStripMenuItem("Справка");
            var aboutText = @"AntiStealer One EXE

Коммерческая desktop-версия статического анализатора вредоносных PE/архивов.

Возможности:
• Deep static scan (PE + IOC + API + секции + entropy + overlay)
• 1000+ внутренних эвристик и сценарных правил
• Детект токенов/ключей/крипто-артефактов
• Family-классификация (локальная + опциональная серверная)
• Экспорт отчетов TXT/CSV

Редакция: Professional
Версия: 1.2 Pro
Поддержка: support@antistealer.local";
            var miAbout = new ToolStripMenuItem("О программе", null, (_, _) => MessageBox.Show(this, aboutText,
                "О программе", MessageBoxButtons.OK, MessageBoxIcon.Information));
            helpMenu.DropDownItems.Add(miAbout);

            _menu.Items.AddRange(new ToolStripItem[] { fileMenu, settingsMenu, helpMenu });
            _menu.Dock = DockStyle.Top;
            MainMenuStrip = _menu;
            Controls.Add(_menu);
        }

        private void ConfigureControls()
        {
            _btnAddFiles.Text = "Добавить файл(ы)…";
            _btnAddFiles.Left = 10; _btnAddFiles.Top = 34; _btnAddFiles.Width = 170;
            _btnAddFiles.Click += async (_, _) => await PickFilesAsync();

            _btnAddFolder.Text = "Добавить папку…";
            _btnAddFolder.Left = 190; _btnAddFolder.Top = 34; _btnAddFolder.Width = 160;
            _btnAddFolder.Click += async (_, _) => await PickFolderAsync();

            _recursive.Text = "Рекурсивно";
            _recursive.Left = 360; _recursive.Top = 38; _recursive.Width = 120;
            _recursive.CheckedChanged += (_, _) => _settings.RecursiveScan = _recursive.Checked;

            _btnStop.Text = "Стоп";
            _btnStop.Left = 490; _btnStop.Top = 34; _btnStop.Width = 80;
            _btnStop.Enabled = false;
            _btnStop.Click += (_, _) => RequestStop();

            _btnClear.Text = "Очистить";
            _btnClear.Left = 580; _btnClear.Top = 34; _btnClear.Width = 100;
            _btnClear.Click += (_, _) =>
            {
                if (_isScanning) return;
                _grid.Rows.Clear();
                _details.Clear();
                lock (_loadedFilesLock) _loadedFiles.Clear();
                _status.Text = "Готово";
                _progress.Value = 0;
                UpdateSummary();
            };

            _hint.Text = "Поддержка: файлы, папки и ZIP/JAR/APK архивы. Детект: IOC/API/PE + 6000+ кастомных эвристик.";
            _hint.Left = 700; _hint.Top = 38; _hint.Width = 780;
            _hint.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            _summary.Left = 10; _summary.Top = 66; _summary.Width = 1460;
            _summary.Height = 24;
            _summary.Font = new System.Drawing.Font("Segoe UI", 9, System.Drawing.FontStyle.Bold);
            _summary.Text = "Нет загруженных объектов";
            _summary.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            _progress.Left = 10; _progress.Top = 94; _progress.Width = 1200; _progress.Height = 14;
            _progress.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _status.Left = 1220; _status.Top = 90; _status.Width = 250; _status.Height = 20;
            _status.Text = "Готово";
            _status.Anchor = AnchorStyles.Top | AnchorStyles.Right;

            // D4: filter row above the grid.
            _filterText.Left = 10; _filterText.Top = 120; _filterText.Width = 320;
            _filterText.PlaceholderText = "Фильтр по имени / SHA / family / reasons…";
            _filterText.TextChanged += (_, _) => ApplyRowFilter();

            var lblRisk = new Label { Text = "Уровень:", Left = 340, Top = 124, Width = 66 };
            _filterRisk.Left = 406; _filterRisk.Top = 120; _filterRisk.Width = 130;
            _filterRisk.DropDownStyle = ComboBoxStyle.DropDownList;
            _filterRisk.Items.AddRange(new object[] { "Все", "HIGH", "MED", "LOW", "ERROR" });
            _filterRisk.SelectedIndex = 0;
            _filterRisk.SelectedIndexChanged += (_, _) => ApplyRowFilter();

            _filterSigned.Left = 546; _filterSigned.Top = 122; _filterSigned.Width = 140;
            _filterSigned.Text = "Только unsigned";
            _filterSigned.CheckedChanged += (_, _) => ApplyRowFilter();

            _filterPacked.Left = 696; _filterPacked.Top = 122; _filterPacked.Width = 110;
            _filterPacked.Text = "Только packed";
            _filterPacked.CheckedChanged += (_, _) => ApplyRowFilter();

            Controls.AddRange(new Control[] { _filterText, lblRisk, _filterRisk, _filterSigned, _filterPacked });

            _grid.Left = 10; _grid.Top = 148; _grid.Width = 1460; _grid.Height = 400;
            _grid.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            _grid.ReadOnly = true;
            _grid.AllowUserToAddRows = false;
            _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _grid.MultiSelect = false;
            _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            _grid.RowHeadersVisible = false;
            _grid.BackgroundColor = System.Drawing.Color.White;
            _grid.BorderStyle = BorderStyle.FixedSingle;
            _grid.Columns.Add("File", "File");
            _grid.Columns.Add("Type", "Type");
            _grid.Columns.Add("Arch", "Arch");
            _grid.Columns.Add("Risk", "Risk");
            _grid.Columns.Add("Level", "Level");
            _grid.Columns.Add("Family", "Family");
            _grid.Columns.Add("Conf", "Conf");
            _grid.Columns.Add("Net", "Net?");
            _grid.Columns.Add("Packed", "Packed?");
            _grid.Columns.Add("Signed", "Signed?");
            _grid.Columns.Add("Heur", "Custom heur");
            _grid.Columns.Add("URLs", "URLs");
            _grid.Columns.Add("APIs", "API hits");
            _grid.Columns.Add("IOCs", "IOC hits");
            _grid.Columns.Add("SHA256", "SHA256 (short)");
            _grid.Columns.Add("Why", "Why (short)");
            // D7: allow sorting by any column by clicking its header.
            foreach (DataGridViewColumn col in _grid.Columns) col.SortMode = DataGridViewColumnSortMode.Automatic;

            _grid.CellClick += (_, e) =>
            {
                if (e.RowIndex < 0) return;
                var row = _grid.Rows[e.RowIndex];
                if (row.Tag is AnalysisResult r)
                    _details.Text = r.ToFullReport();
            };
            // D5: double-click opens tabbed details dialog.
            _grid.CellDoubleClick += (_, e) =>
            {
                if (e.RowIndex < 0) return;
                if (_grid.Rows[e.RowIndex].Tag is AnalysisResult r) ShowDetailsDialog(r);
            };
            // D9: right-click on row => show context menu.
            _grid.CellMouseDown += (_, e) =>
            {
                if (e.Button != MouseButtons.Right || e.RowIndex < 0) return;
                _grid.ClearSelection();
                _grid.Rows[e.RowIndex].Selected = true;
                _grid.CurrentCell = _grid.Rows[e.RowIndex].Cells[0];
                _rowMenu?.Show(Cursor.Position);
            };

            _details.Left = 10; _details.Top = 558; _details.Width = 1460; _details.Height = 294;
            _details.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom | AnchorStyles.Top;
            _details.Multiline = true;
            _details.ScrollBars = ScrollBars.Both;
            _details.Font = new System.Drawing.Font("Consolas", 10);
            _details.ReadOnly = true;
            _details.WordWrap = false;

            Controls.AddRange(new Control[] { _btnAddFiles, _btnAddFolder, _recursive, _btnStop, _btnClear, _hint, _summary, _progress, _status, _grid, _details });
        }

        // D11: enrich status label with ETA + throughput + current file.
        private void UpdateProgressStatus(int done, int total, string currentPath)
        {
            try
            {
                var elapsed = (DateTime.UtcNow - _scanStartedAt).TotalSeconds;
                double mbps = elapsed > 0.1 ? (_scanBytesDone / 1024.0 / 1024.0) / elapsed : 0.0;
                string eta = "—";
                if (done > 0 && total > done)
                {
                    var avgSec = elapsed / done;
                    var remain = TimeSpan.FromSeconds(avgSec * (total - done));
                    eta = remain.TotalMinutes >= 1 ? $"{(int)remain.TotalMinutes}m {remain.Seconds}s" : $"{remain.Seconds}s";
                }
                _status.Text = $"{done}/{total} · ETA {eta} · {mbps:0.0} MB/s · {Path.GetFileName(currentPath)}";
            }
            catch { }
        }

        // D4: hide rows that don't match the current filter combination.
        private void ApplyRowFilter()
        {
            var needle = (_filterText.Text ?? "").Trim();
            var levelSel = (_filterRisk.SelectedItem as string) ?? "Все";
            foreach (DataGridViewRow row in _grid.Rows)
            {
                bool keep = true;
                if (row.Tag is AnalysisResult r)
                {
                    if (_filterSigned.Checked && r.IsSigned) keep = false;
                    if (_filterPacked.Checked && !r.PackedLikely) keep = false;
                    if (keep && levelSel != "Все" &&
                        !string.Equals(r.RiskLevel, levelSel, StringComparison.OrdinalIgnoreCase))
                        keep = false;
                    if (keep && needle.Length > 0)
                    {
                        bool hit = r.FilePath.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0
                            || r.Sha256.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0
                            || r.FamilyName.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0
                            || (r.ReasonsShort ?? "").IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
                        if (!hit) keep = false;
                    }
                }
                row.Visible = keep;
            }
        }

        // D9: context menu on grid row.
        private void BuildRowContextMenu()
        {
            _rowMenu = new ContextMenuStrip();
            _rowMenu.Items.Add("Открыть папку",       null, (_, _) => RowAction(r => OpenFolderForResult(r)));
            _rowMenu.Items.Add("Скопировать SHA-256", null, (_, _) => RowAction(r => CopyText(r.Sha256)));
            _rowMenu.Items.Add("Скопировать путь",    null, (_, _) => RowAction(r => CopyText(r.FilePath)));
            _rowMenu.Items.Add("Искать на VirusTotal", null, (_, _) => RowAction(r =>
            {
                if (r.Sha256.Length == 64)
                    try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo($"https://www.virustotal.com/gui/file/{r.Sha256}") { UseShellExecute = true }); } catch { }
            }));
            _rowMenu.Items.Add(new ToolStripSeparator());
            _rowMenu.Items.Add("Экспорт отчёта JSON…", null, (_, _) => RowAction(r => ExportOne(r, ".json")));
            _rowMenu.Items.Add("Экспорт отчёта HTML…", null, (_, _) => RowAction(r => ExportOne(r, ".html")));
            _rowMenu.Items.Add(new ToolStripSeparator());
            _rowMenu.Items.Add("Переместить в карантин…", null, (_, _) => RowAction(Quarantine));
            _rowMenu.Items.Add("Удалить строку",            null, (_, _) => RowAction(r =>
            {
                if (_grid.CurrentRow != null)
                {
                    lock (_loadedFilesLock) _loadedFiles.Remove(r.FilePath);
                    _grid.Rows.Remove(_grid.CurrentRow);
                    UpdateSummary();
                }
            }));
        }

        private void RowAction(Action<AnalysisResult> a)
        {
            if (_grid.CurrentRow?.Tag is AnalysisResult r) a(r);
        }

        private static void CopyText(string s)
        {
            try { if (!string.IsNullOrEmpty(s)) Clipboard.SetText(s); } catch { }
        }

        private static void OpenFolderForResult(AnalysisResult r)
        {
            try
            {
                var dir = Path.GetDirectoryName(r.FilePath);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dir) { UseShellExecute = true });
            }
            catch { }
        }

        private void ExportOne(AnalysisResult r, string ext)
        {
            using var sfd = new SaveFileDialog
            {
                Filter = ext == ".json" ? "JSON (*.json)|*.json" : "HTML (*.html)|*.html",
                FileName = Path.GetFileName(r.FilePath) + ext,
            };
            if (sfd.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                var list = new[] { r };
                if (ext == ".json") File.WriteAllText(sfd.FileName, ReportWriter.ToJson(list), Encoding.UTF8);
                else                 File.WriteAllText(sfd.FileName, ReportWriter.ToHtml(list), Encoding.UTF8);
            }
            catch (Exception ex) { MessageBox.Show(this, "Ошибка экспорта: " + ex.Message, "Экспорт"); }
        }

        // D9/G9: move suspicious file into quarantine, XOR-encoding content so on-access AV doesn't
        // auto-delete it. Original path is recorded in a sidecar .meta file.
        private void Quarantine(AnalysisResult r)
        {
            try
            {
                if (!File.Exists(r.FilePath)) { MessageBox.Show(this, "Файл не найден.", "Карантин"); return; }
                if (MessageBox.Show(this,
                    $"Переместить {Path.GetFileName(r.FilePath)} в карантин?\nФайл будет XOR-обфусцирован.",
                    "Карантин", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

                var qdir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                        "AntiStealer", "Quarantine");
                Directory.CreateDirectory(qdir);
                var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss");
                var baseName = Path.GetFileName(r.FilePath) + "." + stamp + ".qbin";
                var qPath = Path.Combine(qdir, baseName);
                var bytes = File.ReadAllBytes(r.FilePath);
                for (int i = 0; i < bytes.Length; i++) bytes[i] ^= 0xAA;
                File.WriteAllBytes(qPath, bytes);
                File.WriteAllText(qPath + ".meta",
                    $"original={r.FilePath}\nsha256={r.Sha256}\nquarantined_utc={stamp}\nxor_key=0xAA\n",
                    Encoding.UTF8);
                try { File.Delete(r.FilePath); } catch { }
                MessageBox.Show(this, "Файл помещён в карантин:\n" + qPath, "Карантин");
            }
            catch (Exception ex) { MessageBox.Show(this, "Ошибка карантина: " + ex.Message, "Карантин"); }
        }

        // D5: tabbed details dialog.
        private void ShowDetailsDialog(AnalysisResult r)
        {
            using var dlg = new Form
            {
                Text = Path.GetFileName(r.FilePath) + " — details",
                StartPosition = FormStartPosition.CenterParent,
                Width = 1100, Height = 760,
                MinimizeBox = false, MaximizeBox = true,
            };
            var tabs = new TabControl { Dock = DockStyle.Fill };

            TabPage MakePageWithText(string title, string text)
            {
                var tb = new TextBox
                {
                    Multiline = true, ReadOnly = true, Dock = DockStyle.Fill,
                    ScrollBars = ScrollBars.Both, WordWrap = false,
                    Font = new System.Drawing.Font("Consolas", 10),
                    Text = text,
                };
                var page = new TabPage(title);
                page.Controls.Add(tb);
                return page;
            }

            tabs.TabPages.Add(MakePageWithText("Summary",
                $"File:   {r.FilePath}\nSHA-256: {r.Sha256}\nSize:    {(File.Exists(r.FilePath) ? new FileInfo(r.FilePath).Length : 0)} bytes\n" +
                $"Type:    {r.FileType}\nRisk:    {r.RiskScore}/100 ({r.RiskLevel})\nFamily:  {r.FamilyName} ({r.FamilyConfidence:0.#}%)\n\n" +
                $"Reasons: {r.ReasonsShort}"));
            tabs.TabPages.Add(MakePageWithText("Strings",
                string.Join('\n', r.StringHits.Take(500))));
            tabs.TabPages.Add(MakePageWithText("URLs / IPs / emails",
                "== URLs ==\n" + string.Join('\n', r.UrlsFound.Take(300)) +
                "\n\n== IPv4 ==\n" + string.Join('\n', r.Ipv4Hits.Take(300)) +
                "\n\n== Emails ==\n" + string.Join('\n', r.EmailHits.Take(300))));
            tabs.TabPages.Add(MakePageWithText("APIs / imports",
                "== SuspiciousApiHits ==\n" + string.Join('\n', r.SuspiciousApiHits.Take(300)) +
                "\n\n== Imports ==\n"       + string.Join('\n', r.ImportedApis.Take(500))));
            tabs.TabPages.Add(MakePageWithText("Sections",
                string.Join('\n', r.SectionNames.Select(n => $"  {n}  entropy={(r.SectionEntropy.TryGetValue(n, out var e) ? e : 0):0.00}"))));
            tabs.TabPages.Add(BuildEntropyChartPage(r));         // D6
            tabs.TabPages.Add(MakePageWithText("Raw report", r.ToFullReport()));

            dlg.Controls.Add(tabs);
            dlg.ShowDialog(this);
        }

        // D6: entropy-per-chunk bar chart in the details dialog (no external chart lib).
        private static TabPage BuildEntropyChartPage(AnalysisResult r)
        {
            var page = new TabPage("Entropy chart");
            var panel = new Panel { Dock = DockStyle.Fill, BackColor = System.Drawing.Color.Black };
            panel.Paint += (s, e) =>
            {
                var g = e.Graphics;
                int w = panel.ClientSize.Width, h = panel.ClientSize.Height;
                if (w < 10 || h < 10) return;
                g.Clear(System.Drawing.Color.Black);
                var axis = new System.Drawing.Pen(System.Drawing.Color.DimGray);
                g.DrawLine(axis, 40, h - 30, w - 10, h - 30);
                g.DrawLine(axis, 40, 10,     40,    h - 30);
                using var font = new System.Drawing.Font("Segoe UI", 8);
                g.DrawString("entropy 0..8", font, System.Drawing.Brushes.DimGray, 45, 10);

                var data = r.ChunkEntropy;
                if (data == null || data.Count == 0)
                {
                    g.DrawString("No chunk entropy available.", font, System.Drawing.Brushes.Gray, 50, h / 2);
                    return;
                }
                int availW = Math.Max(1, w - 50);
                int availH = Math.Max(1, h - 40);
                double barW = Math.Max(1.0, (double)availW / data.Count);
                for (int i = 0; i < data.Count; i++)
                {
                    double v = Math.Max(0, Math.Min(8, data[i]));
                    float x = 40 + (float)(i * barW);
                    float bh = (float)(availH * (v / 8.0));
                    var color = v >= 7.2 ? System.Drawing.Color.OrangeRed
                              : v >= 6.0 ? System.Drawing.Color.Orange
                              : System.Drawing.Color.LimeGreen;
                    using var br = new System.Drawing.SolidBrush(color);
                    g.FillRectangle(br, x, h - 30 - bh, (float)Math.Max(1, barW - 0.5), bh);
                }
            };
            page.Controls.Add(panel);
            return page;
        }

        // D10: session dashboard — aggregate stats window.
        private void ShowDashboard()
        {
            var results = CollectResults();
            if (results.Count == 0) { MessageBox.Show(this, "Нет данных.", "Dashboard"); return; }

            int high = results.Count(x => x.RiskScore >= 70);
            int med  = results.Count(x => x.RiskScore >= 40 && x.RiskScore < 70);
            int low  = results.Count - high - med;
            int signed = results.Count(x => x.IsSigned);
            int packed = results.Count(x => x.PackedLikely);
            int net    = results.Count(x => x.NetLikely);
            var topFamilies = results
                .Where(x => !string.IsNullOrEmpty(x.FamilyName))
                .GroupBy(x => x.FamilyName, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g => $"  {g.Key,-20}  {g.Count()}");
            var topIndicators = results
                .SelectMany(x => x.CustomHeuristicHits)
                .GroupBy(s => s, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Take(15)
                .Select(g => $"  {g.Key,-40}  {g.Count()}");

            var body = new StringBuilder();
            body.AppendLine($"Files analyzed: {results.Count}");
            body.AppendLine($"  HIGH risk:  {high}");
            body.AppendLine($"  MED risk:   {med}");
            body.AppendLine($"  LOW risk:   {low}");
            body.AppendLine($"  Signed:     {signed}");
            body.AppendLine($"  Packed:     {packed}");
            body.AppendLine($"  Networky:   {net}");
            body.AppendLine();
            body.AppendLine("Top families:");
            foreach (var l in topFamilies) body.AppendLine(l);
            body.AppendLine();
            body.AppendLine("Top custom-heuristic hits:");
            foreach (var l in topIndicators) body.AppendLine(l);

            using var dlg = new Form
            {
                Text = "Dashboard",
                Width = 700, Height = 600,
                StartPosition = FormStartPosition.CenterParent,
            };
            var tb = new TextBox
            {
                Multiline = true, ReadOnly = true, Dock = DockStyle.Fill,
                ScrollBars = ScrollBars.Both, WordWrap = false,
                Font = new System.Drawing.Font("Consolas", 10),
                Text = body.ToString(),
            };
            dlg.Controls.Add(tb);
            dlg.ShowDialog(this);
        }

        private void BindDragDrop()
        {
            AllowDrop = true;
            DragEnter += (_, e) =>
            {
                if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
                {
                    e.Effect = DragDropEffects.Copy;
                    // 8.7 — visual highlight via the MVU dispatcher.
                    _ux.Dispatch(new UxAppMsg.DragEnter());
                }
            };
            DragLeave += (_, _) => _ux.Dispatch(new UxAppMsg.DragLeave());
            DragDrop += async (_, e) =>
            {
                _ux.Dispatch(new UxAppMsg.DragLeave());
                if (_isScanning) return;
                if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
                    await ProcessPathsAsync(files);
            };
        }

        private async Task PickFilesAsync()
        {
            if (_isScanning) return;
            using var ofd = new OpenFileDialog
            {
                Title = "Выберите файл(ы) или архивы",
                Multiselect = true,
                InitialDirectory = Directory.Exists(_settings.LastFileDir) ? _settings.LastFileDir : "",
                Filter = "Supported (*.asi;*.dll;*.exe;*.zip;*.jar;*.apk;*.msi;*.msix;*.appx;*.7z;*.rar;*.gz;*.tar;*.hta;*.js;*.vbs;*.ps1;*.bat;*.cmd;*.lua;*.pdf;*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.rtf)|*.asi;*.dll;*.exe;*.zip;*.jar;*.apk;*.msi;*.msix;*.appx;*.7z;*.rar;*.gz;*.tar;*.hta;*.js;*.vbs;*.ps1;*.bat;*.cmd;*.lua;*.pdf;*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.rtf|All files (*.*)|*.*"
            };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                try { _settings.LastFileDir = Path.GetDirectoryName(ofd.FileNames[0]) ?? ""; _settings.Save(); } catch { }
                await ProcessPathsAsync(ofd.FileNames);
            }
        }

        private async Task PickFolderAsync()
        {
            if (_isScanning) return;
            using var fbd = new FolderBrowserDialog
            {
                Description = "Выберите папку для анализа",
                InitialDirectory = Directory.Exists(_settings.LastFolderDir) ? _settings.LastFolderDir : "",
            };
            if (fbd.ShowDialog() == DialogResult.OK)
            {
                try { _settings.LastFolderDir = fbd.SelectedPath; _settings.Save(); } catch { }
                await ProcessPathsAsync(new[] { fbd.SelectedPath });
            }
        }

        private void ApplySettingsToUi()
        {
            _recursive.Checked = _settings.RecursiveScan;
            Analyzer.EnableServerClassification = _settings.EnableServerClassifier;
            Analyzer.EnableExternalRules = _settings.EnableExternalRules;
            Analyzer.MaxReadPrefixBytes = _settings.MaxReadPrefixMb * 1024 * 1024;
            Analyzer.MaxAsciiStrings = _settings.MaxAsciiStrings;
            Analyzer.MaxUnicodeStrings = _settings.MaxUnicodeStrings;
            Analyzer.MaxExtractedUrls = _settings.MaxUrls;
            _status.Text = "Готово";
        }

        private void UpdateSummary()
        {
            if (_grid.Rows.Count == 0)
            {
                _summary.Text = "Нет загруженных объектов";
                return;
            }

            int high = 0, medium = 0, low = 0, signed = 0, packed = 0, heurPositive = 0;
            foreach (DataGridViewRow row in _grid.Rows)
            {
                int risk = 0;
                if (row.Tag is AnalysisResult r)
                {
                    risk = r.RiskScore;
                    if (r.IsSigned) signed++;
                    if (r.PackedLikely) packed++;
                    if (r.CustomHeuristicHits.Count > 0) heurPositive++;
                }
                else if (row.Cells[3].Value?.ToString() is string riskCell && int.TryParse(riskCell.Split('/')[0], out var parsedRisk))
                {
                    risk = parsedRisk;
                }

                if (risk >= 70) high++;
                else if (risk >= 40) medium++;
                else low++;
            }
            _summary.Text = $"Всего: {_grid.Rows.Count} | High: {high} | Medium: {medium} | Low: {low} | Signed: {signed} | Packed: {packed} | Custom+: {heurPositive}";
        }

        private async Task ProcessPathsAsync(IEnumerable<string> paths)
        {
            if (_isScanning) return;

            var work = new List<(string path, bool isArchive, string displayPath)>();
            foreach (var p in paths.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                try
                {
                    if (File.Exists(p))
                    {
                        var ext = Path.GetExtension(p).ToLowerInvariant();
                        if (IsSupportedBinaryExt(ext)) work.Add((p, false, p));
                        else if (IsArchiveExt(ext)) work.Add((p, true, p));
                    }
                    else if (Directory.Exists(p))
                    {
                        var opt = _settings.RecursiveScan ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                        foreach (var f in Directory.EnumerateFiles(p, "*", opt))
                        {
                            var ext = Path.GetExtension(f).ToLowerInvariant();
                            if (IsSupportedBinaryExt(ext)) work.Add((f, false, f));
                            else if (IsArchiveExt(ext)) work.Add((f, true, f));
                        }
                    }
                }
                catch (Exception ex)
                {
                    // M8: register the failed path so repeated drops don't spam the grid.
                    var key = $"ERROR::{p}";
                    if (TryRegisterFile(key))
                        AddRow(AnalysisResult.Error(p, $"Path processing error: {ex.Message}"));
                }
            }

            if (work.Count == 0)
            {
                _status.Text = "Нет подходящих файлов";
                return;
            }

            _scanCts = new CancellationTokenSource();
            _isScanning = true;
            ToggleControlsForScan(true);
            _progress.Minimum = 0;
            _progress.Maximum = work.Count;
            _progress.Value = 0;

            int done = 0;
            int addedRows = 0;
            _scanStartedAt = DateTime.UtcNow;
            _scanBytesTotal = 0;
            _scanBytesDone = 0;
            foreach (var w in work)
            {
                try { if (!w.isArchive && File.Exists(w.path)) _scanBytesTotal += new FileInfo(w.path).Length; } catch { }
            }
            var startedAt = _scanStartedAt;
            try
            {
                // F1: analyse plain-file work items in parallel. Archives still run sequentially because
                // ZipArchive is not thread-safe and nested archive scanning spawns more work items internally.
                var plainItems = work.Where(w => !w.isArchive).ToList();
                var archiveItems = work.Where(w => w.isArchive).ToList();

                int dop = Math.Max(1, _settings.MaxParallelism > 0 ? _settings.MaxParallelism : Environment.ProcessorCount);
                var uiSync = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

                await Parallel.ForEachAsync(plainItems,
                    new ParallelOptions { MaxDegreeOfParallelism = dop, CancellationToken = _scanCts.Token },
                    async (item, ct) =>
                    {
                        uiSync.Post(_ => _status.Text = $"Сканирование: {Path.GetFileName(item.path)}", null);
                        long size = 0; try { size = new FileInfo(item.path).Length; } catch { }
                        int added = await AnalyzeAndAddAsync(item.path, item.displayPath, ct);
                        Interlocked.Add(ref addedRows, added);
                        int localDone = Interlocked.Increment(ref done);
                        Interlocked.Add(ref _scanBytesDone, size);
                        int snapshotDone = localDone;
                        int totalCount = work.Count;
                        uiSync.Post(_ =>
                        {
                            _progress.Value = Math.Min(_progress.Maximum, snapshotDone);
                            UpdateProgressStatus(snapshotDone, totalCount, item.path);  // D11
                        }, null);
                    });

                foreach (var item in archiveItems)
                {
                    _scanCts.Token.ThrowIfCancellationRequested();
                    _status.Text = $"Сканирование: {Path.GetFileName(item.path)}";
                    await ScanArchiveAsync(item.path, 0, _scanCts.Token);
                    done++;
                    _progress.Value = Math.Min(_progress.Maximum, done);
                    UpdateProgressStatus(done, work.Count, item.path);
                }

                var elapsed = (DateTime.UtcNow - startedAt).TotalSeconds;
                _status.Text = $"Готово. Обработано: {done}, добавлено: {addedRows}, {elapsed:0.0} c";
            }
            catch (OperationCanceledException)
            {
                _status.Text = $"Остановлено пользователем. Обработано: {done}";
            }
            finally
            {
                _isScanning = false;
                ToggleControlsForScan(false);
                _scanCts?.Dispose();
                _scanCts = null;

                // E7: autosave report after scan (opt-in).
                if (_settings.AutoSaveReports)
                {
                    try
                    {
                        var results = CollectResults();
                        if (results.Count > 0)
                        {
                            var dir = ReportWriter.AutoSave(results);
                            _status.Text = $"Готово. Отчёт: {dir}";
                        }
                    }
                    catch { /* autosave is best-effort */ }
                }
            }
        }

        private async Task ScanArchiveAsync(string archivePath, int depth, CancellationToken ct)
        {
            if (depth > _settings.MaxArchiveDepth) return;
            try
            {
                using var z = ZipFile.OpenRead(archivePath);
                foreach (var entry in z.Entries)
                {
                    ct.ThrowIfCancellationRequested();
                    if (string.IsNullOrWhiteSpace(entry.Name)) continue;
                    var ext = Path.GetExtension(entry.Name).ToLowerInvariant();
                    if (!IsSupportedBinaryExt(ext) && !IsArchiveExt(ext)) continue;
                    if (entry.Length > _settings.MaxInputFileSizeMb * 1024L * 1024L) continue;

                    var display = $"{archivePath}::{entry.FullName}";
                    if (!TryRegisterFile(display)) continue;

                    // G2: use a random filename in a dedicated per-session tempdir instead of GetTempFileName()
                    // (which pre-creates a predictable file). Directory is recreated on demand.
                    var tmpDir = Path.Combine(Path.GetTempPath(), "antistealer-" + AppTempSession);
                    Directory.CreateDirectory(tmpDir);
                    var tmp = Path.Combine(tmpDir, Path.GetRandomFileName() + ext);
                    try
                    {
                        await using (var es = entry.Open())
                        await using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                            await es.CopyToAsync(fs, ct);

                        if (IsSupportedBinaryExt(ext))
                            await AnalyzeAndAddAsync(tmp, display, ct, alreadyRegistered: true, sourceExt: ext);
                        else if (IsArchiveExt(ext)) await ScanArchiveAsync(tmp, depth + 1, ct);
                    }
                    // M9: surface per-entry extraction errors instead of silently swallowing them.
                    catch (OperationCanceledException) { throw; }
                    catch (Exception entryEx)
                    {
                        AddRow(AnalysisResult.Error(display, $"archive entry error: {entryEx.Message}"));
                    }
                    finally
                    {
                        try { File.Delete(tmp); } catch { /* best-effort cleanup */ }
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                AddRow(AnalysisResult.Error(archivePath, $"Archive scan error: {ex.Message}"));
            }
        }

        // G2: per-session suffix for temp directories so we don't clash with other scanners / other users.
        private static readonly string AppTempSession = Guid.NewGuid().ToString("N");

        private async Task<int> AnalyzeAndAddAsync(string path, string displayPath, CancellationToken ct, bool alreadyRegistered = false, string? sourceExt = null)
        {
            var ext = (sourceExt ?? Path.GetExtension(path)).ToLowerInvariant();
            if (!IsSupportedBinaryExt(ext)) return 0;

            // M4: register the file first; only stat if we actually kept the entry.
            if (!alreadyRegistered)
            {
                var key = Path.GetFullPath(path);
                if (!TryRegisterFile(key)) return 0;
            }

            long fileLen;
            try
            {
                fileLen = new FileInfo(path).Length;
            }
            catch (Exception ex)
            {
                AddRow(AnalysisResult.Error(displayPath, $"stat error: {ex.Message}"));
                return 1;
            }

            if (fileLen > _settings.MaxInputFileSizeMb * 1024L * 1024L)
            {
                AddRow(AnalysisResult.Error(displayPath, $"Skipped: file larger than {_settings.MaxInputFileSizeMb} MB"));
                return 1;
            }

            // AA4: all analysis + cloud enrichment + rescore is driven through
            // the engine facade, so the .exe contains no analysis logic.
            AnalysisResult res = await _engine.AnalyzeFileAsync(
                path, displayPath, enrichWithCloud: true, ct: ct);

            if (_settings.HideLowRisk && res.RiskScore < 40) return 0;
            AddRow(res);
            return 1;
        }

        private void AddRow(AnalysisResult res)
        {
            // F1: AnalyzeAndAddAsync is invoked from worker threads during parallel scans; marshal to UI thread.
            if (_grid.InvokeRequired)
            {
                _grid.BeginInvoke(new Action<AnalysisResult>(AddRow), res);
                return;
            }

            var rowIndex = _grid.Rows.Add(
                Path.GetFileName(res.FilePath),
                res.FileType,
                res.Is64 ? "x64" : "x86/unknown",
                $"{res.RiskScore}/100",
                res.RiskLevel,
                string.IsNullOrWhiteSpace(res.FamilyName) ? "unknown" : res.FamilyName,
                res.FamilyConfidence > 0 ? $"{res.FamilyConfidence:0}%" : "-",
                res.NetLikely ? "YES" : "no",
                res.PackedLikely ? "YES" : "no",
                res.IsSigned ? "YES" : "no",
                res.CustomHeuristicHits.Count,
                res.UrlsFound.Count,
                res.SuspiciousApiHits.Count,
                res.TotalIocHits,
                res.Sha256.Length >= 12 ? res.Sha256[..12] : res.Sha256,
                res.ReasonsShort
            );

            var row = _grid.Rows[rowIndex];
            row.Tag = res;
            ColorizeRow(row, res.RiskScore);
            if (_settings.AutoSelectLastRow)
                _grid.CurrentCell = _grid.Rows[rowIndex].Cells[0];

            ApplyRowFilter();  // D4: respect active filters for newly added rows.
            UpdateSummary();
        }

        private static readonly HashSet<string> SupportedBinaryExts = new(StringComparer.OrdinalIgnoreCase)
        {
            // Original PE-ish.
            ".asi", ".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr",
            // Installers / packages scanned as raw binary (format-family classification done inside Analyze).
            ".msi", ".msix", ".appx",
            // Archives we can't yet extract (no SharpCompress dep) — still classified + string-scanned.
            ".7z", ".rar", ".gz", ".tar",
            // Native binaries for other platforms — static classification only.
            ".so", ".dylib",
            // Script formats (read as text + script-specific indicators).
            // ".lua" gets the dedicated SA-MP / GTA threat-group scan in
            // FormatDetectors.DetectLuaThreats.
            ".hta", ".js", ".vbs", ".ps1", ".psm1", ".bat", ".cmd", ".lua",
            // Document formats (.doc/.xls/.ppt are OLE, the rest are OOXML zips).
            ".pdf", ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".rtf",
        };
        private static bool IsSupportedBinaryExt(string ext) => SupportedBinaryExts.Contains(ext);
        private static bool IsArchiveExt(string ext) => ext == ".zip" || ext == ".jar" || ext == ".apk";

        private static void ColorizeRow(DataGridViewRow row, int risk)
        {
            if (risk >= 70) row.DefaultCellStyle.BackColor = System.Drawing.Color.FromArgb(255, 230, 230);
            else if (risk >= 40) row.DefaultCellStyle.BackColor = System.Drawing.Color.FromArgb(255, 245, 224);
            else row.DefaultCellStyle.BackColor = System.Drawing.Color.FromArgb(231, 250, 231);
        }

        private void ToggleControlsForScan(bool scanning)
        {
            _btnAddFiles.Enabled = !scanning;
            _btnAddFolder.Enabled = !scanning;
            _btnClear.Enabled = !scanning;
            _recursive.Enabled = !scanning;
            _btnStop.Enabled = scanning;
        }

        private void RequestStop() => _scanCts?.Cancel();

        private void ShowSettingsDialog()
        {
            using var f = new SettingsForm(_settings);
            if (f.ShowDialog(this) != DialogResult.OK) return;

            _settings = f.Value;
            // AA4: settings dialog can change cloud API keys / parser limits;
            // rebuild the engine so the next scan picks up the new settings.
            _engine   = AntiStealerEngineFactory.Create(new EngineOptions
            {
                AdvancedSettings      = _settings,
                EnableCloudEnrichment = true,
            });
            _settings.Save();
            ApplySettingsToUi();
            ApplyTheme();  // D1: theme may have flipped.
        }

        private void ExportSelectedReport()
        {
            if (_grid.CurrentRow?.Tag is not AnalysisResult r)
            {
                MessageBox.Show(this, "Сначала выберите строку в таблице.", "Экспорт", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using var sfd = new SaveFileDialog { Filter = "Text files (*.txt)|*.txt", FileName = Path.GetFileName(r.FilePath) + ".report.txt" };
            if (sfd.ShowDialog(this) == DialogResult.OK)
                File.WriteAllText(sfd.FileName, r.ToFullReport(), Encoding.UTF8);
        }

        private void ExportCsv()
        {
            if (_grid.Rows.Count == 0)
            {
                MessageBox.Show(this, "Нет данных для экспорта.", "Экспорт", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using var sfd = new SaveFileDialog { Filter = "CSV files (*.csv)|*.csv", FileName = "analysis-summary.csv" };
            if (sfd.ShowDialog(this) != DialogResult.OK) return;

            // M13: escape embedded newlines, carriage returns, quotes and commas per RFC 4180.
            static string Esc(string s)
            {
                s ??= string.Empty;
                bool needsQuotes = s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0;
                var escaped = s.Replace("\"", "\"\"");
                return needsQuotes ? "\"" + escaped + "\"" : escaped;
            }

            var sb = new StringBuilder();
            sb.AppendLine("File,Type,RiskScore,RiskLevel,Family,Confidence,Net,Packed,Signed,Heuristics,URLs,API,IOCs,SHA256,Reasons");
            foreach (DataGridViewRow row in _grid.Rows)
            {
                if (row.Tag is not AnalysisResult r) continue;
                sb.AppendLine(string.Join(",", new[]
                {
                    Esc(r.FilePath), Esc(r.FileType), r.RiskScore.ToString(), Esc(r.RiskLevel), Esc(r.FamilyName), r.FamilyConfidence.ToString("0.##"),
                    r.NetLikely.ToString(), r.PackedLikely.ToString(), r.IsSigned.ToString(), r.CustomHeuristicHits.Count.ToString(),
                    r.UrlsFound.Count.ToString(), r.SuspiciousApiHits.Count.ToString(), r.TotalIocHits.ToString(), Esc(r.Sha256), Esc(r.ReasonsShort)
                }));
            }
            File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);
        }

        // E1–E5: per-row export into the user-chosen format. `.json` / `.html` / `.pdf` / `.stix.json`
        // / `.sarif` are all single-file artefacts containing every loaded row. For per-file reports,
        // the E6 batch-report option writes a directory with per-file HTML + index.html.
        private void ExportAll(string ext)
        {
            var results = CollectResults();
            if (results.Count == 0)
            {
                MessageBox.Show(this, "Нет данных для экспорта.", "Экспорт", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string filter = ext switch
            {
                ".json"      => "JSON (*.json)|*.json",
                ".html"      => "HTML (*.html)|*.html",
                ".pdf"       => "PDF (*.pdf)|*.pdf",
                ".stix.json" => "STIX 2.1 bundle (*.stix.json)|*.stix.json",
                ".sarif"     => "SARIF (*.sarif)|*.sarif",
                _            => "All files (*.*)|*.*",
            };
            using var sfd = new SaveFileDialog { Filter = filter, FileName = "antistealer-report" + ext };
            if (sfd.ShowDialog(this) != DialogResult.OK) return;

            try
            {
                switch (ext)
                {
                    case ".json":      File.WriteAllText(sfd.FileName, ReportWriter.ToJson(results), Encoding.UTF8); break;
                    case ".html":      File.WriteAllText(sfd.FileName, ReportWriter.ToHtml(results), Encoding.UTF8); break;
                    case ".pdf":       File.WriteAllBytes(sfd.FileName, ReportWriter.ToPdfBytes(results)); break;
                    case ".stix.json": File.WriteAllText(sfd.FileName, ReportWriter.ToStix(results), Encoding.UTF8); break;
                    case ".sarif":     File.WriteAllText(sfd.FileName, ReportWriter.ToSarif(results), Encoding.UTF8); break;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Ошибка экспорта: " + ex.Message, "Экспорт", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // E6: pick a directory and drop per-file HTML reports + an index.html with sortable rows.
        private void ExportBatch()
        {
            var results = CollectResults();
            if (results.Count == 0)
            {
                MessageBox.Show(this, "Нет данных для экспорта.", "Экспорт", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using var fbd = new FolderBrowserDialog { Description = "Папка для batch-отчёта" };
            if (fbd.ShowDialog(this) != DialogResult.OK) return;

            try
            {
                ReportWriter.WriteBatchHtml(results, fbd.SelectedPath);
                MessageBox.Show(this, $"Batch-отчёт создан в {fbd.SelectedPath}", "Экспорт", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Ошибка экспорта: " + ex.Message, "Экспорт", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private List<AnalysisResult> CollectResults()
        {
            var results = new List<AnalysisResult>(_grid.Rows.Count);
            foreach (DataGridViewRow row in _grid.Rows)
                if (row.Tag is AnalysisResult r) results.Add(r);
            return results;
        }
    }
    public sealed class SettingsForm : Form
    {
        private readonly CheckBox _recursive = new() { Left = 15, Top = 15, Width = 420, Text = "Сканировать папки рекурсивно" };
        private readonly CheckBox _hideLowRisk = new() { Left = 15, Top = 45, Width = 420, Text = "Скрывать low-risk в таблице" };
        private readonly CheckBox _autoSelect = new() { Left = 15, Top = 75, Width = 420, Text = "Автовыбор последней добавленной строки" };
        private readonly CheckBox _serverClassifier = new() { Left = 15, Top = 105, Width = 420, Text = "Включить server classifier (если задан URL)" };
        private readonly CheckBox _externalRules = new() { Left = 15, Top = 135, Width = 420, Text = "Включить community_rules.txt" };

        private readonly NumericUpDown _maxDepth = new() { Left = 290, Top = 168, Width = 90, Minimum = 1, Maximum = 12 };
        private readonly NumericUpDown _maxFileMb = new() { Left = 290, Top = 198, Width = 90, Minimum = 1, Maximum = 4096 };
        private readonly NumericUpDown _maxReadMb = new() { Left = 290, Top = 228, Width = 90, Minimum = 4, Maximum = 512 };
        private readonly NumericUpDown _maxUrls = new() { Left = 290, Top = 258, Width = 90, Minimum = 50, Maximum = 5000 };
        private readonly NumericUpDown _maxAscii = new() { Left = 290, Top = 288, Width = 90, Minimum = 2000, Maximum = 200000 };
        private readonly NumericUpDown _maxUnicode = new() { Left = 290, Top = 318, Width = 90, Minimum = 1000, Maximum = 100000 };

        // E7 / D12: extra toggles. (Dark-mode checkbox was removed.)
        private readonly CheckBox _autoSaveReports = new() { Left = 15, Top = 355, Width = 320, Text = "Автосохранять отчёт после скана" };

        public AnalyzerUiSettings Value { get; private set; }

        public SettingsForm(AnalyzerUiSettings current)
        {
            Text = "Настройки";
            Width = 500;
            Height = 520;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;

            Value = current;
            _recursive.Checked = current.RecursiveScan;
            _hideLowRisk.Checked = current.HideLowRisk;
            _autoSelect.Checked = current.AutoSelectLastRow;
            _serverClassifier.Checked = current.EnableServerClassifier;
            _externalRules.Checked = current.EnableExternalRules;
            _maxDepth.Value = current.MaxArchiveDepth;
            _maxFileMb.Value = current.MaxInputFileSizeMb;
            _maxReadMb.Value = current.MaxReadPrefixMb;
            _maxUrls.Value = current.MaxUrls;
            _maxAscii.Value = current.MaxAsciiStrings;
            _maxUnicode.Value = current.MaxUnicodeStrings;
            _autoSaveReports.Checked = current.AutoSaveReports;

            var lblDepth = new Label { Left = 15, Top = 170, Width = 260, Text = "Макс. глубина архивов:" };
            var lblMaxFile = new Label { Left = 15, Top = 200, Width = 260, Text = "Макс. размер файла (MB):" };
            var lblReadMb = new Label { Left = 15, Top = 230, Width = 260, Text = "Читаемый префикс файла (MB):" };
            var lblMaxUrls = new Label { Left = 15, Top = 260, Width = 260, Text = "Макс. найденных URL:" };
            var lblAscii = new Label { Left = 15, Top = 290, Width = 260, Text = "Макс. ASCII-строк:" };
            var lblUnicode = new Label { Left = 15, Top = 320, Width = 260, Text = "Макс. Unicode-строк:" };

            // D12: tooltips on every setting so users can see what each knob does.
            var tips = new ToolTip { AutoPopDelay = 6000, InitialDelay = 400 };
            tips.SetToolTip(_recursive,         "Сканировать все подкаталоги при добавлении папки.");
            tips.SetToolTip(_hideLowRisk,       "Не показывать в таблице файлы с RiskScore < 40.");
            tips.SetToolTip(_autoSelect,        "Автоматически фокусировать последнюю добавленную строку.");
            tips.SetToolTip(_serverClassifier,  "Отправлять хэш + фичи на локальный сервер-классификатор (если настроен).");
            tips.SetToolTip(_externalRules,     "Подгружать правила из community_rules.txt рядом с .exe.");
            tips.SetToolTip(_maxDepth,          "Максимальная глубина вложенности архивов при рекурсивном скане.");
            tips.SetToolTip(_maxFileMb,         "Файлы больше этого размера пропускаются.");
            tips.SetToolTip(_maxReadMb,         "Сколько первых мегабайт файла читается в память для анализа.");
            tips.SetToolTip(_maxUrls,           "Ограничение на кол-во URL, сохраняемых в отчёте.");
            tips.SetToolTip(_maxAscii,          "Ограничение на кол-во ASCII-строк, извлекаемых из файла.");
            tips.SetToolTip(_maxUnicode,        "Ограничение на кол-во Unicode-строк, извлекаемых из файла.");
            tips.SetToolTip(_autoSaveReports,   "Сохранять JSON+HTML отчёт в %APPDATA%\\AntiStealer\\Reports\\ после каждого скана.");

            var btnOk = new Button { Left = 300, Width = 80, Top = 432, DialogResult = DialogResult.OK, Text = "OK" };
            var btnCancel = new Button { Left = 390, Width = 80, Top = 432, DialogResult = DialogResult.Cancel, Text = "Отмена" };
            var btnReset = new Button { Left = 15, Width = 130, Top = 432, Text = "Сбросить настройки" };
            tips.SetToolTip(btnReset, "Восстановить дефолты (только UI; для сохранения нажмите ОК).");
            btnReset.Click += (_, _) =>
            {
                var def = new AnalyzerUiSettings();
                _recursive.Checked = def.RecursiveScan;
                _hideLowRisk.Checked = def.HideLowRisk;
                _autoSelect.Checked = def.AutoSelectLastRow;
                _serverClassifier.Checked = def.EnableServerClassifier;
                _externalRules.Checked = def.EnableExternalRules;
                _maxDepth.Value = def.MaxArchiveDepth;
                _maxFileMb.Value = def.MaxInputFileSizeMb;
                _maxReadMb.Value = def.MaxReadPrefixMb;
                _maxUrls.Value = def.MaxUrls;
                _maxAscii.Value = def.MaxAsciiStrings;
                _maxUnicode.Value = def.MaxUnicodeStrings;
                _autoSaveReports.Checked = def.AutoSaveReports;
            };

            btnOk.Click += (_, _) =>
            {
                // Preserve fields this dialog doesn't edit (cloud keys, window state, etc.).
                Value.RecursiveScan = _recursive.Checked;
                Value.HideLowRisk = _hideLowRisk.Checked;
                Value.AutoSelectLastRow = _autoSelect.Checked;
                Value.EnableServerClassifier = _serverClassifier.Checked;
                Value.EnableExternalRules = _externalRules.Checked;
                Value.MaxArchiveDepth = (int)_maxDepth.Value;
                Value.MaxInputFileSizeMb = (int)_maxFileMb.Value;
                Value.MaxReadPrefixMb = (int)_maxReadMb.Value;
                Value.MaxUrls = (int)_maxUrls.Value;
                Value.MaxAsciiStrings = (int)_maxAscii.Value;
                Value.MaxUnicodeStrings = (int)_maxUnicode.Value;
                Value.AutoSaveReports = _autoSaveReports.Checked;
            };

            Controls.AddRange(new Control[]
            {
                _recursive, _hideLowRisk, _autoSelect, _serverClassifier, _externalRules,
                lblDepth, _maxDepth, lblMaxFile, _maxFileMb, lblReadMb, _maxReadMb,
                lblMaxUrls, _maxUrls, lblAscii, _maxAscii, lblUnicode, _maxUnicode,
                _autoSaveReports,
                btnReset, btnOk, btnCancel,
            });
            AcceptButton = btnOk;
            CancelButton = btnCancel;
        }
    }

}
