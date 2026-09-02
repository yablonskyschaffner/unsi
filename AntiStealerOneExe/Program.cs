// AA5: this project is now a 30-line apphost. The WinForms surface (MainForm
// + SettingsForm + UI helpers) lives in AntiStealer.UI.dll, the analyzer
// engine in AntiStealer.Engine.dll. The .exe loads both side-by-side at
// startup; if either DLL is missing the apphost fails with a
// `FileNotFoundException` referencing the missing library (covered by the
// AA4/AA5 CI smoke tests in .github/workflows/build.yml).
//
// Keeping Program in the exe project is what makes Main the entrypoint of
// AntiStealer.exe — moving Main into a library would require a separate
// shim exe anyway, so we keep the WinExe wrapper here.
using AntiStealer.Engine;

namespace AntiStealerOneExe
{
    internal static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            // Section 7 — any non-empty arg list goes through the Spectre.Console.Cli
            // command tree (`CliApp`, defined in AntiStealer.Engine.dll). The legacy
            // hand-rolled `Cli` dispatcher is kept as a fallback in case the user
            // explicitly invokes `legacy-scan`.
            if (args != null && args.Length > 0)
            {
                return CliApp.Run(args);
            }

            ApplicationConfiguration.Initialize();
            // MainForm lives in AntiStealer.UI.dll; the exe is otherwise free of
            // UI logic and analyzer logic.
            Application.Run(new MainForm());
            return 0;
        }
    }
}
