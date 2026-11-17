using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Themes.Fluent;

namespace LanDrop.App;

// Flags used by the automated checks; normal use has none.
sealed class AppOptions
{
    public bool Smoke;          // --smoke-test: start, wait for a connection on loopback, then quit
    public string Screenshot;   // --screenshot <file.png>: save a picture of the window first
    public int? Port;           // --test-port <n>
    public bool Loopback;       // --test-loopback
    public string InviteFile;   // --test-invite-file <file>: start waiting right away and write the invite key there
    public string IconFile;     // --write-icon <file.png> <size>: save the app icon and quit (used for packaging)
    public int IconSize = 1024;

    public static AppOptions Parse(string[] a)
    {
        var o = new AppOptions();
        for (int i = 0; i < a.Length; i++)
        {
            try
            {
                switch (a[i])
                {
                    case "--smoke-test": o.Smoke = true; o.Loopback = true; o.Port ??= 50597; break;
                    case "--screenshot": o.Screenshot = Path.GetFullPath(a[++i]); break;
                    case "--test-port": o.Port = int.Parse(a[++i]); break;
                    case "--test-loopback": o.Loopback = true; break;
                    case "--test-invite-file": o.InviteFile = Path.GetFullPath(a[++i]); break;
                    case "--write-icon": o.IconFile = Path.GetFullPath(a[++i]); o.IconSize = int.Parse(a[++i]); break;
                }
            }
            catch { }
        }
        return o;
    }
}

static class Program
{
    public static AppOptions Options = new();

    [STAThread]
    public static int Main(string[] args)
    {
        Options = AppOptions.Parse(args);
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UsePlatformDetect().WithInterFont().LogToTrace();

    public static void Quit(int code)
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d) d.Shutdown(code);
    }
}

sealed class App : Application
{
    public override void Initialize()
    {
        Name = "LAN Drop";
        Styles.Add(new FluentTheme());
        // On a Mac this replaces the default "About Avalonia" menu item.
        var about = new NativeMenuItem("About LAN Drop");
        about.Click += async (_, _) =>
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d && d.MainWindow != null)
                await Dialogs.Message(d.MainWindow, "About LAN Drop",
                    "LAN Drop " + typeof(App).Assembly.GetName().Version?.ToString(3) +
                    "\nSend files directly between computers.\n\nhttps://github.com/AlmaCRose/lan-drop");
        };
        NativeMenu.SetMenu(this, new NativeMenu { about });
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d)
        {
            if (Program.Options.IconFile != null)
            {
                using (var bmp = IconArt.Render(Program.Options.IconSize)) bmp.Save(Program.Options.IconFile);
                d.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                Avalonia.Threading.Dispatcher.UIThread.Post(() => d.Shutdown(0));
            }
            else d.MainWindow = new MainWindow(Program.Options);
        }
        base.OnFrameworkInitializationCompleted();
    }
}
