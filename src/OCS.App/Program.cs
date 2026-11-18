using Avalonia;

namespace OCS.App;

internal static class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called.
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Contains("--selftest"))
        {
            return SelfTest.RunAsync().GetAwaiter().GetResult();
        }

        // --data-dir <path> overrides the vault location (for running two
        // independent endpoints on one machine). OCS_DATA_DIR works too.
        var cleanArgs = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--data-dir")
            {
                if (i + 1 >= args.Length)
                {
                    Console.Error.WriteLine("--data-dir requires a directory path.");
                    return 2;
                }
                AppOptions.DataDirectoryOverride = Path.GetFullPath(args[++i]);
            }
            else
            {
                cleanArgs.Add(args[i]);
            }
        }
        if (AppOptions.DataDirectoryOverride is null)
        {
            var env = Environment.GetEnvironmentVariable("OCS_DATA_DIR");
            if (!string.IsNullOrWhiteSpace(env))
            {
                AppOptions.DataDirectoryOverride = Path.GetFullPath(env);
            }
        }

        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(cleanArgs.ToArray());
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
