namespace OCS.App;

// Runtime options parsed from the command line before the UI starts.
internal static class AppOptions
{
    // When set, the vault lives in this directory instead of the per-user
    // default (AppPaths.VaultDirectory). Lets two independent endpoints
    // (e.g. Alice / Bob test vaults) run side by side on one machine.
    public static string? DataDirectoryOverride { get; set; }
}