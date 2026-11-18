namespace OCS.Platform;

// Per-user application data locations. No secrets are ever placed in the
// install directory; the vault lives under the user's profile.
public static class AppPaths
{
    public static string VaultDirectory
    {
        get
        {
            var root = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (string.IsNullOrEmpty(root))
            {
                root = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
            }
            return Path.Combine(root, "OCS-Encryption-Chat");
        }
    }
}
