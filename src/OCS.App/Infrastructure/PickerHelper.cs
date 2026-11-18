using Avalonia.Controls;
using Avalonia.Platform.Storage;
using OCS.Core.Abstractions;

namespace OCS.App.Infrastructure;

// Thin wrappers over Avalonia's storage picker so view models never touch views.
public static class PickerHelper
{
    public static async Task<string?> OpenTextFileAsync(TopLevel? top, string title, params string[] patterns)
    {
        if (top is null) return null;
        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType(title) { Patterns = patterns },
                new FilePickerFileType("所有文件") { Patterns = new[] { "*" } },
            },
        });
        if (files.Count == 0) return null;
        await using var stream = await files[0].OpenReadAsync();
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }

    public static async Task<string?> SaveTextFileAsync(TopLevel? top, string title, string suggestedName)
    {
        if (top is null) return null;
        var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
        });
        return file?.Path.LocalPath;
    }

    public static async Task WriteAllTextAsync(string path, string content, CancellationToken ct)
    {
        var tmp = path + ".tmp";
        await File.WriteAllTextAsync(tmp, content, ct);
        File.Move(tmp, path, overwrite: true);
    }
}
