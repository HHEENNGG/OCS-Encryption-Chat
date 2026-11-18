using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using OCS.App.ViewModels;

namespace OCS.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();
    private bool _closed;

    public MainWindow()
    {
        InitializeComponent();
        if (AppOptions.DataDirectoryOverride is { } dir)
        {
            // Distinguish side-by-side test endpoints (e.g. Alice / Bob).
            Title += $" — {Path.GetFileName(dir.TrimEnd(Path.DirectorySeparatorChar))}";
        }
        DataContext = _vm;
        _vm.TopLevelAccessor = () => this;
        AddHandler(PointerMovedEvent, (_, _) => _vm.ResetActivity(), RoutingStrategies.Tunnel);
        AddHandler(KeyDownEvent, (_, _) => _vm.ResetActivity(), RoutingStrategies.Tunnel);
        Closing += OnClosing;
    }

    private async void OnClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_closed) return;
        e.Cancel = true;
        try
        {
            await _vm.ShutdownAsync();
        }
        catch
        {
            // shutdown must never block window close
        }
        _closed = true;
        Close();
    }
}
