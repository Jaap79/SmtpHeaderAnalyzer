using System.Windows;
using System.Windows.Media;

namespace SmtpHeaderAnalyzer.Services;

public static class ThemeService
{
    public static bool IsDarkMode { get; private set; } = true;

    public static void Apply(bool darkMode)
    {
        IsDarkMode = darkMode;
        var resources = Application.Current.Resources;
        var palette = darkMode
            ? new[] { "#14171C", "#1B1E24", "#252A32", "#20242B", "#F1F4F6", "#9EA7B3", "#353C47" }
            : new[] { "#F3F5F8", "#FFFFFF", "#E9EDF2", "#F8FAFC", "#17202A", "#5B6572", "#C9D0D8" };

        var names = new[] { "WindowBrush", "SurfaceBrush", "SurfaceAltBrush", "ControlBrush", "TextBrush", "MutedTextBrush", "BorderBrush" };
        for (var index = 0; index < names.Length; index++)
        {
            resources[names[index]] = Brush(palette[index]);
        }

        foreach (Window window in Application.Current.Windows)
        {
            WindowThemeService.Apply(window, darkMode);
        }
    }

    public static void ApplyWindow(Window window) => WindowThemeService.Apply(window, IsDarkMode);

    private static SolidColorBrush Brush(string value)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
        brush.Freeze();
        return brush;
    }
}
