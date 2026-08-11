using System.Windows;

namespace SmtpHeaderAnalyzer;

public static class SearchVisual
{
    public static readonly DependencyProperty IsCurrentProperty = DependencyProperty.RegisterAttached(
        "IsCurrent",
        typeof(bool),
        typeof(SearchVisual),
        new FrameworkPropertyMetadata(false));

    public static readonly DependencyProperty IsMarkedProperty = DependencyProperty.RegisterAttached(
        "IsMarked",
        typeof(bool),
        typeof(SearchVisual),
        new FrameworkPropertyMetadata(false));

    public static bool GetIsCurrent(DependencyObject element) => (bool)element.GetValue(IsCurrentProperty);
    public static void SetIsCurrent(DependencyObject element, bool value) => element.SetValue(IsCurrentProperty, value);
    public static bool GetIsMarked(DependencyObject element) => (bool)element.GetValue(IsMarkedProperty);
    public static void SetIsMarked(DependencyObject element, bool value) => element.SetValue(IsMarkedProperty, value);
}
