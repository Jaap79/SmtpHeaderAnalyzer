using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using SmtpHeaderAnalyzer.Models;

namespace SmtpHeaderAnalyzer.Converters;

public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value is FindingSeverity severity ? severity switch
        {
            FindingSeverity.Critical => "DangerBrush",
            FindingSeverity.Warning => "WarningBrush",
            FindingSeverity.Good => "GoodBrush",
            _ => "NeutralBrush"
        } : "NeutralBrush";
        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
