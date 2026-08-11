using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using SmtpHeaderAnalyzer.Models;
using SmtpHeaderAnalyzer.Services;

namespace SmtpHeaderAnalyzer;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly HeaderAnalyzer _analyzer = new();
    private MailAnalysis? _analysis;
    private string _sourceLabel = "Nog niets geladen";
    private string _statusText = "Gereed — analyse vindt volledig lokaal plaats.";

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
    }

    public MailAnalysis? Analysis
    {
        get => _analysis;
        private set
        {
            _analysis = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasAnalysis));
            OnPropertyChanged(nameof(HasNoAnalysis));
        }
    }

    public bool HasAnalysis => Analysis is not null;
    public bool HasNoAnalysis => !HasAnalysis;

    public string SourceLabel
    {
        get => _sourceLabel;
        private set { _sourceLabel = value; OnPropertyChanged(); }
    }

    public string StatusText
    {
        get => _statusText;
        private set { _statusText = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Window_SourceInitialized(object? sender, EventArgs e) => ThemeService.ApplyWindow(this);

    private void OpenFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open mailbestand",
            Filter = "Mailbestanden (*.eml;*.msg)|*.eml;*.msg|EML-bestanden (*.eml)|*.eml|Outlook MSG-bestanden (*.msg)|*.msg",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) == true) LoadFile(dialog.FileName);
    }

    private void Analyze_Click(object sender, RoutedEventArgs e) => Analyze(HeaderInput.Text, "Geplakte headers");

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        HeaderInput.Clear();
        Analysis = null;
        SourceLabel = "Nog niets geladen";
        StatusText = "Invoer en analyse gewist; er is niets opgeslagen.";
        HeaderInput.Focus();
    }

    private void Theme_Click(object sender, RoutedEventArgs e)
    {
        ThemeService.Apply(!ThemeService.IsDarkMode);
        ThemeButton.Content = ThemeService.IsDarkMode ? "Licht thema" : "Donker thema";
        StatusText = ThemeService.IsDarkMode ? "Donker thema actief." : "Licht thema actief.";
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new AboutWindow { Owner = this };
        dialog.ShowDialog();
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (Analysis is null) return;
        var dialog = new SaveFileDialog
        {
            Title = "Exporteer analyse",
            Filter = "JSON-rapport (*.json)|*.json|Tekstrapport (*.txt)|*.txt",
            FileName = $"smtp-header-analyse-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != true) return;

        var output = Path.GetExtension(dialog.FileName).Equals(".txt", StringComparison.OrdinalIgnoreCase)
            ? ReportService.ToText(Analysis)
            : ReportService.ToJson(Analysis);
        File.WriteAllText(dialog.FileName, output, new System.Text.UTF8Encoding(false));
        StatusText = $"Rapport opgeslagen: {dialog.FileName}";
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (Analysis is null) return;
        SaveCsv(
            "Exporteer volledige analyse naar CSV",
            $"smtp-header-analyse-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
            ReportService.ToCsv(Analysis));
    }

    private void ExportTimelineCsv_Click(object sender, RoutedEventArgs e)
    {
        if (Analysis is null) return;
        SaveCsv(
            "Exporteer UTC-timeline voor Kali Timeline Tool",
            $"smtp-route-timeline-utc-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
            ReportService.ToTimelineCsv(Analysis));
    }

    private void SaveCsv(string title, string fileName, string contents)
    {
        var dialog = new SaveFileDialog
        {
            Title = title,
            Filter = "CSV-bestand (*.csv)|*.csv",
            FileName = fileName,
            AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != true) return;

        File.WriteAllText(dialog.FileName, contents, new System.Text.UTF8Encoding(false));
        StatusText = $"CSV opgeslagen: {dialog.FileName}";
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) && e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length == 1 && IsSupported(files[0])
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: 1 } files && IsSupported(files[0])) LoadFile(files[0]);
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.O)
        {
            OpenFile_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.Enter)
        {
            Analyze_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.S && HasAnalysis)
        {
            Export_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift) && e.Key == Key.C && HasAnalysis)
        {
            ExportCsv_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Alt) && e.Key == Key.C && HasAnalysis)
        {
            ExportTimelineCsv_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
    }

    private void LoadFile(string path)
    {
        try
        {
            var headers = InputFileService.ReadHeaders(path);
            HeaderInput.Text = headers;
            Analyze(headers, Path.GetFileName(path));
        }
        catch (Exception exception)
        {
            ShowError("Bestand kan niet worden gelezen", exception.Message);
        }
    }

    private void Analyze(string text, string source)
    {
        try
        {
            Analysis = _analyzer.Analyze(text, source);
            SourceLabel = source;
            StatusText = $"Analyse gereed — {Analysis.Headers.Count} headers, {Analysis.Route.Count} hops, {Analysis.Findings.Count} bevindingen.";
        }
        catch (Exception exception)
        {
            ShowError("Analyse mislukt", exception.Message);
        }
    }

    private void ShowError(string title, string message)
    {
        StatusText = $"{title}: {message}";
        MessageBox.Show(this, message, title, MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private static bool IsSupported(string path) => Path.GetExtension(path).Equals(".eml", StringComparison.OrdinalIgnoreCase) || Path.GetExtension(path).Equals(".msg", StringComparison.OrdinalIgnoreCase);

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
