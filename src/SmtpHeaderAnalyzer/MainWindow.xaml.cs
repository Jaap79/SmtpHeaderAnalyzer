using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
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
    private readonly HashSet<object> _markedSearchItems = new(ReferenceEqualityComparer.Instance);
    private List<object> _searchMatches = [];
    private int _searchIndex = -1;
    private string _searchQuery = string.Empty;
    private object? _currentSearchItem;
    private FrameworkElement? _currentSearchContainer;
    private SearchWindow? _searchWindow;

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
        ResetSearchNavigation(clearMarks: true);
        Analysis = null;
        _searchWindow?.RefreshForCurrentView();
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

    private void Search_Click(object sender, RoutedEventArgs e)
    {
        if (!HasAnalysis) return;
        if (_searchWindow is { IsVisible: true })
        {
            _searchWindow.Activate();
            return;
        }

        _searchWindow = new SearchWindow(this);
        _searchWindow.Show();
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

    private void ExportPdf_Click(object sender, RoutedEventArgs e)
    {
        if (Analysis is null) return;
        var dialog = new SaveFileDialog
        {
            Title = "Exporteer opgemaakt PDF-rapport",
            Filter = "PDF-rapport (*.pdf)|*.pdf",
            FileName = $"smtp-header-analyse-{DateTime.Now:yyyyMMdd-HHmmss}.pdf",
            AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != true) return;

        try
        {
            PdfReportService.Write(Analysis, dialog.FileName);
            StatusText = $"PDF-rapport opgeslagen: {dialog.FileName}";
        }
        catch (Exception exception)
        {
            ShowError("PDF kan niet worden gemaakt", exception.Message);
        }
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
        if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.F && HasAnalysis)
        {
            Search_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.O)
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
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.P && HasAnalysis)
        {
            ExportPdf_Click(this, new RoutedEventArgs());
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
            ResetSearchNavigation(clearMarks: true);
            Analysis = _analyzer.Analyze(text, source);
            _searchWindow?.RefreshForCurrentView();
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

    internal SearchNavigationState StartSearch(string query)
    {
        ClearCurrentSearchHighlight();
        _searchQuery = query.Trim();
        var scope = CurrentSearchScope();
        _searchMatches = scope is null || string.IsNullOrEmpty(_searchQuery)
            ? []
            : scope.Items.Where(item => SearchService.Matches(item, _searchQuery)).ToList();
        _searchIndex = _searchMatches.Count > 0 ? 0 : -1;
        return CurrentSearchState(navigate: true);
    }

    internal SearchNavigationState MoveSearch(int direction)
    {
        if (_searchMatches.Count == 0) return CurrentSearchState(navigate: false);
        _searchIndex = (_searchIndex + direction + _searchMatches.Count) % _searchMatches.Count;
        return CurrentSearchState(navigate: true);
    }

    internal SearchNavigationState ToggleCurrentSearchMark()
    {
        if (_currentSearchItem is null) return CurrentSearchState(navigate: false);

        if (!_markedSearchItems.Add(_currentSearchItem)) _markedSearchItems.Remove(_currentSearchItem);
        if (_currentSearchContainer is not null)
        {
            SearchVisual.SetIsMarked(_currentSearchContainer, _markedSearchItems.Contains(_currentSearchItem));
        }

        StatusText = _markedSearchItems.Contains(_currentSearchItem)
            ? "Zoekresultaat visueel gemarkeerd; de analysegegevens zijn niet gewijzigd."
            : "Visuele markering verwijderd; de analysegegevens zijn niet gewijzigd.";
        return CurrentSearchState(navigate: false);
    }

    internal SearchNavigationState ClearSearchMarksInCurrentView()
    {
        var scope = CurrentSearchScope();
        if (scope is not null)
        {
            foreach (var item in scope.Items)
            {
                _markedSearchItems.Remove(item);
                if (FindContainer(scope.Control, item, scrollIntoView: false) is { } container)
                {
                    SearchVisual.SetIsMarked(container, false);
                }
            }
        }

        StatusText = "Visuele zoekmarkeringen in de huidige weergave gewist.";
        return CurrentSearchState(navigate: false);
    }

    internal void SearchWindowClosed(SearchWindow window)
    {
        if (ReferenceEquals(_searchWindow, window)) _searchWindow = null;
    }

    private SearchNavigationState CurrentSearchState(bool navigate)
    {
        var scope = CurrentSearchScope();
        var viewName = scope?.Name ?? "Geen analyse";

        if (navigate && _searchIndex >= 0 && _searchIndex < _searchMatches.Count && scope is not null)
        {
            NavigateToSearchItem(scope, _searchMatches[_searchIndex]);
        }

        var markedCount = scope?.Items.Count(_markedSearchItems.Contains) ?? 0;
        var isMarked = _currentSearchItem is not null && _markedSearchItems.Contains(_currentSearchItem);
        var message = string.IsNullOrEmpty(_searchQuery)
            ? "Vul een zoekterm in. Er wordt gezocht in alle velden van de volledige regel."
            : _searchMatches.Count == 0
                ? $"‘{_searchQuery}’ is niet gevonden in {viewName}."
                : $"Resultaat {_searchIndex + 1} van {_searchMatches.Count} — de volledige regel is geselecteerd{(isMarked ? " en gemarkeerd" : string.Empty)}.";

        return new SearchNavigationState(viewName, _searchIndex, _searchMatches.Count, isMarked, markedCount, message);
    }

    private void NavigateToSearchItem(SearchScope scope, object item)
    {
        ClearCurrentSearchHighlight();
        _currentSearchItem = item;

        if (scope.Control is DataGrid dataGrid) dataGrid.SelectedItem = item;
        if (scope.Control is ListBox listBox) listBox.SelectedItem = item;

        _currentSearchContainer = FindContainer(scope.Control, item, scrollIntoView: true);
        if (_currentSearchContainer is not null)
        {
            SearchVisual.SetIsMarked(_currentSearchContainer, _markedSearchItems.Contains(item));
            SearchVisual.SetIsCurrent(_currentSearchContainer, true);
            _currentSearchContainer.BringIntoView();
        }
    }

    private void ClearCurrentSearchHighlight()
    {
        if (_currentSearchContainer is not null) SearchVisual.SetIsCurrent(_currentSearchContainer, false);
        _currentSearchContainer = null;
        _currentSearchItem = null;
    }

    private FrameworkElement? FindContainer(ItemsControl control, object item, bool scrollIntoView)
    {
        if (scrollIntoView)
        {
            if (control is DataGrid dataGrid) dataGrid.ScrollIntoView(item);
            if (control is ListBox listBox) listBox.ScrollIntoView(item);
            control.UpdateLayout();
        }

        return control.ItemContainerGenerator.ContainerFromItem(item) as FrameworkElement;
    }

    private SearchScope? CurrentSearchScope()
    {
        if (Analysis is null) return null;
        var (name, control) = ResultsTabControl.SelectedIndex switch
        {
            0 => ("Overzicht — adressen en rollen", (ItemsControl)IdentityGrid),
            1 => ("Route", RouteGrid),
            2 => ("Authenticatie", AuthenticationGrid),
            3 => ("Transport", TransportGrid),
            4 => ("Bevindingen", (ItemsControl)FindingsList),
            5 => ("Alle headers", HeadersGrid),
            6 => ("Ongeldige headerregels", InvalidHeaderGrid),
            _ => ("Huidige weergave", (ItemsControl)IdentityGrid)
        };
        return new SearchScope(name, control, control.Items.Cast<object>().ToList());
    }

    private void ResultsTabControl_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.Source, ResultsTabControl)) return;
        ClearCurrentSearchHighlight();
        _searchMatches = [];
        _searchIndex = -1;
        _searchWindow?.RefreshForCurrentView();
    }

    private void DataGrid_LoadingRow(object sender, DataGridRowEventArgs e)
    {
        SearchVisual.SetIsMarked(e.Row, _markedSearchItems.Contains(e.Row.Item));
        SearchVisual.SetIsCurrent(e.Row, ReferenceEquals(e.Row.Item, _currentSearchItem));
    }

    private void ResetSearchNavigation(bool clearMarks)
    {
        ClearCurrentSearchHighlight();
        _searchMatches = [];
        _searchIndex = -1;
        _searchQuery = string.Empty;
        if (clearMarks) _markedSearchItems.Clear();
    }

    private sealed record SearchScope(string Name, ItemsControl Control, IReadOnlyList<object> Items);

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
