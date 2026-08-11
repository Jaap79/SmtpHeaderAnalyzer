using System.Windows;
using System.Windows.Input;
using SmtpHeaderAnalyzer.Services;

namespace SmtpHeaderAnalyzer;

public partial class SearchWindow : Window
{
    private readonly MainWindow _host;

    public SearchWindow(MainWindow host)
    {
        _host = host;
        InitializeComponent();
        if (host.IsVisible) Owner = host;
        RefreshForCurrentView();
    }

    private void Window_SourceInitialized(object? sender, EventArgs e) => ThemeService.ApplyWindow(this);

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        SearchTextBox.Focus();
        SearchTextBox.SelectAll();
    }

    internal void RefreshForCurrentView()
    {
        var state = _host.StartSearch(SearchTextBox?.Text ?? string.Empty);
        Apply(state);
    }

    private void SearchTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
        Apply(_host.StartSearch(SearchTextBox.Text));

    private void Previous_Click(object sender, RoutedEventArgs e) => Apply(_host.MoveSearch(-1));
    private void Next_Click(object sender, RoutedEventArgs e) => Apply(_host.MoveSearch(1));
    private void Mark_Click(object sender, RoutedEventArgs e) => Apply(_host.ToggleCurrentSearchMark());
    private void ClearMarks_Click(object sender, RoutedEventArgs e) => Apply(_host.ClearSearchMarksInCurrentView());
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Apply(SearchNavigationState state)
    {
        ViewText.Text = $"Zoeken in: {state.ViewName}";
        ResultText.Text = state.Message;
        var hasResults = state.Count > 0;
        PreviousButton.IsEnabled = hasResults;
        NextButton.IsEnabled = hasResults;
        MarkButton.IsEnabled = hasResults;
        MarkButton.Content = state.IsMarked ? "Markering verwijderen" : "Markeer regel";
        ClearMarksButton.IsEnabled = state.MarkedCount > 0;
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            Close();
            e.Handled = true;
        }
        else if (e.Key == Key.F3 || (e.Key == Key.Enter && ReferenceEquals(Keyboard.FocusedElement, SearchTextBox)))
        {
            Apply(_host.MoveSearch(Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) ? -1 : 1));
            e.Handled = true;
        }
    }

    private void Window_Closed(object? sender, EventArgs e) => _host.SearchWindowClosed(this);
}
