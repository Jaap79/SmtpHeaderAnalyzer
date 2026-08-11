using System.Diagnostics;
using System.Net.Http;
using System.Windows;
using SmtpHeaderAnalyzer.Services;

namespace SmtpHeaderAnalyzer;

public partial class AboutWindow : Window
{
    private readonly UpdateService _updateService = new();
    private string _releaseUrl = UpdateService.RepositoryUrl;

    public AboutWindow()
    {
        InitializeComponent();
        VersionText.Text = $"Versie {AppVersion.Current}";
    }

    private void Window_SourceInitialized(object? sender, EventArgs e) => ThemeService.ApplyWindow(this);

    private async void CheckForUpdate_Click(object sender, RoutedEventArgs e)
    {
        UpdateButton.IsEnabled = false;
        ReleaseButton.Visibility = Visibility.Collapsed;
        UpdateStatusText.SetResourceReference(ForegroundProperty, "MutedTextBrush");
        UpdateStatusText.Text = "GitHub wordt gecontroleerd...";

        try
        {
            var result = await _updateService.CheckAsync();
            _releaseUrl = result.ReleaseUrl;
            UpdateStatusText.Text = result.Message;
            UpdateStatusText.SetResourceReference(ForegroundProperty, result.UpdateAvailable ? "WarningBrush" : "GoodBrush");
            ReleaseButton.Visibility = result.UpdateAvailable ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (HttpRequestException exception)
        {
            ShowUpdateError($"Updatecontrole mislukt: {FriendlyMessage(exception)}");
        }
        catch (TaskCanceledException)
        {
            ShowUpdateError("Updatecontrole is verlopen. Controleer de internetverbinding en probeer opnieuw.");
        }
        catch (Exception exception)
        {
            ShowUpdateError($"Updatecontrole mislukt: {FriendlyMessage(exception)}");
        }
        finally
        {
            UpdateButton.IsEnabled = true;
        }
    }

    private void ShowUpdateError(string message)
    {
        UpdateStatusText.Text = message;
        UpdateStatusText.SetResourceReference(ForegroundProperty, "DangerBrush");
    }

    private static string FriendlyMessage(Exception exception) =>
        exception.Message.Replace("https://api.github.com/repos/Jaap79/SmtpHeaderAnalyzer/releases/latest", "GitHub", StringComparison.OrdinalIgnoreCase);

    private void OpenRelease_Click(object sender, RoutedEventArgs e) =>
        Process.Start(new ProcessStartInfo(_releaseUrl) { UseShellExecute = true });

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
