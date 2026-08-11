using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.IO;
using System.Text.Json;

namespace SmtpHeaderAnalyzer.Services;

public sealed record UpdateCheckResult(bool UpdateAvailable, string LatestVersion, string ReleaseUrl, string Message);

public sealed class UpdateService
{
    public const string RepositoryUrl = "https://github.com/Jaap79/SmtpHeaderAnalyzer";
    private const string LatestReleaseApiUrl = "https://api.github.com/repos/Jaap79/SmtpHeaderAnalyzer/releases/latest";

    public async Task<UpdateCheckResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        using var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(5)
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("SmtpHeaderAnalyzer", AppVersion.Current));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        using var response = await client.GetAsync(LatestReleaseApiUrl, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new(false, AppVersion.Current, RepositoryUrl, "Er is nog geen publieke release beschikbaar.");
        }

        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var json = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var root = json.RootElement;
        var tag = root.TryGetProperty("tag_name", out var tagValue) ? tagValue.GetString() ?? string.Empty : string.Empty;
        var url = root.TryGetProperty("html_url", out var urlValue) ? urlValue.GetString() ?? RepositoryUrl : RepositoryUrl;
        var latest = NormalizeVersion(tag);

        if (!Version.TryParse(latest, out _))
        {
            throw new InvalidDataException("GitHub gaf geen herkenbaar versienummer terug.");
        }

        var available = IsNewerVersion(AppVersion.Current, latest);
        return available
            ? new(true, latest, url, $"Versie {latest} is beschikbaar.")
            : new(false, latest, url, $"Versie {AppVersion.Current} is actueel.");
    }

    public static bool IsNewerVersion(string current, string candidate)
    {
        if (!Version.TryParse(NormalizeVersion(current), out var currentVersion)) return false;
        return Version.TryParse(NormalizeVersion(candidate), out var candidateVersion) && candidateVersion > currentVersion;
    }

    private static string NormalizeVersion(string value)
    {
        var normalized = value.Trim().TrimStart('v', 'V');
        var suffix = normalized.IndexOfAny(['-', '+']);
        return suffix >= 0 ? normalized[..suffix] : normalized;
    }
}
