using System.Collections.ObjectModel;

namespace SmtpHeaderAnalyzer.Models;

public enum FindingSeverity
{
    Info,
    Good,
    Warning,
    Critical
}

public sealed record HeaderField(int Index, string Name, string Value, string Raw)
{
    public string DisplayValue => Value.Replace("\r", "").Replace("\n", " ");
    public FindingSeverity? RelatedSeverity { get; set; }
}

public sealed record InvalidHeaderLine(int LineNumber, string Reason, string Raw)
{
    public FindingSeverity RelatedSeverity => FindingSeverity.Warning;
}

public sealed record MailIdentity(string Role, string DisplayName, string Address, string Domain, string RawValue)
{
    public FindingSeverity? RelatedSeverity { get; set; }
}

public sealed record RouteHop(
    int Number,
    DateTimeOffset? Timestamp,
    string From,
    string By,
    string With,
    string Id,
    string For,
    string IpAddress,
    TimeSpan? Delay,
    bool IsClaimedOrigin,
    string Raw)
{
    public string TimestampDisplay => Timestamp?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz") ?? "Geen timestamp";
    public string DelayDisplay => Delay is null ? "—" : Delay.Value.TotalSeconds < 60
        ? $"{Delay.Value.TotalSeconds:0.#} sec"
        : $"{Delay.Value.TotalMinutes:0.#} min";
    public FindingSeverity? RelatedSeverity { get; set; }
}

public sealed record AuthenticationCheck(
    string Mechanism,
    string Result,
    string Domain,
    string Identity,
    string Selector,
    string Details)
{
    public bool IsPass => Result.Equals("pass", StringComparison.OrdinalIgnoreCase) || Result.Equals("bestguesspass", StringComparison.OrdinalIgnoreCase);
    public FindingSeverity? RelatedSeverity { get; set; }
}

public sealed record TransportSecurity(
    int Hop,
    string From,
    string By,
    string Protocol,
    string TlsVersion,
    string Cipher,
    string EncryptionStatus,
    string Details)
{
    public FindingSeverity? RelatedSeverity { get; set; }
}

public sealed record SpamIndicator(
    string Name,
    string Value,
    double? NumericValue,
    double? Threshold,
    string Verdict,
    FindingSeverity Severity,
    string Explanation,
    string SourceHeader,
    int HeaderIndex,
    string Reference)
{
    public FindingSeverity RelatedSeverity => Severity;
}

public sealed record AnalysisFinding(FindingSeverity Severity, string Title, string Explanation, string Evidence)
{
    public string StandardsReference { get; init; } = string.Empty;
    public IReadOnlyList<int> RelatedHeaderIndexes { get; init; } = [];
    public IReadOnlyList<int> RelatedRouteHops { get; init; } = [];
    public IReadOnlyList<string> RelatedIdentityRoles { get; init; } = [];
    public IReadOnlyList<string> RelatedAuthenticationMechanisms { get; init; } = [];
    public IReadOnlyList<int> RelatedTransportHops { get; init; } = [];

    public string SeverityLabel => Severity switch
    {
        FindingSeverity.Critical => "KRITIEK",
        FindingSeverity.Warning => "LET OP",
        FindingSeverity.Good => "GOED",
        _ => "INFO"
    };
}

public sealed class MailAnalysis
{
    public ObservableCollection<HeaderField> Headers { get; } = [];
    public ObservableCollection<InvalidHeaderLine> InvalidHeaderLines { get; } = [];
    public ObservableCollection<MailIdentity> Identities { get; } = [];
    public ObservableCollection<RouteHop> Route { get; } = [];
    public ObservableCollection<AuthenticationCheck> Authentication { get; } = [];
    public ObservableCollection<TransportSecurity> Transport { get; } = [];
    public ObservableCollection<AnalysisFinding> Findings { get; } = [];
    public ObservableCollection<SpamIndicator> SpamIndicators { get; } = [];

    public string SourceLabel { get; set; } = "Geplakte headers";
    public string Subject { get; set; } = "(geen onderwerp)";
    public string MessageId { get; set; } = "—";
    public string Date { get; set; } = "—";
    public string ClaimedOrigin { get; set; } = "Onbekend";
    public string OriginConfidence { get; set; } = "Beperkt";
    public string OriginExplanation { get; set; } = "Geen route-informatie beschikbaar.";
    public int InvalidLineCount => InvalidHeaderLines.Count;
    public bool HasInvalidHeaderLines => InvalidHeaderLines.Count > 0;
    public string RawHeaders { get; set; } = string.Empty;

    public int CriticalCount => Findings.Count(item => item.Severity == FindingSeverity.Critical);
    public int WarningCount => Findings.Count(item => item.Severity == FindingSeverity.Warning);
    public int PassedAuthCount => Authentication.Where(item => item.IsPass).Select(item => item.Mechanism).Distinct(StringComparer.OrdinalIgnoreCase).Count();
}
