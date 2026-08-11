using SmtpHeaderAnalyzer.Models;

namespace SmtpHeaderAnalyzer.Services;

internal static class SearchService
{
    public static bool Matches(object item, string query) =>
        GetSearchableText(item).Contains(query.Trim(), StringComparison.OrdinalIgnoreCase);

    public static string GetSearchableText(object item) => item switch
    {
        MailIdentity identity => Join(identity.Role, identity.DisplayName, identity.Address, identity.Domain, identity.RawValue),
        RouteHop hop => Join(hop.Number, hop.TimestampDisplay, hop.Timestamp?.UtcDateTime.ToString("O"), hop.From, hop.By, hop.With, hop.Id, hop.For, hop.IpAddress, hop.DelayDisplay, hop.Raw),
        AuthenticationCheck check => Join(check.Mechanism, check.Result, check.Domain, check.Identity, check.Selector, check.Details),
        TransportSecurity transport => Join(transport.Hop, transport.From, transport.By, transport.Protocol, transport.TlsVersion, transport.Cipher, transport.EncryptionStatus, transport.Details),
        AnalysisFinding finding => Join(finding.SeverityLabel, finding.Title, finding.Explanation, finding.Evidence),
        HeaderField header => Join(header.Index, header.Name, header.DisplayValue, header.Raw),
        _ => item.ToString() ?? string.Empty
    };

    private static string Join(params object?[] values) => string.Join('\n', values.Where(value => value is not null));
}

internal sealed record SearchNavigationState(
    string ViewName,
    int Index,
    int Count,
    bool IsMarked,
    int MarkedCount,
    string Message);
