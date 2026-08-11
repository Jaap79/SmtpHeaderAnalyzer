using System.Text;
using System.Text.Json;
using System.Globalization;
using SmtpHeaderAnalyzer.Models;

namespace SmtpHeaderAnalyzer.Services;

public static class ReportService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string ToJson(MailAnalysis analysis)
    {
        var report = new
        {
            generatedAt = DateTimeOffset.Now,
            offlineAnalysis = true,
            caveat = "Headeranalyse verifieert geen actuele DNS-records. Received-regels onder de vertrouwde relaygrens kunnen zijn vervalst.",
            source = analysis.SourceLabel,
            message = new { analysis.Subject, analysis.MessageId, analysis.Date },
            origin = new { claimed = analysis.ClaimedOrigin, confidence = analysis.OriginConfidence, explanation = analysis.OriginExplanation },
            identities = analysis.Identities,
            route = analysis.Route,
            authentication = analysis.Authentication,
            transport = analysis.Transport,
            findings = analysis.Findings,
            headers = analysis.Headers
        };
        return JsonSerializer.Serialize(report, JsonOptions);
    }

    public static string ToText(MailAnalysis analysis)
    {
        var builder = new StringBuilder();
        builder.AppendLine("SMTP HEADER ANALYSE");
        builder.AppendLine($"Bron: {analysis.SourceLabel}");
        builder.AppendLine($"Onderwerp: {analysis.Subject}");
        builder.AppendLine($"Message-ID: {analysis.MessageId}");
        builder.AppendLine($"Vermoedelijke oorsprong: {analysis.ClaimedOrigin}");
        builder.AppendLine($"Betrouwbaarheid: {analysis.OriginConfidence}");
        builder.AppendLine();
        builder.AppendLine("AFZENDERIDENTITEITEN");
        foreach (var identity in analysis.Identities) builder.AppendLine($"- {identity.Role}: {identity.Address} ({identity.Domain})");
        builder.AppendLine();
        builder.AppendLine("AUTHENTICATIE");
        foreach (var item in analysis.Authentication) builder.AppendLine($"- {item.Mechanism}: {item.Result}; domein={item.Domain}; selector={item.Selector}");
        builder.AppendLine();
        builder.AppendLine("ROUTE (OUDSTE NAAR NIEUWSTE)");
        foreach (var hop in analysis.Route) builder.AppendLine($"- {hop.Number}. {hop.TimestampDisplay} | {hop.From} -> {hop.By} | {hop.With} | delta {hop.DelayDisplay}");
        builder.AppendLine();
        builder.AppendLine("BEVINDINGEN");
        foreach (var finding in analysis.Findings) builder.AppendLine($"- [{finding.SeverityLabel}] {finding.Title}: {finding.Explanation} | {finding.Evidence}");
        builder.AppendLine();
        builder.AppendLine("Let op: offline headeranalyse voert geen DNS-hercontrole uit en bewijst geen legitimiteit.");
        return builder.ToString();
    }

    public static string ToCsv(MailAnalysis analysis)
    {
        var builder = new StringBuilder();
        AppendCsvRow(builder, "record_type", "sequence", "timestamp_utc", "category", "name", "value", "result", "from", "by", "ip_address", "domain", "identity", "selector", "protocol", "tls_version", "cipher", "severity", "details", "raw_evidence");

        foreach (var header in analysis.Headers)
            AppendCsvRow(builder, "header", header.Index.ToString(CultureInfo.InvariantCulture), "", "header", header.Name, header.Value, "", "", "", "", "", "", "", "", "", "", "", "", header.Raw);

        foreach (var identity in analysis.Identities)
            AppendCsvRow(builder, "identity", "", "", "address", identity.Role, identity.Address, "", "", "", "", identity.Domain, identity.Address, "", "", "", "", "", identity.DisplayName, identity.RawValue);

        foreach (var hop in analysis.Route)
            AppendCsvRow(builder, "route_hop", hop.Number.ToString(CultureInfo.InvariantCulture), UtcTimestamp(hop.Timestamp), "mail_route", $"SMTP hop {hop.Number}", hop.Id, "", hop.From, hop.By, hop.IpAddress, "", "", "", hop.With, "", "", "", $"delay={hop.DelayDisplay}; recipient={hop.For}", hop.Raw);

        foreach (var item in analysis.Authentication)
            AppendCsvRow(builder, "authentication", "", "", "authentication", item.Mechanism, "", item.Result, "", "", "", item.Domain, item.Identity, item.Selector, "", "", "", "", item.Details, "");

        foreach (var item in analysis.Transport)
            AppendCsvRow(builder, "transport", item.Hop.ToString(CultureInfo.InvariantCulture), "", "transport_security", $"Transport hop {item.Hop}", item.EncryptionStatus, "", item.From, item.By, "", "", "", "", item.Protocol, item.TlsVersion, item.Cipher, "", item.Details, item.Details);

        foreach (var finding in analysis.Findings)
            AppendCsvRow(builder, "finding", "", "", "finding", finding.Title, finding.Explanation, "", "", "", "", "", "", "", "", "", "", finding.SeverityLabel, finding.Explanation, finding.Evidence);

        return builder.ToString();
    }

    public static string ToTimelineCsv(MailAnalysis analysis)
    {
        var builder = new StringBuilder();
        AppendCsvRow(builder, "timestamp", "event", "source", "category", "actor", "tags", "evidence", "files", "parent_id", "relation", "notes", "raw_line", "id", "created_at", "updated_at");
        var generatedAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

        foreach (var hop in analysis.Route)
        {
            var transport = analysis.Transport.FirstOrDefault(item => item.Hop == hop.Number);
            var id = $"smtp-hop-{hop.Number:D3}";
            var parentId = hop.Number > 1 ? $"smtp-hop-{hop.Number - 1:D3}" : string.Empty;
            var timestamp = UtcTimestamp(hop.Timestamp);
            var tags = new List<string> { "smtp", "email", "route" };
            if (transport?.EncryptionStatus.StartsWith("Versleuteld", StringComparison.OrdinalIgnoreCase) == true) tags.Add("encrypted");
            if (string.IsNullOrWhiteSpace(timestamp)) tags.Add("timestamp-missing");
            var actor = string.IsNullOrWhiteSpace(hop.IpAddress) ? hop.From : $"{hop.From} [{hop.IpAddress}]";
            var eventText = $"SMTP hop {hop.Number}: {hop.From} -> {hop.By}";
            var notes = $"protocol={hop.With}; delay={hop.DelayDisplay}; id={hop.Id}; recipient={hop.For}; tls={transport?.TlsVersion}; cipher={transport?.Cipher}";

            AppendCsvRow(builder,
                timestamp,
                eventText,
                analysis.SourceLabel,
                "Email transport",
                actor,
                string.Join(", ", tags),
                Flatten(hop.Raw),
                "[]",
                parentId,
                hop.Number > 1 ? "relayed_to" : string.Empty,
                notes,
                Flatten(hop.Raw),
                id,
                generatedAt,
                generatedAt);
        }

        return builder.ToString();
    }

    private static string UtcTimestamp(DateTimeOffset? value) => value?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture) ?? string.Empty;

    private static string Flatten(string value) => value.Replace("\r", string.Empty).Replace('\n', ' ').Trim();

    private static void AppendCsvRow(StringBuilder builder, params string?[] values)
    {
        builder.AppendLine(string.Join(',', values.Select(EscapeCsv)));
    }

    private static string EscapeCsv(string? value)
    {
        value ??= string.Empty;
        return value.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }
}
