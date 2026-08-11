using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using SmtpHeaderAnalyzer.Models;

namespace SmtpHeaderAnalyzer.Services;

public sealed partial class HeaderAnalyzer
{
    private static readonly HashSet<string> IdentityHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "From", "Sender", "Reply-To", "Return-Path", "To", "Cc", "Delivered-To", "Envelope-To", "Resent-From"
    };

    public MailAnalysis Analyze(string input, string sourceLabel = "Geplakte headers")
    {
        if (string.IsNullOrWhiteSpace(input)) throw new InvalidDataException("Plak headers of open een EML/MSG-bestand.");
        if (input.Length > 5_000_000) throw new InvalidDataException("De headerinvoer is groter dan de limiet van 5 MB.");

        var analysis = new MailAnalysis { SourceLabel = sourceLabel, RawHeaders = Normalize(input) };
        ParseFields(analysis);
        ParseSummary(analysis);
        ParseIdentities(analysis);
        ParseRoute(analysis);
        ParseAuthentication(analysis);
        ParseTransport(analysis);
        BuildFindings(analysis);
        return analysis;
    }

    private static void ParseFields(MailAnalysis analysis)
    {
        var lines = analysis.RawHeaders.Split('\n');
        string? name = null;
        var value = new StringBuilder();
        var raw = new StringBuilder();
        var index = 0;

        void Flush()
        {
            if (name is null) return;
            analysis.Headers.Add(new HeaderField(++index, name, Rfc2047.Decode(value.ToString().Trim()), raw.ToString().TrimEnd()));
            name = null;
            value.Clear();
            raw.Clear();
        }

        foreach (var sourceLine in lines)
        {
            var line = sourceLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                Flush();
                continue;
            }

            if ((line[0] == ' ' || line[0] == '\t') && name is not null)
            {
                value.Append(' ').Append(line.Trim());
                raw.AppendLine(line);
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0 || !HeaderNameRegex().IsMatch(line[..colon]))
            {
                Flush();
                analysis.InvalidLineCount++;
                continue;
            }

            Flush();
            name = line[..colon];
            value.Append(line[(colon + 1)..].TrimStart());
            raw.AppendLine(line);
        }
        Flush();

        if (analysis.Headers.Count == 0) throw new InvalidDataException("Geen geldige mailheaders gevonden.");
    }

    private static void ParseSummary(MailAnalysis analysis)
    {
        analysis.Subject = First(analysis, "Subject") ?? "(geen onderwerp)";
        analysis.MessageId = First(analysis, "Message-ID") ?? "—";
        analysis.Date = First(analysis, "Date") ?? "—";
    }

    private static void ParseIdentities(MailAnalysis analysis)
    {
        foreach (var header in analysis.Headers.Where(item => IdentityHeaders.Contains(item.Name)))
        {
            foreach (var identity in ParseAddresses(header.Value))
            {
                analysis.Identities.Add(new MailIdentity(header.Name, identity.DisplayName, identity.Address, DomainOf(identity.Address), header.Value));
            }

            if (!ParseAddresses(header.Value).Any() && header.Name.Equals("Return-Path", StringComparison.OrdinalIgnoreCase))
            {
                analysis.Identities.Add(new MailIdentity(header.Name, string.Empty, header.Value.Trim('<', '>', ' '), DomainOf(header.Value), header.Value));
            }
        }
    }

    private static void ParseRoute(MailAnalysis analysis)
    {
        var received = analysis.Headers.Where(item => item.Name.Equals("Received", StringComparison.OrdinalIgnoreCase)).Reverse().ToList();
        DateTimeOffset? previous = null;
        for (var index = 0; index < received.Count; index++)
        {
            var value = received[index].Value;
            var timestamp = ParseReceivedTimestamp(value);
            TimeSpan? delay = timestamp is not null && previous is not null ? timestamp.Value - previous.Value : null;
            var from = Token(value, "from", "by|with|via|id|for|;");
            var by = Token(value, "by", "from|with|via|id|for|;");
            var with = Token(value, "with", "from|by|via|id|for|;");
            var id = Token(value, "id", "from|by|with|via|for|;");
            var recipient = Token(value, "for", ";");
            var ip = ExtractIp(from);

            analysis.Route.Add(new RouteHop(index + 1, timestamp, from, by, with, id, recipient, ip, delay, index == 0, received[index].Raw));
            if (timestamp is not null) previous = timestamp;
        }

        if (analysis.Route.Count > 0)
        {
            var origin = analysis.Route[0];
            var originHost = origin.From.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? origin.From;
            analysis.ClaimedOrigin = !string.IsNullOrWhiteSpace(origin.IpAddress)
                ? $"{originHost}  [{origin.IpAddress}]"
                : string.IsNullOrWhiteSpace(origin.From) ? "Onbekend" : origin.From;
            analysis.OriginConfidence = "Beperkt — headerbewijs";
            analysis.OriginExplanation = "Onderste Received-hop (chronologisch de eerste claim). Zonder bekende vertrouwde relaygrens kan een afzender oudere Received-regels vervalsen.";
        }
    }

    private static void ParseAuthentication(MailAnalysis analysis)
    {
        foreach (var header in analysis.Headers.Where(item => item.Name.EndsWith("Authentication-Results", StringComparison.OrdinalIgnoreCase)))
        {
            var parts = SplitOutsideParentheses(header.Value, ';');
            var authority = parts.FirstOrDefault()?.Trim() ?? string.Empty;
            foreach (var part in parts.Skip(1))
            {
                var match = AuthResultRegex().Match(part.Trim());
                if (!match.Success) continue;
                var mechanism = match.Groups["mechanism"].Value.ToUpperInvariant();
                var result = match.Groups["result"].Value.ToLowerInvariant();
                var details = match.Groups["details"].Value.Trim();
                analysis.Authentication.Add(new AuthenticationCheck(
                    mechanism,
                    result,
                    ExtractParameter(details, mechanism.Equals("DKIM", StringComparison.OrdinalIgnoreCase) ? "header.d" : "smtp.mailfrom", "header.from", "smtp.helo"),
                    ExtractParameter(details, "header.from", "smtp.mailfrom", "smtp.helo"),
                    ExtractParameter(details, "header.s"),
                    $"{authority}: {details}".TrimEnd(':', ' ')));
            }
        }

        foreach (var header in analysis.Headers.Where(item => item.Name.Equals("Received-SPF", StringComparison.OrdinalIgnoreCase)))
        {
            var result = header.Value.Split([' ', '('], 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.ToLowerInvariant() ?? "none";
            analysis.Authentication.Add(new AuthenticationCheck("SPF", result,
                ExtractParameter(header.Value, "envelope-from", "identity", "helo"),
                ExtractParameter(header.Value, "envelope-from", "identity"), string.Empty, header.Value));
        }

        foreach (var header in analysis.Headers.Where(item => item.Name.Equals("DKIM-Signature", StringComparison.OrdinalIgnoreCase)))
        {
            var tags = ParseTagList(header.Value);
            analysis.Authentication.Add(new AuthenticationCheck("DKIM SIGNATURE", "present",
                Get(tags, "d"), string.Empty, Get(tags, "s"),
                $"algoritme={Get(tags, "a")}; canonicalisatie={Get(tags, "c")}; signed-headers={Get(tags, "h")}"));
        }

        foreach (var header in analysis.Headers.Where(item => item.Name.StartsWith("ARC-", StringComparison.OrdinalIgnoreCase) && !item.Name.Equals("ARC-Authentication-Results", StringComparison.OrdinalIgnoreCase)))
        {
            var tags = ParseTagList(header.Value);
            analysis.Authentication.Add(new AuthenticationCheck(header.Name.ToUpperInvariant(), Get(tags, "cv", "present"), Get(tags, "d"), string.Empty, Get(tags, "s"), $"instance={Get(tags, "i")}; algoritme={Get(tags, "a")}"));
        }
    }

    private static void ParseTransport(MailAnalysis analysis)
    {
        foreach (var hop in analysis.Route)
        {
            var tlsVersion = TlsVersionRegex().Match(hop.Raw).Value.Replace('_', '.').ToUpperInvariant();
            var cipher = CipherRegex().Match(hop.Raw).Value;
            var encrypted = !string.IsNullOrWhiteSpace(tlsVersion) || !string.IsNullOrWhiteSpace(cipher) || hop.With.Contains("SMTPS", StringComparison.OrdinalIgnoreCase);
            analysis.Transport.Add(new TransportSecurity(hop.Number, hop.From, hop.By, hop.With,
                string.IsNullOrWhiteSpace(tlsVersion) ? "—" : tlsVersion,
                string.IsNullOrWhiteSpace(cipher) ? "—" : cipher,
                encrypted ? "Versleuteld of geïmpliceerd" : "Niet aantoonbaar",
                hop.Raw.Replace("\r", "").Replace("\n", " ")));
        }
    }

    private static void BuildFindings(MailAnalysis analysis)
    {
        AddAuthFindings(analysis);
        AddIdentityFindings(analysis);

        if (analysis.Route.Count == 0)
        {
            Add(analysis, FindingSeverity.Warning, "Geen Received-route", "De serverroute en oorsprong zijn niet vast te stellen.", "Received ontbreekt.");
        }
        else
        {
            Add(analysis, FindingSeverity.Info, "Oorsprong is een onderbouwde claim", analysis.OriginExplanation, analysis.ClaimedOrigin);
        }

        foreach (var hop in analysis.Route.Where(item => item.Delay is { TotalSeconds: < -5 }))
        {
            Add(analysis, FindingSeverity.Warning, "Niet-monotone tijdlijn", $"Hop {hop.Number} ligt eerder dan de voorgaande hop. Mogelijke klokafwijking of gemanipuleerde header.", hop.Raw);
        }
        foreach (var hop in analysis.Route.Where(item => item.Delay is { TotalMinutes: > 15 }))
        {
            Add(analysis, FindingSeverity.Warning, "Opvallende bezorgvertraging", $"Tussen hop {hop.Number - 1} en {hop.Number} zit {hop.DelayDisplay}.", hop.Raw);
        }

        var dateHeaders = All(analysis, "Date").ToList();
        if (dateHeaders.Count == 0) Add(analysis, FindingSeverity.Warning, "Date ontbreekt", "De verzendtijd is niet aanwezig.", "Geen Date-header.");
        if (All(analysis, "From").Count() > 1) Add(analysis, FindingSeverity.Critical, "Meerdere From-headers", "Meerdere auteurvelden zijn verdacht en kunnen parsingverschillen uitlokken.", string.Join(" | ", All(analysis, "From")));
        if (All(analysis, "Message-ID").Count() > 1) Add(analysis, FindingSeverity.Warning, "Meerdere Message-ID-headers", "De mail bevat meerdere unieke identifiers.", string.Join(" | ", All(analysis, "Message-ID")));
        if (analysis.InvalidLineCount > 0) Add(analysis, FindingSeverity.Warning, "Ongeldige headerregels", $"{analysis.InvalidLineCount} regel(s) konden niet als RFC-header worden geïnterpreteerd.", "Bekijk Alle headers voor de brondata.");

        foreach (var header in analysis.Headers.Where(item => item.Name.Equals("Diagnostic-Code", StringComparison.OrdinalIgnoreCase) || item.Name.Equals("Status", StringComparison.OrdinalIgnoreCase) || item.Name.Equals("Action", StringComparison.OrdinalIgnoreCase) || item.Name.Equals("X-Failed-Recipients", StringComparison.OrdinalIgnoreCase)))
        {
            Add(analysis, FindingSeverity.Critical, $"Afleverfout: {header.Name}", "De mail bevat DSN- of foutafhandelingsinformatie.", header.Value);
        }
        foreach (var header in analysis.Headers.Where(item => item.Name.Contains("Spam", StringComparison.OrdinalIgnoreCase) || item.Name.Contains("Antispam", StringComparison.OrdinalIgnoreCase) || item.Name.Equals("X-MS-Exchange-Organization-SCL", StringComparison.OrdinalIgnoreCase)))
        {
            Add(analysis, FindingSeverity.Info, $"Filtermetadata: {header.Name}", "Lokale spam- of transportclassificatie aangetroffen.", header.Value);
        }
        if (analysis.Headers.Any(item => item.Name.Equals("X-Analyzer-Warning", StringComparison.OrdinalIgnoreCase)))
        {
            Add(analysis, FindingSeverity.Warning, "MSG bevat geen transportheaders", "Alleen opgeslagen MAPI-velden konden worden gelezen; route- en authenticatieanalyse is hierdoor onvolledig.", First(analysis, "X-Analyzer-Warning") ?? string.Empty);
        }

        if (!analysis.Findings.Any(item => item.Severity is FindingSeverity.Critical or FindingSeverity.Warning))
        {
            Add(analysis, FindingSeverity.Good, "Geen directe headeranomalieën", "De offline controles vonden geen duidelijke afwijkingen. Dit bewijst niet dat de mail legitiem is.", "Controleer inhoud en context afzonderlijk.");
        }
    }

    private static void AddAuthFindings(MailAnalysis analysis)
    {
        foreach (var mechanism in new[] { "SPF", "DKIM", "DMARC" })
        {
            var checks = analysis.Authentication.Where(item => item.Mechanism.Equals(mechanism, StringComparison.OrdinalIgnoreCase)).ToList();
            if (checks.Any(item => item.IsPass))
            {
                Add(analysis, FindingSeverity.Good, $"{mechanism} geslaagd", "De ontvangende infrastructuur rapporteert een geldige controle.", string.Join(" | ", checks.Where(item => item.IsPass).Select(item => item.Details)));
            }
            else if (checks.Any(item => IsFailure(item.Result)))
            {
                Add(analysis, FindingSeverity.Critical, $"{mechanism} mislukt", "De ontvangende infrastructuur rapporteert een negatieve authenticatie-uitkomst.", string.Join(" | ", checks.Select(item => $"{item.Result}: {item.Details}")));
            }
            else if (checks.Count == 0)
            {
                Add(analysis, FindingSeverity.Warning, $"Geen {mechanism}-resultaat", "Deze aangeleverde headers bevatten geen verifieerbaar resultaat. Offline wordt geen DNS-hercontrole uitgevoerd.", "Authentication-Results/Received-SPF bevat geen resultaat.");
            }
        }
    }

    private static void AddIdentityFindings(MailAnalysis analysis)
    {
        var from = analysis.Identities.FirstOrDefault(item => item.Role.Equals("From", StringComparison.OrdinalIgnoreCase));
        if (from is null)
        {
            Add(analysis, FindingSeverity.Critical, "From ontbreekt", "Er is geen zichtbare auteurheader.", "Geen From-header.");
            return;
        }

        var returnPath = analysis.Identities.FirstOrDefault(item => item.Role.Equals("Return-Path", StringComparison.OrdinalIgnoreCase));
        var replyTo = analysis.Identities.FirstOrDefault(item => item.Role.Equals("Reply-To", StringComparison.OrdinalIgnoreCase));
        if (returnPath is not null && !DomainsAlign(from.Domain, returnPath.Domain))
        {
            Add(analysis, FindingSeverity.Warning, "From en Return-Path wijken af", "De zichtbare afzender en envelope sender gebruiken niet-uitgelijnde domeinen. Dit kan legitiem zijn bij verzendplatformen.", $"From={from.Address}; Return-Path={returnPath.Address}");
        }
        if (replyTo is not null && !DomainsAlign(from.Domain, replyTo.Domain))
        {
            Add(analysis, FindingSeverity.Warning, "Reply-To wijkt af", "Antwoorden worden naar een ander, niet-uitgelijnd domein gestuurd.", $"From={from.Address}; Reply-To={replyTo.Address}");
        }
    }

    private static IEnumerable<(string DisplayName, string Address)> ParseAddresses(string value)
    {
        foreach (Match match in MailboxRegex().Matches(value))
        {
            var address = match.Groups["angle"].Success ? match.Groups["angle"].Value : match.Groups["plain"].Value;
            var display = match.Groups["display"].Value.Trim().Trim('"');
            if (address.Contains('@')) yield return (display, address.Trim().Trim('<', '>', ','));
        }
    }

    private static string DomainOf(string value)
    {
        var clean = value.Trim().Trim('<', '>', ' ', ',', ';');
        var at = clean.LastIndexOf('@');
        return at >= 0 && at < clean.Length - 1 ? clean[(at + 1)..].TrimEnd('>') : string.Empty;
    }

    private static bool DomainsAlign(string first, string second)
    {
        if (string.IsNullOrWhiteSpace(first) || string.IsNullOrWhiteSpace(second)) return false;
        return first.Equals(second, StringComparison.OrdinalIgnoreCase) || first.EndsWith('.' + second, StringComparison.OrdinalIgnoreCase) || second.EndsWith('.' + first, StringComparison.OrdinalIgnoreCase);
    }

    private static DateTimeOffset? ParseReceivedTimestamp(string value)
    {
        var semicolon = value.LastIndexOf(';');
        if (semicolon < 0) return null;
        var candidate = CommentsRegex().Replace(value[(semicolon + 1)..], " ").Trim();
        return DateTimeOffset.TryParse(candidate, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var parsed) ? parsed : null;
    }

    private static string Token(string value, string token, string terminators)
    {
        var match = Regex.Match(value, $@"(?is)(?:^|\s){Regex.Escape(token)}\s+(?<value>.*?)(?=\s+(?:{terminators})\s+|;|$)");
        return match.Success ? WhitespaceRegex().Replace(match.Groups["value"].Value.Trim(), " ") : string.Empty;
    }

    private static string ExtractIp(string value)
    {
        foreach (Match match in IpCandidateRegex().Matches(value))
        {
            var candidate = match.Value.Trim('[', ']');
            if (IPAddress.TryParse(candidate, out _)) return candidate;
        }
        return string.Empty;
    }

    private static string ExtractParameter(string value, params string[] names)
    {
        foreach (var name in names)
        {
            var match = Regex.Match(value, $@"(?i)(?:^|\s){Regex.Escape(name)}\s*=\s*(?<value>[^\s;()]+)");
            if (match.Success) return match.Groups["value"].Value.Trim('"', '<', '>');
        }
        return string.Empty;
    }

    private static Dictionary<string, string> ParseTagList(string value) =>
        SplitOutsideParentheses(value, ';')
            .Select(part => part.Split('=', 2))
            .Where(parts => parts.Length == 2)
            .GroupBy(parts => parts[0].Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First()[1].Trim(), StringComparer.OrdinalIgnoreCase);

    private static string Get(Dictionary<string, string> tags, string key, string fallback = "") => tags.TryGetValue(key, out var value) ? value : fallback;

    private static IReadOnlyList<string> SplitOutsideParentheses(string value, char separator)
    {
        var result = new List<string>();
        var start = 0;
        var depth = 0;
        var quoted = false;
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] == '"') quoted = !quoted;
            if (quoted) continue;
            if (value[index] == '(') depth++;
            else if (value[index] == ')' && depth > 0) depth--;
            else if (value[index] == separator && depth == 0)
            {
                result.Add(value[start..index]);
                start = index + 1;
            }
        }
        result.Add(value[start..]);
        return result;
    }

    private static string? First(MailAnalysis analysis, string name) => analysis.Headers.FirstOrDefault(item => item.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;
    private static IEnumerable<string> All(MailAnalysis analysis, string name) => analysis.Headers.Where(item => item.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(item => item.Value);
    private static bool IsFailure(string value) => value.Equals("fail", StringComparison.OrdinalIgnoreCase) || value.Equals("softfail", StringComparison.OrdinalIgnoreCase) || value.Equals("temperror", StringComparison.OrdinalIgnoreCase) || value.Equals("permerror", StringComparison.OrdinalIgnoreCase);
    private static void Add(MailAnalysis analysis, FindingSeverity severity, string title, string explanation, string evidence) => analysis.Findings.Add(new AnalysisFinding(severity, title, explanation, evidence));

    private static string Normalize(string input) => input.Replace("\0", string.Empty).Replace("\r\n", "\n").Replace('\r', '\n').Trim();

    [GeneratedRegex("^[!-9;-~]+$")]
    private static partial Regex HeaderNameRegex();
    [GeneratedRegex(@"(?<display>[^,;<]*?)\s*<(?<angle>[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+)>|(?<plain>[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+)", RegexOptions.IgnoreCase)]
    private static partial Regex MailboxRegex();
    [GeneratedRegex(@"(?<mechanism>spf|dkim|dmarc|arc|compauth|iprev)\s*=\s*(?<result>[a-z0-9_-]+)(?<details>.*)", RegexOptions.IgnoreCase)]
    private static partial Regex AuthResultRegex();
    [GeneratedRegex(@"\([^()]*(?:\([^()]*\)[^()]*)*\)")]
    private static partial Regex CommentsRegex();
    [GeneratedRegex(@"\[[0-9A-Fa-f:.]+\]|(?<![A-Fa-f0-9:])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")]
    private static partial Regex IpCandidateRegex();
    [GeneratedRegex(@"(?i)TLS(?:v)?[ _]?(?:1[._][0-3]|1[0-3])")]
    private static partial Regex TlsVersionRegex();
    [GeneratedRegex(@"(?i)(?:TLS|ECDHE|DHE|AES|CHACHA20)[A-Z0-9_-]{5,}")]
    private static partial Regex CipherRegex();
    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespaceRegex();
}

internal static partial class Rfc2047
{
    public static string Decode(string input) => EncodedWordRegex().Replace(input, match =>
    {
        try
        {
            var encoding = Encoding.GetEncoding(match.Groups["charset"].Value);
            var payload = match.Groups["payload"].Value;
            byte[] bytes = match.Groups["kind"].Value.Equals("B", StringComparison.OrdinalIgnoreCase)
                ? Convert.FromBase64String(payload)
                : DecodeQuotedPrintable(payload);
            return encoding.GetString(bytes);
        }
        catch
        {
            return match.Value;
        }
    });

    private static byte[] DecodeQuotedPrintable(string input)
    {
        var bytes = new List<byte>();
        for (var index = 0; index < input.Length; index++)
        {
            if (input[index] == '_') bytes.Add((byte)' ');
            else if (input[index] == '=' && index + 2 < input.Length && byte.TryParse(input.AsSpan(index + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
            {
                bytes.Add(value);
                index += 2;
            }
            else bytes.Add((byte)input[index]);
        }
        return bytes.ToArray();
    }

    [GeneratedRegex(@"=\?(?<charset>[^?]+)\?(?<kind>[bqBQ])\?(?<payload>[^?]+)\?=")]
    private static partial Regex EncodedWordRegex();
}
