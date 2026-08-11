using System.Globalization;
using System.Text.RegularExpressions;
using SmtpHeaderAnalyzer.Models;

namespace SmtpHeaderAnalyzer.Services;

internal static partial class SpamIndicatorService
{
    private static readonly HashSet<string> MicrosoftReportHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "X-Forefront-Antispam-Report",
        "X-Microsoft-Antispam",
        "X-Microsoft-Antispam-Mailbox-Delivery",
        "X-MS-Exchange-Organization-Antispam-Report"
    };

    public static void Parse(MailAnalysis analysis)
    {
        foreach (var header in analysis.Headers)
        {
            if (header.Name.Equals("X-MS-Exchange-Organization-SCL", StringComparison.OrdinalIgnoreCase))
                AddNumeric(analysis, header, "SCL", header.Value, null);
            if (header.Name.Equals("X-MS-Exchange-Organization-PCL", StringComparison.OrdinalIgnoreCase))
                AddNumeric(analysis, header, "PCL", header.Value, null);

            if (MicrosoftReportHeaders.Contains(header.Name))
            {
                foreach (Match match in MicrosoftIndicatorRegex().Matches(header.Value))
                    AddMicrosoft(analysis, header, match.Groups["name"].Value.ToUpperInvariant(), match.Groups["value"].Value.Trim());
            }

            if (header.Name.Equals("X-Spam-Status", StringComparison.OrdinalIgnoreCase)) ParseSpamAssassinStatus(analysis, header);
            else if (header.Name.Equals("X-Spam-Flag", StringComparison.OrdinalIgnoreCase)) AddFlag(analysis, header, "SpamAssassin vlag", header.Value);
            else if (header.Name.Equals("X-Spam-Score", StringComparison.OrdinalIgnoreCase)) AddNumeric(analysis, header, "SpamAssassin score", header.Value, null);
            else if (header.Name.Equals("X-Spam-Level", StringComparison.OrdinalIgnoreCase)) AddSpamLevel(analysis, header);
            else if (header.Name.Equals("X-Rspamd-Score", StringComparison.OrdinalIgnoreCase)) ParseRspamdScore(analysis, header);
        }
    }

    private static void AddMicrosoft(MailAnalysis analysis, HeaderField header, string name, string value)
    {
        if (name is "SCL" or "BCL" or "PCL") AddNumeric(analysis, header, name, value, null);
        else
        {
            var (severity, verdict, explanation) = name switch
            {
                "SFV" => InterpretSfv(value),
                "CAT" => InterpretCategory(value),
                "IPV" => InterpretIpv(value),
                "SFTY" => InterpretSafety(value),
                "SRV" when value.Equals("BULK", StringComparison.OrdinalIgnoreCase) => (FindingSeverity.Warning, "bulkmail", "Microsoft heeft het bericht als bulkmail geclassificeerd; de uiteindelijke actie hangt af van het BCL-beleid."),
                _ => (FindingSeverity.Info, "filtermetadata", "Microsoft-filtermetadata aangetroffen; deze waarde is niet zelfstandig een spamverdict.")
            };
            Add(analysis, new SpamIndicator(name, value, null, null, verdict, severity, explanation, header.Name, header.Index, "Microsoft EOP/Defender anti-spam headers"));
        }
    }

    private static void AddNumeric(MailAnalysis analysis, HeaderField header, string name, string rawValue, double? threshold)
    {
        if (!TryNumber(rawValue, out var value)) return;
        var (severity, verdict, explanation, effectiveThreshold) = name switch
        {
            "SCL" => InterpretScl(value),
            "BCL" => InterpretBcl(value),
            "PCL" => InterpretPcl(value),
            "SpamAssassin score" => InterpretGenericScore(value, threshold, "SpamAssassin"),
            _ => (FindingSeverity.Info, "score aangetroffen", "Numerieke filterwaarde aangetroffen; zonder lokale drempel is geen definitief spamverdict mogelijk.", threshold)
        };
        var reference = name is "SCL" or "BCL" or "PCL" ? "Microsoft EOP/Defender anti-spam headers" : "Apache SpamAssassin headerformat";
        Add(analysis, new SpamIndicator(name, value.ToString("0.###", CultureInfo.InvariantCulture), value, effectiveThreshold, verdict, severity, explanation, header.Name, header.Index, reference));
    }

    private static (FindingSeverity, string, string, double?) InterpretScl(double value) => value switch
    {
        -1 => (FindingSeverity.Good, "spamfiltering overgeslagen", "SCL -1 betekent dat spamfiltering is overgeslagen, bijvoorbeeld door een allow-list of mailflowregel. Dit is geen inhoudelijk schoonverklaring.", null),
        0 or 1 => (FindingSeverity.Good, "niet als spam beoordeeld", "Microsoft spamfiltering beoordeelde het bericht niet als spam.", null),
        5 or 6 => (FindingSeverity.Warning, "spam", "Microsoft markeerde het bericht als spam; standaard gaat het naar Ongewenste e-mail, afhankelijk van beleid.", 5),
        >= 7 and <= 9 => (FindingSeverity.Critical, "high confidence spam", "Microsoft markeerde het bericht als high confidence spam; de actie kan Junk of quarantaine zijn, afhankelijk van beleid.", 7),
        >= 2 and <= 4 => (FindingSeverity.Warning, "afwijkende SCL-waarde", "Microsoft spamfiltering stempelt normaal geen SCL 2, 3 of 4; controleer mailflowregels of andere overrides.", null),
        _ => (FindingSeverity.Warning, "ongeldige SCL-waarde", "De SCL-waarde valt buiten het gedocumenteerde bereik -1 tot en met 9.", null)
    };

    private static (FindingSeverity, string, string, double?) InterpretBcl(double value) => value switch
    {
        0 => (FindingSeverity.Good, "geen bulkzender", "Microsoft classificeert de afzender niet als bulkzender.", 7),
        >= 1 and <= 3 => (FindingSeverity.Good, "bulkzender met weinig klachten", "Bulkzender met weinig ontvangersklachten. De tenantdrempel blijft bepalend.", 7),
        >= 4 and <= 6 => (FindingSeverity.Warning, "bulkzender met gemengde klachten", "Bulkzender met een gemengd klachtenniveau. Standaard- en Strict-beleid kunnen lagere drempels gebruiken.", 7),
        >= 7 and <= 9 => (FindingSeverity.Critical, "hoge bulkklachtwaarde", "De waarde bereikt de standaard BCL-drempel en kan als bulk/spam worden behandeld; tenantbeleid kan afwijken.", 7),
        _ => (FindingSeverity.Warning, "ongeldige BCL-waarde", "De BCL-waarde valt buiten het gedocumenteerde bereik 0 tot en met 9.", 7)
    };

    private static (FindingSeverity, string, string, double?) InterpretPcl(double value) => value switch
    {
        >= 1 and <= 3 => (FindingSeverity.Good, "neutraal", "De inhoud is volgens de Exchange PCL-classificatie niet waarschijnlijk phishing.", 4),
        >= 4 and <= 8 => (FindingSeverity.Critical, "waarschijnlijk phishing", "De inhoud is volgens de Exchange PCL-classificatie waarschijnlijk phishing; Outlook kan actieve inhoud blokkeren.", 4),
        _ => (FindingSeverity.Warning, "ongeldige PCL-waarde", "De PCL-waarde valt buiten het gedocumenteerde bereik 1 tot en met 8.", 4)
    };

    private static (FindingSeverity, string, string) InterpretSfv(string value) => value.ToUpperInvariant() switch
    {
        "NSPM" => (FindingSeverity.Good, "niet als spam gedetecteerd", "Microsoft spamfiltering heeft het bericht als nonspam beoordeeld."),
        "SKI" or "SKN" or "SKQ" => (FindingSeverity.Good, "filtering overgeslagen of toegestaan", "Het bericht is vóór filtering toegestaan, heeft filtering overgeslagen of is uit quarantaine vrijgegeven; dit is geen inhoudelijk schoonverklaring."),
        "SPM" => (FindingSeverity.Critical, "spam gedetecteerd", "Microsoft spamfiltering heeft het bericht als spam beoordeeld."),
        "SKS" => (FindingSeverity.Warning, "vooraf als spam gemarkeerd", "Een mailflowregel of andere voorverwerking markeerde het bericht als spam vóór de inhoudsfiltering."),
        "SKB" or "BLK" => (FindingSeverity.Critical, "afzender geblokkeerd", "De afzender of het domein stond op een blokkeerlijst."),
        _ => (FindingSeverity.Info, "onbekend filterverdict", "Een SFV-waarde is aanwezig, maar valt buiten de ingebouwde openbare Microsoft-waardelijst.")
    };

    private static (FindingSeverity, string, string) InterpretCategory(string value) => value.ToUpperInvariant() switch
    {
        "NONE" => (FindingSeverity.Good, "geen dreigingscategorie", "Microsoft heeft geen dreigingscategorie aan het bericht gekoppeld."),
        "BULK" => (FindingSeverity.Warning, "bulkmail", "Microsoft heeft het bericht als bulkmail gecategoriseerd."),
        "SPM" or "HSPM" or "OSPM" => (FindingSeverity.Critical, "spamcategorie", "Microsoft heeft het bericht als spam of high confidence spam gecategoriseerd."),
        "PHSH" or "HPHSH" or "HPHISH" or "INTOS" or "SPOOF" or "UIMP" or "DIMP" or "BIMP" or "GIMP" => (FindingSeverity.Critical, "phishing of impersonatie", "Microsoft heeft een phishing-, spoofing- of impersonatiecategorie toegepast."),
        "MALW" or "AMP" or "FTBP" => (FindingSeverity.Critical, "malwarecategorie", "Microsoft heeft een malware- of bijlagebeveiligingscategorie toegepast."),
        "SAP" => (FindingSeverity.Warning, "Safe Attachments-beleid", "Microsoft Safe Attachments heeft een beleidsverdict toegepast; controleer de bijbehorende Defender-telemetrie."),
        _ => (FindingSeverity.Info, "overige dreigingscategorie", "Microsoft heeft een categorie toegepast die niet zelfstandig als goed of fout wordt geïnterpreteerd.")
    };

    private static (FindingSeverity, string, string) InterpretIpv(string value) => value.ToUpperInvariant() switch
    {
        "CAL" => (FindingSeverity.Good, "IP toegestaan", "Het bron-IP stond op de IP Allow List; filtering kan hierdoor zijn overgeslagen. Dit is geen inhoudelijk schoonverklaring."),
        "NLI" => (FindingSeverity.Info, "IP niet op lijst", "Het bron-IP stond niet op de Microsoft IP-reputatielijsten."),
        _ => (FindingSeverity.Info, "IP-filtermetadata", "Microsoft IP-filtermetadata aangetroffen.")
    };

    private static (FindingSeverity, string, string) InterpretSafety(string value) => value switch
    {
        "9.19" => (FindingSeverity.Critical, "domeinimpersonatie", "Microsoft heeft domeinimpersonatie gedetecteerd."),
        "9.20" => (FindingSeverity.Critical, "gebruikersimpersonatie", "Microsoft heeft gebruikersimpersonatie gedetecteerd."),
        "9.25" => (FindingSeverity.Warning, "eerste contact", "Microsoft heeft een first-contact safety tip toegepast; dit kan op een verdacht eerste contact wijzen."),
        _ => (FindingSeverity.Info, "safety-tipmetadata", "Microsoft safety-tipmetadata aangetroffen.")
    };

    private static void ParseSpamAssassinStatus(MailAnalysis analysis, HeaderField header)
    {
        var match = SpamAssassinStatusRegex().Match(header.Value);
        if (!match.Success) return;
        var yes = match.Groups["verdict"].Value.Equals("Yes", StringComparison.OrdinalIgnoreCase);
        TryNumber(match.Groups["score"].Value, out var score);
        var threshold = TryNumber(match.Groups["required"].Value, out var required) ? required : (double?)null;
        var severity = yes || threshold is not null && score >= threshold ? FindingSeverity.Critical : FindingSeverity.Good;
        Add(analysis, new SpamIndicator("SpamAssassin", $"score={score:0.###}; required={threshold:0.###}", score, threshold, yes ? "spam" : "ham/nonspam", severity,
            yes ? "SpamAssassin heeft het bericht als spam gemarkeerd." : "SpamAssassin heeft het bericht niet als spam gemarkeerd.", header.Name, header.Index, "Apache SpamAssassin X-Spam-Status"));
    }

    private static void AddFlag(MailAnalysis analysis, HeaderField header, string name, string value)
    {
        var yes = value.Trim().Equals("YES", StringComparison.OrdinalIgnoreCase) || value.Trim().Equals("TRUE", StringComparison.OrdinalIgnoreCase);
        Add(analysis, new SpamIndicator(name, value.Trim(), null, null, yes ? "spam" : "niet als spam gemarkeerd", yes ? FindingSeverity.Critical : FindingSeverity.Good,
            yes ? "De externe spamfiltervlag staat aan." : "De externe spamfiltervlag staat niet aan.", header.Name, header.Index, "Gangbare X-Spam-Flag-header"));
    }

    private static void AddSpamLevel(MailAnalysis analysis, HeaderField header)
    {
        var level = header.Value.Count(character => character == '*');
        var severity = level >= 5 ? FindingSeverity.Critical : level >= 3 ? FindingSeverity.Warning : FindingSeverity.Good;
        Add(analysis, new SpamIndicator("SpamAssassin level", level.ToString(CultureInfo.InvariantCulture), level, null, "heuristische spamlevel", severity,
            "Het aantal sterretjes is een installatie-afhankelijke indicatie; zonder lokale drempel is dit geen definitief verdict.", header.Name, header.Index, "Gangbare X-Spam-Level-header"));
    }

    private static void ParseRspamdScore(MailAnalysis analysis, HeaderField header)
    {
        var numbers = NumberRegex().Matches(header.Value).Select(match => match.Value).ToList();
        if (numbers.Count == 0 || !TryNumber(numbers[0], out var score)) return;
        var threshold = numbers.Count > 1 && TryNumber(numbers[1], out var parsedThreshold) ? parsedThreshold : (double?)null;
        var (severity, verdict, explanation, _) = InterpretGenericScore(score, threshold, "Rspamd");
        Add(analysis, new SpamIndicator("Rspamd score", score.ToString("0.###", CultureInfo.InvariantCulture), score, threshold, verdict, severity, explanation, header.Name, header.Index, "Rspamd score-header"));
    }

    private static (FindingSeverity, string, string, double?) InterpretGenericScore(double value, double? threshold, string product)
    {
        if (threshold is null) return (FindingSeverity.Info, "score zonder drempel", $"{product} rapporteert een score, maar de lokale actiedrempel ontbreekt.", null);
        return value >= threshold
            ? (FindingSeverity.Critical, "drempel bereikt", $"De {product}-score bereikt of overschrijdt de gerapporteerde lokale drempel.", threshold)
            : value >= threshold * 0.7
                ? (FindingSeverity.Warning, "dicht bij drempel", $"De {product}-score ligt dicht bij de gerapporteerde lokale drempel.", threshold)
                : (FindingSeverity.Good, "onder drempel", $"De {product}-score ligt onder de gerapporteerde lokale drempel.", threshold);
    }

    private static bool TryNumber(string value, out double number) =>
        double.TryParse(NumberRegex().Match(value).Value, NumberStyles.Float, CultureInfo.InvariantCulture, out number);

    private static void Add(MailAnalysis analysis, SpamIndicator indicator)
    {
        if (!analysis.SpamIndicators.Any(existing => existing.HeaderIndex == indicator.HeaderIndex && existing.Name.Equals(indicator.Name, StringComparison.OrdinalIgnoreCase) && existing.Value == indicator.Value))
            analysis.SpamIndicators.Add(indicator);
    }

    [GeneratedRegex(@"(?i)(?:^|;)\s*(?<name>SCL|BCL|PCL|SFV|CAT|IPV|SFTY|SRV)\s*[:=]\s*(?<value>[^;\s]+)")]
    private static partial Regex MicrosoftIndicatorRegex();
    [GeneratedRegex(@"(?i)^\s*(?<verdict>Yes|No)\b.*?\bscore\s*=\s*(?<score>-?\d+(?:\.\d+)?)(?:.*?\brequired\s*=\s*(?<required>-?\d+(?:\.\d+)?))?")]
    private static partial Regex SpamAssassinStatusRegex();
    [GeneratedRegex(@"-?\d+(?:[.,]\d+)?")]
    private static partial Regex NumberRegex();
}
