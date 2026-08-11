using System.Text.RegularExpressions;
using SmtpHeaderAnalyzer.Models;

namespace SmtpHeaderAnalyzer.Services;

internal sealed record DeliveryCodeInterpretation(string Code, FindingSeverity Severity, string Title, string Explanation, string Reference);

internal static partial class DeliveryStatusCodeService
{
    private static readonly IReadOnlyDictionary<string, string> EnhancedDetails = new Dictionary<string, string>
    {
        ["0.0"] = "Overige of niet nader gedefinieerde afleverstatus.",
        ["1.0"] = "Overige of niet nader gedefinieerde adresstatus.",
        ["1.1"] = "Bestemmingsmailbox bestaat niet of is ongeldig.",
        ["1.2"] = "Bestemmingssysteem of domein is ongeldig.",
        ["1.3"] = "Syntaxis van het bestemmingsadres is ongeldig.",
        ["1.4"] = "Bestemmingsmailbox is ambigu.",
        ["1.5"] = "Bestemmingsadres is geldig.",
        ["1.6"] = "Bestemmingsmailbox is verhuisd en heeft geen bruikbaar doorstuuradres.",
        ["1.7"] = "Syntaxis van het afzenderadres is ongeldig.",
        ["1.8"] = "Afzendersysteem of -domein is ongeldig.",
        ["1.9"] = "Bericht is doorgestuurd naar een mailsysteem dat geen verdere DSN-informatie kan leveren.",
        ["1.10"] = "Het adresdomein publiceert een null MX en accepteert dus geen e-mail.",
        ["2.0"] = "Overige of niet nader gedefinieerde mailboxstatus.",
        ["2.1"] = "Mailbox is uitgeschakeld en accepteert geen berichten.",
        ["2.2"] = "Mailbox is vol.",
        ["2.3"] = "Bericht overschrijdt een administratieve mailboxlimiet.",
        ["2.4"] = "Probleem bij het uitbreiden van een mailinglijst.",
        ["3.0"] = "Overige of niet nader gedefinieerde mailsysteemstatus.",
        ["3.1"] = "Mailsysteem heeft onvoldoende opslagruimte.",
        ["3.2"] = "Mailsysteem accepteert momenteel geen netwerkberichten.",
        ["3.3"] = "Mailsysteem ondersteunt de benodigde berichtfuncties niet.",
        ["3.4"] = "Bericht is te groot voor het bestemmingssysteem.",
        ["3.5"] = "Mailsysteem is onjuist geconfigureerd.",
        ["3.6"] = "Bericht is geaccepteerd, maar de gevraagde berichtprioriteit is gewijzigd.",
        ["4.0"] = "Overige of niet nader gedefinieerde netwerk- of routeringsstatus.",
        ["4.1"] = "Bestemmingshost antwoordt niet.",
        ["4.2"] = "Slechte of verbroken netwerkverbinding.",
        ["4.3"] = "Routeringsserver of directoryservice faalt.",
        ["4.4"] = "Geen route naar het bestemmingssysteem.",
        ["4.5"] = "Netwerkcongestie.",
        ["4.6"] = "Routeringslus gedetecteerd.",
        ["4.7"] = "Maximale bezorgtijd verstreken.",
        ["5.0"] = "Overige of niet nader gedefinieerde protocolstatus.",
        ["5.1"] = "Ongeldige of niet-herkende SMTP-opdracht.",
        ["5.2"] = "Syntaxisfout in SMTP-opdracht.",
        ["5.3"] = "Te veel ontvangers.",
        ["5.4"] = "Ongeldige argumenten voor een SMTP-opdracht.",
        ["5.5"] = "Verkeerde protocolversie.",
        ["5.6"] = "AUTH-uitwisselingsregel overschrijdt de toegestane bufferlengte.",
        ["6.0"] = "Overige of niet nader gedefinieerde inhouds- of mediastatus.",
        ["6.1"] = "Media- of inhoudstype wordt niet ondersteund.",
        ["6.2"] = "Conversie is vereist maar verboden.",
        ["6.3"] = "Conversie is vereist maar niet mogelijk.",
        ["6.4"] = "Conversie is uitgevoerd met gegevensverlies.",
        ["6.5"] = "Conversie is mislukt.",
        ["6.6"] = "Berichtinhoud kon niet van een extern systeem worden opgehaald.",
        ["6.7"] = "Niet-ASCII-adres is voor deze afzender of ontvanger niet toegestaan.",
        ["6.8"] = "UTF-8-antwoord is nodig, maar wordt door de SMTP-client niet toegestaan.",
        ["6.9"] = "Bericht met UTF-8-headers kan niet aan één of meer ontvangers worden overgedragen.",
        ["6.10"] = "Verouderde duplicaatcode van X.6.8: vereist UTF-8-antwoord wordt niet toegestaan.",
        ["7.0"] = "Overige of niet nader gedefinieerde beveiligings- of beleidsstatus.",
        ["7.1"] = "Aflevering niet geautoriseerd; bericht geweigerd door beveiligingsbeleid.",
        ["7.2"] = "Uitbreiding van mailinglijst niet toegestaan.",
        ["7.3"] = "Beveiligingsconversie vereist maar niet mogelijk.",
        ["7.4"] = "Benodigde beveiligingsfuncties worden niet ondersteund.",
        ["7.5"] = "Cryptografische verwerking is mislukt.",
        ["7.6"] = "Cryptografisch algoritme wordt niet ondersteund.",
        ["7.7"] = "Berichtintegriteit kon niet worden gevalideerd.",
        ["7.8"] = "SMTP-authenticatiegegevens zijn ongeldig of onvoldoende.",
        ["7.9"] = "Gekozen SMTP-authenticatiemechanisme is te zwak voor het serverbeleid.",
        ["7.10"] = "Een versleutelde verbinding is vereist vóór authenticatie.",
        ["7.11"] = "Het gekozen authenticatiemechanisme mag alleen over een versleutelde verbinding worden gebruikt.",
        ["7.12"] = "De gebruiker moet overstappen naar het geselecteerde authenticatiemechanisme.",
        ["7.13"] = "Gebruikersaccount is uitgeschakeld.",
        ["7.14"] = "Een vereiste vertrouwensrelatie met een derde server ontbreekt.",
        ["7.15"] = "Aangevraagde berichtprioriteit is lager dan de server toestaat.",
        ["7.16"] = "Bericht is te groot voor de opgegeven prioriteit.",
        ["7.17"] = "Mailboxeigenaar is gewijzigd sinds de opgegeven RRVS-timestamp.",
        ["7.18"] = "Domeineigenaar is gewijzigd sinds de opgegeven RRVS-timestamp.",
        ["7.19"] = "RRVS-controle kan niet worden uitgevoerd omdat de vereiste timestamp ontbreekt.",
        ["7.20"] = "Geen geldige DKIM-handtekening gevonden.",
        ["7.21"] = "Geen acceptabele DKIM-handtekening gevonden.",
        ["7.22"] = "Geen geldige DKIM-handtekening die met de auteur uitlijnt.",
        ["7.23"] = "SPF-validatie is mislukt.",
        ["7.24"] = "Fout tijdens SPF-validatie.",
        ["7.25"] = "Reverse-DNS-validatie is mislukt.",
        ["7.26"] = "Meerdere authenticatiecontroles zijn mislukt.",
        ["7.27"] = "Afzenderdomein publiceert een null MX.",
        ["7.28"] = "Mogelijke mailflood gedetecteerd.",
        ["7.29"] = "ARC-validatie is mislukt.",
        ["7.30"] = "REQUIRETLS is vereist maar wordt verderop niet ondersteund."
    };

    private static readonly IReadOnlyDictionary<string, string> SmtpReplies = new Dictionary<string, string>
    {
        ["211"] = "Systeemstatus of helpantwoord.", ["214"] = "Helpinformatie.", ["220"] = "SMTP-service gereed.", ["221"] = "SMTP-service sluit de verbinding.",
        ["250"] = "Opdracht voltooid.", ["251"] = "Ontvanger is niet lokaal; bericht wordt doorgestuurd.", ["252"] = "Ontvanger kan niet worden geverifieerd, maar aflevering wordt geprobeerd.", ["354"] = "Start invoer van berichtinhoud.",
        ["421"] = "Service niet beschikbaar; tijdelijke sluiting.", ["450"] = "Mailbox tijdelijk niet beschikbaar.", ["451"] = "Lokale verwerkingsfout; probeer later opnieuw.", ["452"] = "Onvoldoende systeemopslag.", ["455"] = "Server kan parameters tijdelijk niet verwerken.",
        ["500"] = "Syntaxisfout of onbekende opdracht.", ["501"] = "Syntaxisfout in parameters.", ["502"] = "Opdracht niet geïmplementeerd.", ["503"] = "Ongeldige opdrachtvolgorde.", ["504"] = "Parameter niet geïmplementeerd.",
        ["550"] = "Mailbox of gevraagde actie niet beschikbaar; vaak beleid, adres of rechten.", ["551"] = "Ontvanger is niet lokaal; alternatief adres opgegeven.", ["552"] = "Opslag- of berichtgroottelimiet overschreden.", ["553"] = "Mailboxnaam of adres niet toegestaan.", ["554"] = "Transactie mislukt of bericht geweigerd.", ["555"] = "MAIL FROM/RCPT TO-parameters niet herkend of geïmplementeerd."
    };

    public static IReadOnlyList<DeliveryCodeInterpretation> Parse(string value)
    {
        var results = new List<DeliveryCodeInterpretation>();
        foreach (Match match in EnhancedCodeRegex().Matches(value))
        {
            var code = match.Value;
            var parts = code.Split('.');
            var severity = parts[0] switch { "2" => FindingSeverity.Good, "4" => FindingSeverity.Warning, "5" => FindingSeverity.Critical, _ => FindingSeverity.Info };
            var classText = parts[0] switch { "2" => "succes", "4" => "tijdelijke fout", "5" => "permanente fout", _ => "onbekende klasse" };
            var detailKey = $"{parts[1]}.{parts[2]}";
            var explanation = EnhancedDetails.TryGetValue(detailKey, out var detail)
                ? $"{classText}: {detail}"
                : $"{classText}: geregistreerde detailcode {detailKey}; de aangeleverde diagnostische tekst blijft leidend.";
            results.Add(new DeliveryCodeInterpretation(code, severity, $"Enhanced status {code}", explanation, "RFC 3463 / RFC 5248 / IANA SMTP Enhanced Status Codes"));
        }

        foreach (Match match in SmtpReplyRegex().Matches(value))
        {
            var code = match.Value;
            if (results.Any(item => item.Code == code)) continue;
            var severity = code[0] switch { '2' or '3' => FindingSeverity.Good, '4' => FindingSeverity.Warning, '5' => FindingSeverity.Critical, _ => FindingSeverity.Info };
            var explanation = SmtpReplies.TryGetValue(code, out var detail) ? detail : "SMTP-replycode aangetroffen; diagnostische tekst blijft leidend.";
            results.Add(new DeliveryCodeInterpretation(code, severity, $"SMTP-reply {code}", explanation, "RFC 5321 section 4.2"));
        }

        return results.DistinctBy(item => item.Code).ToList();
    }

    [GeneratedRegex(@"(?<!\d)(?:2|4|5)\.\d{1,3}\.\d{1,3}(?!\d)")]
    private static partial Regex EnhancedCodeRegex();
    [GeneratedRegex(@"(?<![\d.])(?:2|3|4|5)\d{2}(?![\d.])")]
    private static partial Regex SmtpReplyRegex();
}
