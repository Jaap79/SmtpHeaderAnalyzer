using System.Globalization;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using SmtpHeaderAnalyzer.Models;

namespace SmtpHeaderAnalyzer.Services;

public static class PdfReportService
{
    private static readonly XColor Ink = XColor.FromArgb(23, 32, 42);
    private static readonly XColor Muted = XColor.FromArgb(91, 101, 114);
    private static readonly XColor Surface = XColor.FromArgb(243, 245, 248);
    private static readonly XColor Border = XColor.FromArgb(201, 208, 216);
    private static readonly XColor Accent = XColor.FromArgb(255, 152, 46);
    private static readonly XColor Good = XColor.FromArgb(24, 135, 99);
    private static readonly XColor Warning = XColor.FromArgb(177, 102, 0);
    private static readonly XColor Danger = XColor.FromArgb(191, 47, 61);

    public static void Write(MailAnalysis analysis, string path)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Een uitvoerpad is vereist.", nameof(path));

        using var document = new PdfDocument();
        document.Info.Title = $"SMTP Header Analyse — {analysis.Subject}";
        document.Info.Author = "SMTP Header Analyzer";
        document.Info.Subject = "Offline forensische analyse van SMTP-headers";
        document.Info.Keywords = "SMTP, headers, SPF, DKIM, DMARC, SCL, forensics";
        document.Info.Creator = "SMTP Header Analyzer v0.99";

        using (var report = new ReportCanvas(document, landscape: false))
        {
            report.Title("SMTP HEADER ANALYSE", "Offline forensisch rapport");
            report.KeyValue("Gegenereerd (UTC)", DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture));
            report.KeyValue("Bron", analysis.SourceLabel);
            report.KeyValue("Onderwerp", analysis.Subject);
            report.KeyValue("Message-ID", analysis.MessageId);
            report.KeyValue("Vermoedelijke oorsprong", analysis.ClaimedOrigin);
            report.KeyValue("Betrouwbaarheid", analysis.OriginConfidence);
            report.Paragraph(analysis.OriginExplanation, muted: true);

            report.Section("AFZENDERIDENTITEITEN");
            if (analysis.Identities.Count == 0) report.Paragraph("Geen adresseerbare identiteiten aangetroffen.", muted: true);
            foreach (var item in analysis.Identities)
                report.Row(item.Role, $"{item.Address}  |  domein={item.Domain}{(string.IsNullOrWhiteSpace(item.DisplayName) ? string.Empty : $"  |  naam={item.DisplayName}")}", item.RelatedSeverity);

            report.Section("ROUTE — OUDSTE NAAR NIEUWSTE");
            if (analysis.Route.Count == 0) report.Paragraph("Geen Received-route aangetroffen.", muted: true);
            foreach (var hop in analysis.Route)
                report.Row($"Hop {hop.Number} · {hop.TimestampDisplay}", $"{hop.From} → {hop.By}  |  {hop.With}  |  IP={hop.IpAddress}  |  delta={hop.DelayDisplay}", hop.RelatedSeverity);

            report.Section("AUTHENTICATIE");
            if (analysis.Authentication.Count == 0) report.Paragraph("Geen authenticatieresultaten aangetroffen.", muted: true);
            foreach (var item in analysis.Authentication)
                report.Row($"{item.Mechanism}: {item.Result}", $"domein={item.Domain}; identiteit={item.Identity}; selector={item.Selector}; {item.Details}", item.RelatedSeverity);

            report.Section("TRANSPORTBEVEILIGING");
            if (analysis.Transport.Count == 0) report.Paragraph("Geen routehops om transportbeveiliging uit af te leiden.", muted: true);
            foreach (var item in analysis.Transport)
                report.Row($"Hop {item.Hop}: {item.EncryptionStatus}", $"{item.From} → {item.By}; SMTP={item.Protocol}; TLS={item.TlsVersion}; cipher={item.Cipher}", item.RelatedSeverity);

            report.Section("SPAM- EN DREIGINGSINDICATOREN");
            if (analysis.SpamIndicators.Count == 0) report.Paragraph("Geen ondersteunde score- of verdictheaders aangetroffen.", muted: true);
            foreach (var item in analysis.SpamIndicators)
                report.Row($"{item.Name} = {item.Value} · {item.Verdict}", $"{item.Explanation}{(item.Threshold is null ? string.Empty : $" Drempel={item.Threshold:0.###}.")} Referentie: {item.Reference}", item.Severity);

            report.Section("BEVINDINGEN");
            foreach (var finding in analysis.Findings)
            {
                var details = $"{finding.Explanation}\nBewijs: {finding.Evidence}";
                if (!string.IsNullOrWhiteSpace(finding.StandardsReference)) details += $"\nReferentie: {finding.StandardsReference}";
                report.Row($"[{finding.SeverityLabel}] {finding.Title}", details, finding.Severity);
            }

            report.Section("ONGELDIGE HEADERREGELS");
            if (analysis.InvalidHeaderLines.Count == 0) report.Paragraph("Geen.", muted: true);
            foreach (var line in analysis.InvalidHeaderLines)
                report.Row($"Regel {line.LineNumber}: {line.Reason}", line.Raw, FindingSeverity.Warning, monospace: true);

            report.Section("METHODISCHE BEPERKING");
            report.Paragraph("De analyse gebruikt uitsluitend aangeleverde headers. Er vindt geen DNS-hercontrole plaats en headers onder de vertrouwde relaygrens kunnen zijn vervalst. Een groene markering is dus geen zelfstandig bewijs van legitimiteit.", muted: true);
        }

        using (var headers = new ReportCanvas(document, landscape: true, appendix: true))
        {
            headers.Title("ALLE HEADERS", "Liggende bronbijlage — waarden worden afgebroken voor leesbaarheid");
            foreach (var header in analysis.Headers)
                headers.Row($"{header.Index}. {header.Name}", header.Value, header.RelatedSeverity, monospace: true);
        }

        document.Save(path);
    }

    private sealed class ReportCanvas : IDisposable
    {
        private readonly PdfDocument _document;
        private readonly bool _landscape;
        private readonly bool _appendix;
        private readonly XFont _titleFont = new("Segoe UI", 19, XFontStyleEx.Bold, XPdfFontOptions.UnicodeDefault);
        private readonly XFont _subtitleFont = new("Segoe UI", 9, XFontStyleEx.Regular, XPdfFontOptions.UnicodeDefault);
        private readonly XFont _sectionFont = new("Segoe UI", 9.5, XFontStyleEx.Bold, XPdfFontOptions.UnicodeDefault);
        private readonly XFont _labelFont = new("Segoe UI", 9, XFontStyleEx.Bold, XPdfFontOptions.UnicodeDefault);
        private readonly XFont _bodyFont = new("Segoe UI Symbol", 8.5, XFontStyleEx.Regular, XPdfFontOptions.UnicodeDefault);
        private readonly XFont _monoFont = new("Segoe UI Symbol", 7.5, XFontStyleEx.Regular, XPdfFontOptions.UnicodeDefault);
        private PdfPage? _page;
        private XGraphics? _graphics;
        private double _y;
        private const double Margin = 38;
        private const double HeaderHeight = 42;
        private const double FooterHeight = 28;

        public ReportCanvas(PdfDocument document, bool landscape, bool appendix = false)
        {
            _document = document;
            _landscape = landscape;
            _appendix = appendix;
            NewPage();
        }

        private double ContentWidth => _page!.Width.Point - Margin * 2;
        private double Bottom => _page!.Height.Point - FooterHeight - Margin / 2;

        public void Title(string title, string subtitle)
        {
            Ensure(58);
            _graphics!.DrawString(title, _titleFont, new XSolidBrush(Ink), new XRect(Margin, _y, ContentWidth, 25), XStringFormats.TopLeft);
            _y += 27;
            _graphics.DrawString(subtitle, _subtitleFont, new XSolidBrush(Muted), new XRect(Margin, _y, ContentWidth, 16), XStringFormats.TopLeft);
            _y += 27;
        }

        public void Section(string title)
        {
            Ensure(31);
            _y += 8;
            _graphics!.DrawRectangle(new XSolidBrush(Accent), Margin, _y, 4, 17);
            _graphics.DrawString(title, _sectionFont, new XSolidBrush(Ink), new XRect(Margin + 10, _y + 1, ContentWidth - 10, 16), XStringFormats.TopLeft);
            _y += 23;
        }

        public void KeyValue(string label, string value) => Row(label, value, null);

        public void Paragraph(string text, bool muted = false)
        {
            var lines = Wrap(text, _bodyFont, ContentWidth - 16);
            var height = Math.Max(24, lines.Count * 12 + 12);
            Ensure(height + 4);
            _graphics!.DrawRoundedRectangle(new XPen(Border, 0.7), new XSolidBrush(Surface), Margin, _y, ContentWidth, height, 3, 3);
            DrawLines(lines, _bodyFont, muted ? Muted : Ink, Margin + 8, _y + 6, ContentWidth - 16, 12);
            _y += height + 5;
        }

        public void Row(string label, string value, FindingSeverity? severity, bool monospace = false)
        {
            var valueFont = monospace ? _monoFont : _bodyFont;
            var labelWidth = _landscape ? 180d : 145d;
            var valueWidth = ContentWidth - labelWidth - 28;
            var labelLines = Wrap(label, _labelFont, labelWidth - 12);
            var valueLines = Wrap(value, valueFont, valueWidth - 10);
            var lineHeight = monospace ? 10.5 : 12d;
            var height = Math.Max(29, Math.Max(labelLines.Count * 12, valueLines.Count * lineHeight) + 12);
            Ensure(height + 4);

            var stripe = severity switch { FindingSeverity.Good => Good, FindingSeverity.Warning => Warning, FindingSeverity.Critical => Danger, _ => Accent };
            _graphics!.DrawRoundedRectangle(new XPen(Border, 0.7), new XSolidBrush(XColors.White), Margin, _y, ContentWidth, height, 3, 3);
            _graphics!.DrawRectangle(new XSolidBrush(stripe), Margin, _y, 4, height);
            DrawLines(labelLines, _labelFont, Ink, Margin + 12, _y + 7, labelWidth - 12, 12);
            DrawLines(valueLines, valueFont, Ink, Margin + labelWidth + 14, _y + 7, valueWidth - 10, lineHeight);
            _y += height + 4;
        }

        private void Ensure(double required)
        {
            if (_y + required <= Bottom) return;
            FinishPage();
            NewPage();
        }

        private void NewPage()
        {
            _page = _document.AddPage();
            if (_landscape)
            {
                _page.Width = XUnit.FromMillimeter(297);
                _page.Height = XUnit.FromMillimeter(210);
            }
            else
            {
                _page.Width = XUnit.FromMillimeter(210);
                _page.Height = XUnit.FromMillimeter(297);
            }
            _graphics = XGraphics.FromPdfPage(_page);
            _graphics.DrawRectangle(XBrushes.White, 0, 0, _page.Width.Point, _page.Height.Point);
            _graphics.DrawRectangle(new XSolidBrush(Ink), 0, 0, _page.Width.Point, HeaderHeight);
            _graphics.DrawRectangle(new XSolidBrush(Accent), 0, HeaderHeight - 4, _page.Width.Point, 4);
            _graphics.DrawString("SMTP HEADER ANALYZER", _sectionFont, XBrushes.White, new XRect(Margin, 14, ContentWidth, 16), XStringFormats.TopLeft);
            _graphics.DrawString(_appendix ? "BRONBIJLAGE" : "OFFLINE MAILANALYSE", _subtitleFont, new XSolidBrush(XColor.FromArgb(210, 215, 222)), new XRect(Margin, 15, ContentWidth, 15), XStringFormats.TopRight);
            _y = HeaderHeight + 22;
        }

        private void FinishPage()
        {
            if (_page is null || _graphics is null) return;
            var pageNumber = _document.PageCount;
            var footerY = _page.Height.Point - FooterHeight;
            _graphics.DrawLine(new XPen(Border, 0.7), Margin, footerY, _page.Width.Point - Margin, footerY);
            _graphics.DrawString("Lokaal gegenereerd — geen headers of analyseresultaten verzonden", _subtitleFont, new XSolidBrush(Muted), new XRect(Margin, footerY + 8, ContentWidth, 13), XStringFormats.TopLeft);
            _graphics.DrawString($"Pagina {pageNumber}", _subtitleFont, new XSolidBrush(Muted), new XRect(Margin, footerY + 8, ContentWidth, 13), XStringFormats.TopRight);
            _graphics.Dispose();
            _graphics = null;
        }

        private List<string> Wrap(string? text, XFont font, double width)
        {
            var result = new List<string>();
            foreach (var sourceLine in (text ?? string.Empty).Replace("\r", string.Empty).Split('\n'))
            {
                var words = sourceLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (words.Length == 0) { result.Add(string.Empty); continue; }
                var current = string.Empty;
                foreach (var word in words)
                {
                    var candidate = string.IsNullOrEmpty(current) ? word : current + " " + word;
                    if (_graphics!.MeasureString(candidate, font).Width <= width) { current = candidate; continue; }
                    if (!string.IsNullOrEmpty(current)) result.Add(current);
                    current = string.Empty;
                    var fragment = string.Empty;
                    foreach (var character in word)
                    {
                        var next = fragment + character;
                        if (_graphics.MeasureString(next, font).Width <= width) fragment = next;
                        else { if (fragment.Length > 0) result.Add(fragment); fragment = character.ToString(); }
                    }
                    current = fragment;
                }
                if (!string.IsNullOrEmpty(current)) result.Add(current);
            }
            return result.Count == 0 ? [string.Empty] : result;
        }

        private void DrawLines(IEnumerable<string> lines, XFont font, XColor color, double x, double y, double width, double lineHeight)
        {
            foreach (var line in lines)
            {
                _graphics!.DrawString(line, font, new XSolidBrush(color), new XRect(x, y, width, lineHeight + 2), XStringFormats.TopLeft);
                y += lineHeight;
            }
        }

        public void Dispose() => FinishPage();
    }
}
