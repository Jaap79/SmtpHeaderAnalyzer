using SmtpHeaderAnalyzer.Models;
using SmtpHeaderAnalyzer.Services;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.IO;
using System.Reflection;
using System.Windows.Controls;
using System.Text;
using OpenMcdf;

var tests = new (string Name, Action Run)[]
{
    ("Unfolding en encoded subject", TestHeaderDecoding),
    ("Route chronologisch en TLS", TestRouteAndTls),
    ("SPF DKIM DMARC extractie", TestAuthentication),
    ("Identity alignment bevindingen", TestIdentityMismatch),
    ("DSN foutafhandeling", TestDeliveryFailure),
    ("Dubbele From detectie", TestDuplicateFrom),
    ("EML leest alleen headers", TestEmlInput),
    ("MSG leest transportheaders zonder RTF", TestMsgInput),
    ("Volledige CSV export", TestCsvExport),
    ("Kali Timeline CSV met UTC vooraan", TestTimelineCsvExport),
    ("Versievergelijking updatecontrole", TestVersionComparison),
    ("WPF dark/light render", TestUiRender)
};

var failures = new List<string>();
foreach (var test in tests)
{
    try
    {
        test.Run();
        Console.WriteLine($"PASS  {test.Name}");
    }
    catch (Exception exception)
    {
        failures.Add($"{test.Name}: {exception.Message}");
        Console.WriteLine($"FAIL  {test.Name}: {exception.Message}");
    }
}

Console.WriteLine($"\n{tests.Length - failures.Count}/{tests.Length} tests geslaagd.");
if (failures.Count > 0) Environment.Exit(1);

static MailAnalysis Analyze(string additional = "")
{
    return new HeaderAnalyzer().Analyze(BuildHeaders(additional));
}

static string BuildHeaders(string additional = "") => """
        Received: from mx.receiver.example (mx.receiver.example [203.0.113.20]) by final.example with ESMTPS id BBB for <bob@final.example>; Tue, 11 Aug 2026 10:02:10 +0200
        Received: from sender.example (sender.example [198.51.100.44]) by mx.receiver.example with ESMTPSA (TLS1_3 cipher=TLS_AES_256_GCM_SHA384) id AAA; Tue, 11 Aug 2026 10:01:00 +0200
        Authentication-Results: mx.receiver.example; spf=pass smtp.mailfrom=mailer.example; dkim=pass header.d=example.com header.s=s1; dmarc=pass header.from=example.com
        Received-SPF: pass (mx.receiver.example: domain of bounce@mailer.example designates 198.51.100.44 as permitted sender) envelope-from=bounce@mailer.example
        DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1; h=from:to:subject:date; bh=abc; b=def
        From: Alice <alice@example.com>
        Return-Path: <bounce@mailer.example>
        To: Bob <bob@final.example>
        Subject: =?UTF-8?B?VGVzdCDinJM=?=
        Date: Tue, 11 Aug 2026 10:00:50 +0200
        Message-ID: <abc@example.com>
        """ + additional;

static void TestHeaderDecoding()
{
    var analysis = Analyze();
    Equal("Test ✓", analysis.Subject);
    Equal("alice@example.com", analysis.Identities.First(item => item.Role == "From").Address);
}

static void TestRouteAndTls()
{
    var analysis = Analyze();
    Equal(2, analysis.Route.Count);
    Equal("198.51.100.44", analysis.Route[0].IpAddress);
    Equal("203.0.113.20", analysis.Route[1].IpAddress);
    True(analysis.Route[1].Delay is { TotalSeconds: 70 });
    True(analysis.Transport[0].TlsVersion.Contains("1.3"));
    True(analysis.Transport[0].Cipher.Contains("TLS_AES_256_GCM_SHA384"));
}

static void TestAuthentication()
{
    var analysis = Analyze();
    True(analysis.Authentication.Any(item => item.Mechanism == "SPF" && item.Result == "pass"));
    True(analysis.Authentication.Any(item => item.Mechanism == "DKIM" && item.Domain == "example.com"));
    True(analysis.Authentication.Any(item => item.Mechanism == "DMARC" && item.Result == "pass"));
}

static void TestIdentityMismatch()
{
    var analysis = Analyze("\nReply-To: help@lookalike.test");
    True(analysis.Findings.Any(item => item.Title.Contains("Reply-To")));
    True(analysis.Findings.Any(item => item.Title.Contains("Return-Path")));
}

static void TestDeliveryFailure()
{
    var analysis = Analyze("\nDiagnostic-Code: smtp; 550 5.1.1 User unknown\nAction: failed\nFinal-Recipient: rfc822; nobody@example.net");
    True(analysis.Findings.Count(item => item.Title.StartsWith("Afleverfout")) == 2);
}

static void TestDuplicateFrom()
{
    var analysis = Analyze("\nFrom: Mallory <mallory@evil.test>");
    True(analysis.Findings.Any(item => item.Severity == FindingSeverity.Critical && item.Title == "Meerdere From-headers"));
}

static void TestEmlInput()
{
    var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
    var headers = InputFileService.ReadHeaders(Path.Combine(root, "samples", "representative.eml"));
    True(headers.Contains("Authentication-Results:"));
    True(!headers.Contains("Deze body"));
    Equal(2, new HeaderAnalyzer().Analyze(headers).Route.Count);
}

static void TestMsgInput()
{
    var path = Path.Combine(Path.GetTempPath(), $"smtp-header-analyzer-{Guid.NewGuid():N}.msg");
    try
    {
        using (var root = RootStorage.Create(path))
        using (var stream = root.CreateStream("__substg1.0_007D001F"))
        {
            var bytes = Encoding.Unicode.GetBytes(BuildHeaders() + "\0");
            stream.Write(bytes, 0, bytes.Length);
        }

        var headers = InputFileService.ReadHeaders(path);
        True(headers.Contains("Authentication-Results:"));
        Equal(2, new HeaderAnalyzer().Analyze(headers).Route.Count);
    }
    finally
    {
        if (File.Exists(path)) File.Delete(path);
    }
}

static void TestCsvExport()
{
    var csv = ReportService.ToCsv(Analyze());
    True(csv.StartsWith("record_type,sequence,timestamp_utc,category", StringComparison.Ordinal));
    True(csv.Contains("route_hop,1,2026-08-11T08:01:00.000Z"));
    True(csv.Contains("authentication"));
    True(csv.Contains("finding"));
    File.WriteAllText(Path.Combine(QaOutputDirectory(), "smtp-header-analysis.csv"), csv, new UTF8Encoding(false));
}

static void TestTimelineCsvExport()
{
    var csv = ReportService.ToTimelineCsv(Analyze());
    var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
    Equal("timestamp,event,source,category,actor,tags,evidence,files,parent_id,relation,notes,raw_line,id,created_at,updated_at", lines[0].TrimEnd('\r'));
    True(lines[1].StartsWith("2026-08-11T08:01:00.000Z,", StringComparison.Ordinal));
    True(lines[2].StartsWith("2026-08-11T08:02:10.000Z,", StringComparison.Ordinal));
    True(lines[1].Contains("smtp-hop-001"));
    True(lines[2].Contains("smtp-hop-001,relayed_to"));
    File.WriteAllText(Path.Combine(QaOutputDirectory(), "smtp-route-timeline-utc.csv"), csv, new UTF8Encoding(false));
}

static void TestVersionComparison()
{
    True(UpdateService.IsNewerVersion("0.3.0", "v0.3.1"));
    True(UpdateService.IsNewerVersion("0.3.0", "1.0.0"));
    True(!UpdateService.IsNewerVersion("0.3.0", "v0.3.0"));
    True(!UpdateService.IsNewerVersion("0.3.0", "v0.2.9"));
    True(!UpdateService.IsNewerVersion("onbekend", "v1.0.0"));
}

static string QaOutputDirectory()
{
    var output = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "artifacts", "qa"));
    Directory.CreateDirectory(output);
    return output;
}

static void TestUiRender()
{
    Exception? failure = null;
    var thread = new Thread(() =>
    {
        try
        {
            var app = new SmtpHeaderAnalyzer.App();
            app.InitializeComponent();
            ThemeService.Apply(true);
            var window = new SmtpHeaderAnalyzer.MainWindow { Width = 1400, Height = 820 };
            var identityGrid = (DataGrid)window.FindName("IdentityGrid");
            Equal(4, identityGrid.Columns.Count);
            Equal("E-mailadres", identityGrid.Columns.Single(column => column.DisplayIndex == 2).Header?.ToString());
            Equal("Domein", identityGrid.Columns.Single(column => column.DisplayIndex == 3).Header?.ToString());
            var input = (TextBox)window.FindName("HeaderInput");
            input.Text = BuildHeaders("\nReply-To: help@lookalike.test\nX-MS-Exchange-Organization-SCL: 5");
            typeof(SmtpHeaderAnalyzer.MainWindow).GetMethod("Analyze", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(window, [input.Text, "QA-voorbeeld.eml"]);
            var output = QaOutputDirectory();
            Render(window, Path.Combine(output, "smtp-header-analyzer-dark.png"));
            var darkAbout = new SmtpHeaderAnalyzer.AboutWindow();
            Render(darkAbout, Path.Combine(output, "smtp-header-analyzer-about-dark.png"));
            ThemeService.Apply(false);
            ((Button)window.FindName("ThemeButton")).Content = "Donker thema";
            Render(window, Path.Combine(output, "smtp-header-analyzer-light.png"));
            var lightAbout = new SmtpHeaderAnalyzer.AboutWindow();
            Render(lightAbout, Path.Combine(output, "smtp-header-analyzer-about-light.png"));
            app.Shutdown();
        }
        catch (Exception exception)
        {
            failure = exception;
        }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
    if (failure is not null) throw new InvalidOperationException("UI-rendering mislukte.", failure);
}

static void Render(Window window, string path)
{
    var root = (FrameworkElement)window.Content;
    root.Measure(new Size(window.Width, window.Height));
    root.Arrange(new Rect(0, 0, window.Width, window.Height));
    root.UpdateLayout();
    var bitmap = new RenderTargetBitmap((int)window.Width, (int)window.Height, 96, 96, PixelFormats.Pbgra32);
    bitmap.Render(root);
    var encoder = new PngBitmapEncoder();
    encoder.Frames.Add(BitmapFrame.Create(bitmap));
    using var stream = File.Create(path);
    encoder.Save(stream);
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException($"Verwacht {expected}, kreeg {actual}.");
}

static void True(bool value)
{
    if (!value) throw new InvalidOperationException("Voorwaarde is niet waar.");
}
