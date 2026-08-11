using System.Text;
using System.IO;
using OpenMcdf;

namespace SmtpHeaderAnalyzer.Services;

public static class InputFileService
{
    private const long MaximumFileSize = 50L * 1024L * 1024L;

    public static string ReadHeaders(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var file = new FileInfo(path);
        if (!file.Exists) throw new FileNotFoundException("Het geselecteerde bestand bestaat niet.", path);
        if (file.Length > MaximumFileSize) throw new InvalidDataException("Het bestand is groter dan de limiet van 50 MB.");

        return file.Extension.ToLowerInvariant() switch
        {
            ".eml" => ReadEml(path),
            ".msg" => ReadMsg(path),
            _ => throw new NotSupportedException("Alleen .eml- en .msg-bestanden worden ondersteund.")
        };
    }

    private static string ReadEml(string path)
    {
        using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var builder = new StringBuilder();
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.Length == 0) break;
            builder.AppendLine(line);
        }

        if (builder.Length == 0) throw new InvalidDataException("Geen RFC 5322-headers in het EML-bestand gevonden.");
        return builder.ToString().TrimEnd();
    }

    private static string ReadMsg(string path)
    {
        using var root = RootStorage.OpenRead(path);
        var rawHeaders = ReadStringProperty(root, "007D"); // PR_TRANSPORT_MESSAGE_HEADERS
        if (!string.IsNullOrWhiteSpace(rawHeaders)) return rawHeaders.TrimEnd('\0', '\r', '\n', ' ');

        // Sommige Outlook-items zijn lokaal opgesteld of door software gestript en bevatten
        // geen originele transportheaders. Lees dan alleen veilige, tekstuele MAPI-velden.
        var fallback = new StringBuilder();
        var senderName = ReadStringProperty(root, "0C1A"); // PR_SENDER_NAME
        var senderAddress = FirstNonEmpty(
            ReadStringProperty(root, "5D01"), // PR_SENDER_SMTP_ADDRESS
            ReadStringProperty(root, "0C1F"), // PR_SENDER_EMAIL_ADDRESS
            ReadStringProperty(root, "5D02")); // PR_SENT_REPRESENTING_SMTP_ADDRESS
        Append(fallback, "From", FormatAddress(senderName, senderAddress));
        Append(fallback, "To", ReadStringProperty(root, "0E04")); // PR_DISPLAY_TO
        Append(fallback, "Cc", ReadStringProperty(root, "0E03")); // PR_DISPLAY_CC
        Append(fallback, "Subject", ReadStringProperty(root, "0037")); // PR_SUBJECT
        Append(fallback, "Message-ID", ReadStringProperty(root, "1035")); // PR_INTERNET_MESSAGE_ID
        Append(fallback, "Date", ReadFileTimeProperty(root, "0039")); // PR_CLIENT_SUBMIT_TIME

        if (fallback.Length == 0)
        {
            throw new InvalidDataException("Dit MSG-bestand bevat geen uitleesbare transportheaders.");
        }

        fallback.AppendLine("X-Analyzer-Warning: Originele transportheaders ontbreken in dit MSG-bestand; alleen MAPI-eigenschappen zijn beschikbaar.");
        return fallback.ToString().TrimEnd();
    }

    private static string ReadStringProperty(Storage storage, string propertyId)
    {
        var unicode = ReadStream(storage, $"__substg1.0_{propertyId}001F");
        if (unicode is { Length: > 0 }) return Encoding.Unicode.GetString(unicode).TrimEnd('\0');

        var ansi = ReadStream(storage, $"__substg1.0_{propertyId}001E");
        return ansi is { Length: > 0 } ? Encoding.Latin1.GetString(ansi).TrimEnd('\0') : string.Empty;
    }

    private static string ReadFileTimeProperty(Storage storage, string propertyId)
    {
        var bytes = ReadStream(storage, $"__substg1.0_{propertyId}0040");
        if (bytes is not { Length: >= 8 }) return string.Empty;
        try
        {
            var fileTime = BitConverter.ToInt64(bytes, 0);
            return DateTimeOffset.FromFileTime(fileTime).ToString("r");
        }
        catch (ArgumentOutOfRangeException)
        {
            return string.Empty;
        }
    }

    private static byte[]? ReadStream(Storage storage, string name)
    {
        if (!storage.ContainsEntry(name)) return null;
        using var stream = storage.OpenStream(name);
        if (stream.Length > 5_000_000) throw new InvalidDataException($"MSG-property {name} overschrijdt de veilige limiet van 5 MB.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static string FormatAddress(string name, string address)
    {
        if (string.IsNullOrWhiteSpace(address)) return name;
        return string.IsNullOrWhiteSpace(name) ? address : $"{name} <{address}>";
    }

    private static string FirstNonEmpty(params string[] values) => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static void Append(StringBuilder builder, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) builder.AppendLine($"{name}: {value.Trim()}");
    }
}
