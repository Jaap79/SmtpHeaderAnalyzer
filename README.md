# SMTP Header Analyzer

Windows-tool voor lokale analyse van ruwe SMTP-headers, `.eml`- en Outlook `.msg`-bestanden. De applicatie doet geen DNS-lookups, opent geen mailinhoud en extraheert geen bijlagen.

![Windows](https://img.shields.io/badge/Windows-x64-357EC7) ![.NET](https://img.shields.io/badge/.NET-10-512BD4) ![License](https://img.shields.io/badge/license-MIT-32C48D)

## Analyse

- route uit alle `Received`-regels, chronologisch van oudste naar nieuwste hop;
- timestamps, tussenliggende vertragingen, hostnamen, IP-adressen, protocollen en relay-ID's;
- `From`, `Sender`, `Reply-To`, `Return-Path`, ontvangers en envelope-adressen;
- SPF, DKIM, DMARC, ARC, CompAuth en `Received-SPF` uit aangeleverde resultaten;
- TLS-versie, cipher en SMTP-transporttype voor zover in headers vastgelegd;
- afwijkende domeinen, dubbele kernheaders, tijdlijnproblemen, ontbrekende controles en DSN/foutafhandeling;
- JSON-, tekst- en genormaliseerde CSV-export;
- Kali Timeline Tool-CSV met één event per hop, `timestamp` als eerste kolom en tijden genormaliseerd naar UTC;
- donkere en lichte Windows-interface.

## Privacy en netwerkgebruik

Mailanalyse vindt volledig lokaal plaats. Alleen bij een handmatige klik op **Controleer voor update** wordt de publieke GitHub Releases-API benaderd. Headers, bestandsnamen en analyseresultaten worden nooit meegestuurd. Er is geen telemetrie en er worden geen automatische updatechecks uitgevoerd.

## Installatie

Download `SmtpHeaderAnalyzer.exe` vanaf de [laatste release](https://github.com/Jaap79/SmtpHeaderAnalyzer/releases/latest) en start het bestand. De release is self-contained voor Windows x64; een losse .NET-installatie is niet nodig. De executable is momenteel niet digitaal ondertekend. Controleer desgewenst de SHA-256 tegen `SHA256SUMS.txt` uit dezelfde release.

## Belangrijke forensische grens

De onderste `Received`-regel is de oudste **claim** in de aangeleverde headers. Zonder geconfigureerde vertrouwde relaygrens kan die regel door een afzender zijn toegevoegd. De tool presenteert dit daarom als vermoedelijke oorsprong met beperkte betrouwbaarheid, niet als forensisch bewezen bron-IP. SPF/DKIM/DMARC worden niet opnieuw via DNS gevalideerd.

## Build en test

Vereist: Windows x64 en .NET 10 SDK.

```powershell
dotnet restore .\SmtpHeaderAnalyzer.slnx
dotnet build .\SmtpHeaderAnalyzer.slnx -c Release -m:1 -p:UseSharedCompilation=false
dotnet run --project .\tests\SmtpHeaderAnalyzer.Tests\SmtpHeaderAnalyzer.Tests.csproj -c Release
dotnet publish .\src\SmtpHeaderAnalyzer\SmtpHeaderAnalyzer.csproj -c Release -r win-x64 --self-contained true -o .\dist -m:1 -p:UseSharedCompilation=false
```

`.msg`-transportheaders worden rechtstreeks en read-only uit de MAPI Compound File-property gelezen via OpenMcdf; Outlook en RTF/fontinitialisatie zijn niet vereist.

## Beveiligingsmeldingen

Meld kwetsbaarheden niet in een publieke issue. Volg [SECURITY.md](SECURITY.md).

## Licentie

De applicatiecode valt onder de MIT License. OpenMcdf valt onder MPL-2.0; zie [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
