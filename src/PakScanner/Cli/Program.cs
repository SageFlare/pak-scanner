using System.Text.Json;
using PakScanner;
using PakScanner.Findings;
using PakScanner.Report;
using PakScanner.Rules;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("pak-scan <pak> [--json]");
    Console.WriteLine("  Scans a Chivalry 2 mod .pak and reports benign / attempted / malicious.");
    return 1;
}

var pak = args[0];
var asJson = args.Contains("--json");

var scanner = new SecurityScanner(new ISecurityRule[]
{
    new AssetReplacementRule(),
    new LaunchUrlRule(),
});

var result = scanner.Scan(pak);

if (asJson)
{
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        pak = result.Pak,
        verdict = result.Verdict.ToName(),
        error = result.Error,
        findings = result.Findings.Select(f => new
        {
            f.Rule, f.Path, severity = f.Severity.ToString(), f.Reachable, f.Evidence,
        }),
    }, new JsonSerializerOptions { WriteIndented = true }));
}
else
{
    Console.WriteLine(ReportRenderer.Render(result));
}

// Exit code by verdict: 0 benign, 2 flagged-latent, 3 flagged-active.
return result.Verdict switch
{
    Verdict.Benign => 0,
    Verdict.FlaggedLatent => 2,
    Verdict.FlaggedActive => 3,
    _ => 1,
};
