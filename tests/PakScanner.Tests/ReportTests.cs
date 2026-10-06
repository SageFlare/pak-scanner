using PakScanner.Findings;
using PakScanner.Report;
using Xunit;

namespace PakScanner.Tests;

public class ReportTests
{
    [Fact]
    public void Report_shows_verdict_and_findings()
    {
        var r = new ScanResult(
            "mod.pak", Verdict.FlaggedActive,
            new[] { new Finding("asset_replacement", "TBL/Content/Blueprint/X.uasset", Severity.High, true, "shadows trusted asset") },
            null);
        var text = ReportRenderer.Render(r);
        Assert.Contains("flagged-active", text);
        Assert.Contains("TBL/Content/Blueprint/X.uasset", text);
        Assert.Contains("shadows trusted asset", text);
    }

    [Fact]
    public void Clean_report_says_benign()
    {
        var text = ReportRenderer.Render(new ScanResult("m.pak", Verdict.Benign, Array.Empty<Finding>(), null));
        Assert.Contains("benign", text);
    }

    [Fact]
    public void Attempt_is_distinguished_from_confirmed()
    {
        var r = new ScanResult(
            "m.pak", Verdict.FlaggedLatent,
            new[] { new Finding("launch_url", "Mod/BP.uasset", Severity.High, false, "name table contains LaunchURL") },
            null);
        var text = ReportRenderer.Render(r);
        Assert.Contains("flagged-latent", text);
        Assert.Contains("Latent", text);
        Assert.Contains("LaunchURL", text);
    }
}
