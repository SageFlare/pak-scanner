using PakScanner;
using PakScanner.Findings;
using PakScanner.Rules;
using Xunit;

namespace PakScanner.Tests;

public class ScannerScanTests
{
    // pak-corpus is a sibling repo. BaseDirectory is
    // <...>/pak-scanner/tests/PakScanner.Tests/bin/Debug/net8.0 -> up 6 to the workspace root,
    // then into pak-corpus/samples.
    private static string CorpusSample(string name) =>
        Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..",
            "pak-corpus", "samples", name));

    [Fact]
    public void Benign_map_scans_benign()
    {
        var pak = CorpusSample("benign_map.pak");
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(Array.Empty<ISecurityRule>());
        var result = scanner.Scan(pak);
        Assert.Null(result.Error);
        Assert.Equal(Verdict.Benign, result.Verdict);
    }

    [Theory]
    [InlineData("benign_map.pak")]
    [InlineData("benign_cosmetic.pak")]
    public void Real_benign_samples_score_benign_with_replacement_rule(string sample)
    {
        var pak = CorpusSample(sample);
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(new ISecurityRule[] { new AssetReplacementRule() });
        var result = scanner.Scan(pak);
        Assert.Null(result.Error);
        Assert.Equal(Verdict.Benign, result.Verdict);
    }

    [Fact]
    public void LaunchUrl_attempt_pak_is_detected()
    {
        // Regression: the LaunchURL BP asset is Zlib-compressed. Without zlib-ng initialized,
        // the asset read failed silently and the pak scored Benign (a missed malicious pak).
        var pak = CorpusSample("launch_url_attempt.pak");
        if (!File.Exists(pak)) return; // pen-test sample is user-authored; skip if absent
        var scanner = new SecurityScanner(new ISecurityRule[] { new LaunchUrlRule() });
        var result = scanner.Scan(pak);
        Assert.Contains(result.Findings, f => f.Rule == "launch_url");
        Assert.NotEqual(Verdict.Benign, result.Verdict);
    }

    [Fact]
    public void AssetReplacement_attempt_pak_is_detected()
    {
        var pak = CorpusSample("asset_replacement_attempt.pak");
        if (!File.Exists(pak)) return;
        var scanner = new SecurityScanner(new ISecurityRule[] { new AssetReplacementRule() });
        var result = scanner.Scan(pak);
        Assert.Contains(result.Findings, f => f.Rule == "asset_replacement");
    }

    [Fact]
    public void Garbage_file_is_handled_not_thrown()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"paktest_{Guid.NewGuid():N}.pak");
        File.WriteAllBytes(tmp, new byte[] { 1, 2, 3, 4, 5 });
        try
        {
            var result = new SecurityScanner(Array.Empty<ISecurityRule>()).Scan(tmp);
            // A malformed pak must not throw; it yields a result (error recorded).
            Assert.NotNull(result);
        }
        finally
        {
            File.Delete(tmp);
        }
    }
}
