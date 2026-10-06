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
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(new ISecurityRule[] { new LaunchUrlRule() });
        var result = scanner.Scan(pak);
        Assert.Contains(result.Findings, f => f.Rule == "launch_url");
        Assert.NotEqual(Verdict.Benign, result.Verdict);
    }

    [Fact]
    public void Delivered_launch_url_pak_is_flagged_active()
    {
        // The mod-actor (ArgonSDKModBase + DA_ModMarker) auto-spawns on load, so LaunchURL is
        // reachable -> FlaggedActive, distinct from the loose BP which is FlaggedLatent.
        var pak = CorpusSample("zz_launch_url_delivered.pak");
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(new ISecurityRule[] { new LaunchUrlRule() });
        var result = scanner.Scan(pak);
        Assert.Equal(Verdict.FlaggedActive, result.Verdict);
    }

    [Fact]
    public void Benign_modpack_two_markered_mods_is_benign()
    {
        // Two legit mods in one pak, each WITH a marker -> both menu-visible -> hidden_mod must NOT
        // fire. Guards against the hidden_mod rule false-positiving on honest multi-mod packs.
        var pak = CorpusSample("benign_modpack.pak");
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(new ISecurityRule[]
        {
            new AssetReplacementRule(), new LaunchUrlRule(), new HiddenModRule(),
        });
        var result = scanner.Scan(pak);
        Assert.Equal(Verdict.Benign, result.Verdict);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Web_widget_pak_is_flagged_active_silent_beacon()
    {
        // TBLWebWidget.BrowseToUrl lives in a UserWidget created by an auto-spawned mod actor ->
        // reachable (pak-level delivery) -> flagged-active. Guards the actor->widget link.
        var pak = CorpusSample("zz_web_widget.pak");
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(new ISecurityRule[] { new WebWidgetRule() });
        var result = scanner.Scan(pak);
        Assert.Equal(Verdict.FlaggedActive, result.Verdict);
        Assert.Contains(result.Findings, f => f.Rule == "web_widget" && f.Reachable);
    }

    [Fact]
    public void Trojan_decoy_pak_is_flagged_active_despite_benign_decoy()
    {
        // A pak carrying a benign decoy mod AND a hidden markerless LaunchURL mod must still be
        // flagged-active on the hidden one — the menu would only show the decoy.
        var pak = CorpusSample("trojan_decoy.pak");
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(new ISecurityRule[] { new LaunchUrlRule(), new AssetReplacementRule() });
        var result = scanner.Scan(pak);
        Assert.Equal(Verdict.FlaggedActive, result.Verdict);
        Assert.Contains(result.Findings, f => f.Rule == "launch_url" && f.Reachable);
    }

    [Fact]
    public void AssetReplacement_attempt_pak_is_detected()
    {
        var pak = CorpusSample("asset_replacement_attempt.pak");
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(new ISecurityRule[] { new AssetReplacementRule() });
        var result = scanner.Scan(pak);
        Assert.Contains(result.Findings, f => f.Rule == "asset_replacement");
    }

    [Fact]
    public void Oversized_pak_is_refused_not_ingested()
    {
        // I9: a pak over the size cap must be refused (Indeterminate), not copied+parsed.
        var tmp = Path.Combine(Path.GetTempPath(), $"big_{Guid.NewGuid():N}.pak");
        File.WriteAllBytes(tmp, new byte[1024]);
        try
        {
            var scanner = new SecurityScanner(Array.Empty<ISecurityRule>(), maxPakBytes: 100);
            var result = scanner.Scan(tmp);
            Assert.Equal(Verdict.Indeterminate, result.Verdict);
            Assert.Contains("cap", result.Error ?? "");
        }
        finally { File.Delete(tmp); }
    }

    [Fact]
    public void Garbage_file_is_handled_not_thrown()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"paktest_{Guid.NewGuid():N}.pak");
        File.WriteAllBytes(tmp, new byte[] { 1, 2, 3, 4, 5 });
        try
        {
            var result = new SecurityScanner(Array.Empty<ISecurityRule>()).Scan(tmp);
            // C3: a malformed pak must not throw, must record an error, and must NOT be Benign —
            // an input the scanner can't analyze is Indeterminate (a blocking state).
            Assert.NotNull(result.Error);
            Assert.Equal(Verdict.Indeterminate, result.Verdict);
        }
        finally
        {
            File.Delete(tmp);
        }
    }
}
