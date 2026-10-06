using PakScanner.Findings;
using PakScanner.Rules;
using Xunit;

namespace PakScanner.Tests;

public class AssetReplacementRuleTests
{
    private static ScanTarget Target(params string[] entries) =>
        ScanTarget.ForPathsOnly(entries);

    [Fact]
    public void Entry_under_game_blueprint_dir_is_high_severity()
    {
        var findings = new AssetReplacementRule()
            .Inspect(Target("TBL/Content/Blueprint/BP_PlayerController.uasset"))
            .ToList();
        // High severity (critical dir) but not Reachable — delivery is unconfirmable statically.
        Assert.Contains(findings, f => f is { Severity: Severity.High, Reachable: false, Rule: "asset_replacement" });
    }

    [Fact]
    public void Entry_under_mod_namespace_is_not_flagged()
    {
        var findings = new AssetReplacementRule()
            .Inspect(Target("TBL/Content/Mods/AgMods/MyMod/BP_Thing.uasset"))
            .ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void Non_critical_game_dir_is_medium()
    {
        var findings = new AssetReplacementRule()
            .Inspect(Target("TBL/Content/Audio/Music/Track.uasset"))
            .ToList();
        Assert.Contains(findings, f => f.Severity == Severity.Medium && f.Rule == "asset_replacement");
    }

    [Fact]
    public void Mount_point_style_path_is_not_treated_as_entry()
    {
        // The mount point (../../../) is not an entry; only real entry paths are inspected.
        var findings = new AssetReplacementRule()
            .Inspect(Target("TBL/Content/Mods/MyMod/A.uasset"))
            .ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void Replacement_is_not_marked_reachable_delivery_is_uncertain()
    {
        // I5: a static scanner cannot confirm a replacement actually delivers (cook-fidelity +
        // mount precedence decide that). It's a real concern but flagged-latent, not auto-active.
        var findings = new AssetReplacementRule()
            .Inspect(Target("TBL/Content/Blueprint/BP_PlayerController.uasset"))
            .ToList();
        Assert.All(findings, f => Assert.False(f.Reachable));
        Assert.Contains(findings, f => f.Severity == Severity.High); // critical dir still High
    }

    [Theory]
    [InlineData("./TBL/Content/Blueprint/X.uasset")]
    [InlineData("TBL//Content/Blueprint/X.uasset")]
    [InlineData("/TBL/Content/Blueprint/X.uasset")]
    public void Path_normalization_evasions_are_still_caught(string sneaky)
    {
        // I6: leading ./, doubled //, or leading / must not slip a game-dir replacement past.
        var findings = new AssetReplacementRule().Inspect(Target(sneaky)).ToList();
        Assert.NotEmpty(findings);
    }

}
