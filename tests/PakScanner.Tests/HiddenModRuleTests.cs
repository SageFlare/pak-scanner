using PakScanner.Findings;
using PakScanner.Rules;
using Xunit;

namespace PakScanner.Tests;

public class HiddenModRuleTests
{
    private static ScanTarget RealSample(string name)
    {
        // Build a provider-backed target from a real corpus pak via the scanner's own staging.
        // Simpler: use path-only + the static helpers for unit-level logic.
        return ScanTarget.ForPathsOnly(new[] { name });
    }

    [Fact]
    public void Conventional_actor_without_marker_is_a_hidden_mod_signal()
    {
        // mod actor at AgMods convention path + no marker in the pak = menu-hidden, force-loadable.
        Assert.True(HiddenModRule.IsHiddenMod(
            isModActor: true,
            atConventionPath: true,
            pakHasMarker: false));
    }

    [Fact]
    public void Conventional_actor_WITH_marker_is_not_hidden()
    {
        // has a marker -> shows in the menu -> not a hidden mod.
        Assert.False(HiddenModRule.IsHiddenMod(
            isModActor: true,
            atConventionPath: true,
            pakHasMarker: true));
    }

    [Fact]
    public void Non_mod_actor_is_not_a_hidden_mod()
    {
        Assert.False(HiddenModRule.IsHiddenMod(
            isModActor: false,
            atConventionPath: true,
            pakHasMarker: false));
    }

    [Fact]
    public void Hidden_mod_finding_is_high_latent()
    {
        var f = HiddenModRule.MakeFinding("p");
        Assert.Equal("hidden_mod", f.Rule);
        Assert.Equal(Severity.High, f.Severity);
        Assert.False(f.Reachable); // "hidden" is a strong concern, not a confirmed harmful action
    }
}
