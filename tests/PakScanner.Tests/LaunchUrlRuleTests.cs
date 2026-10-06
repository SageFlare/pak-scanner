using PakScanner.Findings;
using PakScanner.Rules;
using Xunit;

namespace PakScanner.Tests;

public class LaunchUrlRuleTests
{
    [Fact]
    public void Name_set_containing_LaunchURL_is_detected()
    {
        var names = new[] { "BeginPlay", "LaunchURL", "KismetSystemLibrary" };
        Assert.True(LaunchUrlRule.NamesIndicateLaunchUrl(names, out var evidence));
        Assert.Contains("LaunchURL", evidence);
    }

    [Fact]
    public void Benign_name_set_is_not_detected()
    {
        var names = new[] { "BeginPlay", "PlaySound", "SetMaterial", "StaticMesh" };
        Assert.False(LaunchUrlRule.NamesIndicateLaunchUrl(names, out _));
    }

    [Fact]
    public void Detected_launch_url_is_high_but_unreachable_in_phase1()
    {
        // Phase 1 flags presence (an attempt); reachability refinement is Phase 2, so a
        // detected LaunchURL is High severity but Reachable=false -> Attempted, not Malicious.
        var f = LaunchUrlRule.MakeFinding("Mod/BP_Thing.uasset", "name table contains LaunchURL");
        Assert.Equal(Severity.High, f.Severity);
        Assert.False(f.Reachable);
        Assert.Equal("launch_url", f.Rule);
    }
}
