using PakScanner.Findings;
using PakScanner.Rules;
using Xunit;

namespace PakScanner.Tests;

public class LaunchUrlReachabilityTests
{
    [Fact]
    public void ModBase_names_indicate_an_auto_spawned_mod_actor()
    {
        var names = new[] { "BeginPlay", "LaunchURL", "ArgonSDKModBase" };
        Assert.True(LaunchUrlRule.NamesIndicateModActor(names));
    }

    [Fact]
    public void Plain_actor_names_do_not_indicate_a_mod_actor()
    {
        var names = new[] { "BeginPlay", "LaunchURL", "Actor" };
        Assert.False(LaunchUrlRule.NamesIndicateModActor(names));
    }

    [Fact]
    public void Entry_paths_with_a_modmarker_are_detected()
    {
        var paths = new[]
        {
            "TBL/Content/Mods/AgMods/X/X.uasset",
            "TBL/Content/Mods/AgMods/X/ModMarker.uasset",
        };
        Assert.True(LaunchUrlRule.HasModMarker(paths));
    }

    [Fact]
    public void Entry_paths_without_a_modmarker_are_not()
    {
        var paths = new[] { "TBL/Content/Mods/X/BP_Thing.uasset" };
        Assert.False(LaunchUrlRule.HasModMarker(paths));
    }

    [Fact]
    public void Delivered_finding_is_reachable_latent_finding_is_not()
    {
        var delivered = LaunchUrlRule.MakeFinding("p", "e", delivered: true);
        Assert.True(delivered.Reachable);
        var latent = LaunchUrlRule.MakeFinding("p", "e", delivered: false);
        Assert.False(latent.Reachable);
    }
}
