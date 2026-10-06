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
    public void Names_referencing_the_modmarker_class_are_detected_regardless_of_filename()
    {
        // Content-based: the asset references the DA_ModMarker class. Renaming the file does not
        // change these names, so the detection survives the C2 evasion.
        var names = new[] { "DA_ModMarker_C", "ModActors", "Default__DA_ModMarker_C" };
        Assert.True(LaunchUrlRule.NamesIndicateModMarker(names));
    }

    [Fact]
    public void Names_without_a_modmarker_class_are_not()
    {
        var names = new[] { "StaticMesh", "Material", "BeginPlay" };
        Assert.False(LaunchUrlRule.NamesIndicateModMarker(names));
    }

    [Theory]
    [InlineData("TBL/Content/Mods/AgMods/EvilMod/EvilMod.uasset", true)]
    [InlineData("TBL/Content/Mods/AgMods/EvilMod/EvilMod.umap", true)]
    [InlineData("TBL/Content/Mods/AgMods/EvilMod/SomethingElse.uasset", false)] // not <Name>/<Name>
    [InlineData("TBL/Content/Mods/AgMods/EvilMod/Sub/EvilMod.uasset", false)]   // nested, not convention
    [InlineData("TBL/Content/Mods/PlainMod/PlainMod.uasset", false)]            // not under AgMods
    public void AgMods_convention_path_is_recognized(string path, bool expected) =>
        Assert.Equal(expected, LaunchUrlRule.IsAgModsConventionPath(path));

    [Fact]
    public void Delivered_finding_is_reachable_latent_finding_is_not()
    {
        var delivered = LaunchUrlRule.MakeFinding("p", "e", delivered: true);
        Assert.True(delivered.Reachable);
        var latent = LaunchUrlRule.MakeFinding("p", "e", delivered: false);
        Assert.False(latent.Reachable);
    }
}
