using PakScanner.Findings;

namespace PakScanner.Rules;

/// <summary>
/// Flags a "hidden" mod: an ArgonSDKModBase actor at the AgMods auto-spawn convention path
/// (TBL/Content/Mods/AgMods/&lt;Name&gt;/&lt;Name&gt;) that ships WITHOUT a DA_ModMarker. Such a mod
/// does not appear in the Mod Manager menu (the marker drives GUI discoverability), yet a server
/// can force-load it by name (--next-map-mod-actors / ?mods=) and it auto-spawns on load.
///
/// This is a standalone concern independent of any payload node: a mod deliberately kept out of
/// the menu but still loadable is suspicious on its own (the classic trojan-pak shape — a visible
/// decoy plus a hidden actor). Reported High severity but Reachable = false (flagged-latent): being
/// hidden is a strong red flag for a human, not by itself a confirmed harmful action. If the hidden
/// actor also carries a dangerous node (e.g. LaunchURL), that rule independently raises it to
/// flagged-active.
/// </summary>
public sealed class HiddenModRule : ISecurityRule
{
    public const string RuleName = "hidden_mod";

    private static readonly string[] AssetExtensions = { ".uasset", ".umap" };

    public IEnumerable<Finding> Inspect(ScanTarget target)
    {
        // Does ANY asset in the pak carry a DA_ModMarker (making mods here menu-visible)?
        var pakHasMarker = false;
        var actors = new List<(string Path, bool IsModActor, bool AtConvention)>();

        foreach (var path in target.EntryPaths)
        {
            if (!AssetExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                continue;
            var pkg = target.TryLoadPackage(path);
            if (pkg is null) continue;
            var names = pkg.NameMap.Select(n => n.Name).Where(n => n is not null).Cast<string>().ToList();

            if (LaunchUrlRule.NamesIndicateModMarker(names)) pakHasMarker = true;
            if (LaunchUrlRule.NamesIndicateModActor(names))
                actors.Add((path, true, LaunchUrlRule.IsAgModsConventionPath(path)));
        }

        foreach (var (path, isModActor, atConvention) in actors)
        {
            if (IsHiddenMod(isModActor, atConvention, pakHasMarker))
                yield return MakeFinding(path);
        }
    }

    /// <summary>A mod actor at the convention path with no marker in the pak is menu-hidden.</summary>
    public static bool IsHiddenMod(bool isModActor, bool atConventionPath, bool pakHasMarker) =>
        isModActor && atConventionPath && !pakHasMarker;

    public static Finding MakeFinding(string path) =>
        new(RuleName, path, Severity.High, Reachable: false,
            Evidence: "mod actor force-loadable by name but absent from the Mod Manager menu "
                      + "(no DA_ModMarker) — a server can run it without the player seeing it");
}
