using PakScanner.Findings;

namespace PakScanner.Rules;

/// <summary>
/// Flags Blueprint assets that reference the stock <c>LaunchURL</c> node (KismetSystemLibrary),
/// which opens a URL in the user's browser. A pak carries no native code, so LaunchURL is one of
/// the few dangerous built-in nodes a mod can actually call.
///
/// Phase 1 detects *presence* in a package's name table (an attempt). Whether it is actually
/// wired to run on an event — which would make it Reachable (FlaggedActive) — is a Phase 2
/// refinement; until then a detected LaunchURL is High severity but Reachable=false (FlaggedLatent).
/// </summary>
public sealed class LaunchUrlRule : ISecurityRule
{
    public const string RuleName = "launch_url";
    private const string Token = "LaunchURL";

    // Only primary package files are independently loadable. .uexp/.ubulk are side-files of a
    // .uasset and must NOT be load-attempted (doing so counts false "unreadable" packages).
    private static readonly string[] AssetExtensions = { ".uasset", ".umap" };

    private const string ModBaseToken = "ArgonSDKModBase";

    private const string ModMarkerToken = "ModMarker";

    public IEnumerable<Finding> Inspect(ScanTarget target)
    {
        // First pass: collect every asset's names, so we can judge delivery by CONTENTS (does the
        // pak contain a DA_ModMarker asset, and is the LaunchURL BP an ArgonSDKModBase mod-actor)
        // rather than by file naming, which an attacker controls.
        var assetNames = new List<(string Path, List<string> Names)>();
        foreach (var path in target.EntryPaths)
        {
            if (!AssetExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                continue;
            var pkg = target.TryLoadPackage(path);
            if (pkg is null) continue;
            var names = pkg.NameMap.Select(n => n.Name).Where(n => n is not null).Cast<string>().ToList();
            assetNames.Add((path, names));
        }

        // Delivery signal: the Unchained loader auto-spawns a mod actor when the launcher mod list
        // names it, resolving BY NAME/PATH CONVENTION — /Game/Mods/AgMods/<Name>/<Name> cast to
        // ArgonSDKModBase (verified from BPF_ModLoading: UNCN_GetModActorClassByName ->
        // LoadSoftClassSynchronously). A DA_ModMarker is NOT required for the in-game spawn (it
        // feeds editor/metadata tooling). So an ArgonSDKModBase LaunchURL actor delivers if EITHER
        // it sits at the AgMods convention path OR a marker is present in the pak.
        var hasMarker = assetNames.Any(a => NamesIndicateModMarker(a.Names));

        foreach (var (path, names) in assetNames)
        {
            if (!NamesIndicateLaunchUrl(names, out var evidence))
                continue;

            var isModActor = NamesIndicateModActor(names);
            var atConventionPath = IsAgModsConventionPath(path);
            var delivered = isModActor && (atConventionPath || hasMarker);

            string fullEvidence = evidence;
            if (delivered)
            {
                var why = atConventionPath
                    ? "ArgonSDKModBase actor at the AgMods auto-spawn path"
                    : "ArgonSDKModBase actor with a DA_ModMarker present";
                fullEvidence += $"; {why} -> runs on load";
            }
            yield return MakeFinding(path, fullEvidence, delivered);
        }
    }

    /// <summary>
    /// True if the entry sits at the Unchained auto-spawn convention path
    /// TBL/Content/Mods/AgMods/&lt;Name&gt;/&lt;Name&gt;.uasset — the loader spawns the actor by this
    /// name/path convention, so it fires on load with no marker asset required.
    /// </summary>
    public static bool IsAgModsConventionPath(string path)
    {
        var p = path.Replace('\\', '/');
        const string prefix = "TBL/Content/Mods/AgMods/";
        if (!p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var rest = p.Substring(prefix.Length);
        var parts = rest.Split('/');
        if (parts.Length != 2) return false;                 // exactly <Name>/<file>
        var name = parts[0];
        var file = System.IO.Path.GetFileNameWithoutExtension(parts[1]);
        return name.Length > 0 && string.Equals(name, file, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True if the package references the LaunchURL node. Uses substring (not exact equality) so
    /// suffixed/mangled cooked forms (e.g. CallFunc_LaunchURL, LaunchURL_0) are still caught.
    /// </summary>
    public static bool NamesIndicateLaunchUrl(IEnumerable<string> names, out string evidence)
    {
        foreach (var n in names)
        {
            if (n is not null && n.Contains(Token, StringComparison.OrdinalIgnoreCase))
            {
                evidence = $"references {Token} ('{n}')";
                return true;
            }
        }
        evidence = string.Empty;
        return false;
    }

    /// <summary>True if the names show this BP is an ArgonSDKModBase subclass (an auto-spawned mod actor).</summary>
    public static bool NamesIndicateModActor(IEnumerable<string> names) =>
        names.Any(n => n is not null && n.Contains(ModBaseToken, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True if the package references the DA_ModMarker class — detected by CONTENT (the class
    /// name in the asset's name table), so renaming the marker file does not evade it.
    /// </summary>
    public static bool NamesIndicateModMarker(IEnumerable<string> names) =>
        names.Any(n => n is not null && n.Contains(ModMarkerToken, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// <paramref name="delivered"/> true when the node would execute on load (auto-spawned mod
    /// actor) -> Reachable -> FlaggedActive; false when only present in the file -> FlaggedLatent.
    /// </summary>
    public static Finding MakeFinding(string path, string evidence, bool delivered = false) =>
        new(RuleName, path, Severity.High, Reachable: delivered, Evidence: evidence);
}
