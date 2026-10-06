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

    private static readonly string[] AssetExtensions = { ".uasset", ".uexp", ".umap" };

    private const string ModBaseToken = "ArgonSDKModBase";

    public IEnumerable<Finding> Inspect(ScanTarget target)
    {
        // A LaunchURL BP that is an ArgonSDKModBase mod-actor AND ships with a DA_ModMarker is
        // auto-spawned by the Unchained loader on match load -> its BeginPlay runs -> reachable.
        var hasMarker = HasModMarker(target.EntryPaths);

        foreach (var path in target.EntryPaths)
        {
            if (!AssetExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                continue;
            var pkg = target.TryLoadPackage(path);
            if (pkg is null) continue;

            var names = pkg.NameMap.Select(n => n.Name).Where(n => n is not null).Cast<string>().ToList();
            if (!NamesIndicateLaunchUrl(names, out var evidence))
                continue;

            var delivered = hasMarker && NamesIndicateModActor(names);
            var fullEvidence = delivered
                ? evidence + "; auto-spawned mod actor (ArgonSDKModBase + DA_ModMarker) -> runs on load"
                : evidence;
            yield return MakeFinding(path, fullEvidence, delivered);
        }
    }

    /// <summary>True if the package's names reference the LaunchURL node. Testable seam.</summary>
    public static bool NamesIndicateLaunchUrl(IEnumerable<string> names, out string evidence)
    {
        foreach (var n in names)
        {
            if (string.Equals(n, Token, StringComparison.OrdinalIgnoreCase))
            {
                evidence = $"name table contains {Token}";
                return true;
            }
        }
        evidence = string.Empty;
        return false;
    }

    /// <summary>True if the names show this BP is an ArgonSDKModBase subclass (an auto-spawned mod actor).</summary>
    public static bool NamesIndicateModActor(IEnumerable<string> names) =>
        names.Any(n => n is not null && n.Contains(ModBaseToken, StringComparison.OrdinalIgnoreCase));

    /// <summary>True if any pak entry is a DA_ModMarker (makes the loader auto-spawn the tagged actor).</summary>
    public static bool HasModMarker(IEnumerable<string> entryPaths) =>
        entryPaths.Any(p => p is not null &&
            Path.GetFileNameWithoutExtension(p).Contains("ModMarker", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// <paramref name="delivered"/> true when the node would execute on load (auto-spawned mod
    /// actor) -> Reachable -> FlaggedActive; false when only present in the file -> FlaggedLatent.
    /// </summary>
    public static Finding MakeFinding(string path, string evidence, bool delivered = false) =>
        new(RuleName, path, Severity.High, Reachable: delivered, Evidence: evidence);
}
