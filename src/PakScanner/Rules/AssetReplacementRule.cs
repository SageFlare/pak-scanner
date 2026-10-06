using PakScanner.Findings;

namespace PakScanner.Rules;

/// <summary>
/// Flags pak entries that shadow a trusted game asset. In Chivalry 2 a pak entry whose virtual
/// path falls under TBL/Content/&lt;game dir&gt; (rather than the mod's own TBL/Content/Mods/
/// namespace) can replace the game's asset at that path via pak mount precedence.
///
/// Reachability: whether a replacement actually takes effect depends on cook-fidelity of the
/// stand-in and mount precedence, which a static scanner cannot confirm (live testing showed an
/// inert stand-in did NOT deliver). So a replacement is reported as a real concern but
/// Reachable = false (flagged-latent) — severity still reflects how trusted/critical the shadowed
/// target is.
///
/// Known limitation: entries under TBL/Content/Mods/ are treated as the mod's own namespace and
/// not flagged. A pak writing into a DIFFERENT mod's Mods/&lt;Other&gt;/ namespace (cross-mod
/// shadowing) is not distinguishable here without the pak's own declared mod identity; documented
/// as a gap rather than flagged, to avoid a false positive on every benign mod.
///
/// Inspects ENTRY paths only, never the mount point (which legitimately is "../../../").
/// </summary>
public sealed class AssetReplacementRule : ISecurityRule
{
    public const string RuleName = "asset_replacement";

    private const string GameContentPrefix = "TBL/Content/";
    private const string ModNamespace = "TBL/Content/Mods/";

    // Standard Chivalry 2 content dirs (from UnchainedLauncher Chivalry2ScanOptions PathFilters),
    // minus Mods. Replacing content under these shadows trusted game assets.
    // Gameplay-critical dirs are High severity; the rest Medium.
    private static readonly HashSet<string> CriticalDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "Blueprint", "Characters", "GameModes", "Gameplay", "Weapons", "Abilities",
        "AI", "Inventory", "Interactables",
    };

    public IEnumerable<Finding> Inspect(ScanTarget target)
    {
        foreach (var path in target.EntryPaths)
        {
            var norm = Normalize(path);
            if (!norm.StartsWith(GameContentPrefix, StringComparison.OrdinalIgnoreCase))
                continue;
            if (norm.StartsWith(ModNamespace, StringComparison.OrdinalIgnoreCase))
                continue; // the mod's own namespace — not a replacement

            var rest = norm.Substring(GameContentPrefix.Length);
            var topDir = rest.Split('/', 2)[0];
            var severity = CriticalDirs.Contains(topDir) ? Severity.High : Severity.Medium;

            yield return new Finding(
                RuleName, path, severity, Reachable: false,
                Evidence: $"shadows a trusted game asset under TBL/Content/{topDir}/ "
                          + "(would replace the game's asset if it wins mount precedence)");
        }
    }

    /// <summary>
    /// Canonicalize a pak entry path so normalization tricks can't slip a game-dir path past the
    /// prefix check: backslashes -> /, strip a leading "./", collapse repeated slashes, strip a
    /// single leading slash.
    /// </summary>
    internal static string Normalize(string path)
    {
        var p = path.Replace('\\', '/');
        while (p.StartsWith("./", StringComparison.Ordinal)) p = p.Substring(2);
        while (p.Contains("//", StringComparison.Ordinal)) p = p.Replace("//", "/");
        if (p.StartsWith('/')) p = p.Substring(1);
        return p;
    }
}
