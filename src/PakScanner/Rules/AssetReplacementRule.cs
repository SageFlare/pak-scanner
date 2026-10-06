using PakScanner.Findings;

namespace PakScanner.Rules;

/// <summary>
/// Flags pak entries that shadow a trusted game asset. In Chivalry 2 a pak entry whose virtual
/// path falls under TBL/Content/&lt;game dir&gt; (rather than the mod's own TBL/Content/Mods/
/// namespace) replaces the game's asset at that path via pak mount precedence. This is the
/// primary real malicious vector; a replacement takes effect on mount (Reachable = true).
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
            var norm = path.Replace('\\', '/');
            if (!norm.StartsWith(GameContentPrefix, StringComparison.OrdinalIgnoreCase))
                continue;
            if (norm.StartsWith(ModNamespace, StringComparison.OrdinalIgnoreCase))
                continue; // the mod's own namespace — not a replacement

            var rest = norm.Substring(GameContentPrefix.Length);
            var topDir = rest.Split('/', 2)[0];
            var severity = CriticalDirs.Contains(topDir) ? Severity.High : Severity.Medium;

            yield return new Finding(
                RuleName, path, severity, Reachable: true,
                Evidence: $"shadows a trusted game asset under TBL/Content/{topDir}/");
        }
    }
}
