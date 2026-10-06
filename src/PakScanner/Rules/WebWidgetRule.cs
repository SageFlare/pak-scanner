using PakScanner.Findings;

namespace PakScanner.Rules;

/// <summary>
/// Flags Blueprint assets that reference Chivalry 2's in-game web view, <c>UTBLWebWidget</c>
/// (TBL/Public/TBLWebWidget.h), whose <c>BrowseToUrl(FString)</c> is BlueprintCallable. Unlike
/// LaunchURL (which pops the external browser visibly), a mod can create this widget, hide its
/// address bar / keep it offscreen / never add it to the viewport, and navigate it to any URL — a
/// SILENT fetch inside the game process that leaks the player's IP and loads a full web page (JS,
/// trackers, drive-by). Stealthier and higher-severity than LaunchURL; this rule exists because
/// that one would miss it.
///
/// Reachable (flagged-active) when the BP is an auto-spawned mod actor (ArgonSDKModBase at the
/// AgMods convention path, or a marker is present); otherwise flagged-latent (present, delivery
/// unconfirmed) — same delivery model as the launch_url rule.
/// </summary>
public sealed class WebWidgetRule : ISecurityRule
{
    public const string RuleName = "web_widget";
    private static readonly string[] Tokens = { "TBLWebWidget", "BrowseToUrl" };
    private static readonly string[] AssetExtensions = { ".uasset", ".umap" };

    public IEnumerable<Finding> Inspect(ScanTarget target)
    {
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

        var hasMarker = assetNames.Any(a => LaunchUrlRule.NamesIndicateModMarker(a.Names));

        foreach (var (path, names) in assetNames)
        {
            if (!NamesIndicateWebWidget(names, out var evidence))
                continue;

            var delivered = LaunchUrlRule.NamesIndicateModActor(names)
                            && (LaunchUrlRule.IsAgModsConventionPath(path) || hasMarker);
            var full = delivered
                ? evidence + "; auto-spawned mod actor -> runs on load (SILENT: in-game web view, no external browser)"
                : evidence + " (SILENT: in-game web view, no external browser)";
            yield return MakeFinding(path, full, delivered);
        }
    }

    /// <summary>True if the package references the in-game web widget / BrowseToUrl (substring).</summary>
    public static bool NamesIndicateWebWidget(IEnumerable<string> names, out string evidence)
    {
        foreach (var n in names)
        {
            if (n is null) continue;
            foreach (var t in Tokens)
            {
                if (n.Contains(t, StringComparison.OrdinalIgnoreCase))
                {
                    evidence = $"references {t} ('{n}')";
                    return true;
                }
            }
        }
        evidence = string.Empty;
        return false;
    }

    public static Finding MakeFinding(string path, string evidence, bool delivered = false) =>
        new(RuleName, path, Severity.High, Reachable: delivered, Evidence: evidence);
}
