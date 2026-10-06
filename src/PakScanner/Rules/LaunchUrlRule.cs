using PakScanner.Findings;

namespace PakScanner.Rules;

/// <summary>
/// Flags Blueprint assets that reference the stock <c>LaunchURL</c> node (KismetSystemLibrary),
/// which opens a URL in the user's browser. A pak carries no native code, so LaunchURL is one of
/// the few dangerous built-in nodes a mod can actually call.
///
/// Phase 1 detects *presence* in a package's name table (an attempt). Whether it is actually
/// wired to run on an event — which would make it Reachable (Malicious) — is a Phase 2
/// refinement; until then a detected LaunchURL is High severity but Reachable=false (Attempted).
/// </summary>
public sealed class LaunchUrlRule : ISecurityRule
{
    public const string RuleName = "launch_url";
    private const string Token = "LaunchURL";

    private static readonly string[] AssetExtensions = { ".uasset", ".uexp", ".umap" };

    public IEnumerable<Finding> Inspect(ScanTarget target)
    {
        foreach (var path in target.EntryPaths)
        {
            if (!AssetExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                continue;
            var pkg = target.TryLoadPackage(path);
            if (pkg is null) continue;

            var names = pkg.NameMap.Select(n => n.Name).Where(n => n is not null).Cast<string>();
            if (NamesIndicateLaunchUrl(names, out var evidence))
                yield return MakeFinding(path, evidence);
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

    public static Finding MakeFinding(string path, string evidence) =>
        new(RuleName, path, Severity.High, Reachable: false, Evidence: evidence);
}
