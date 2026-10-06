using CUE4Parse.Compression;
using CUE4Parse.Encryption.Aes;
using CUE4Parse.FileProvider;
using CUE4Parse.UE4.Objects.Core.Misc;
using CUE4Parse.UE4.Versions;
using PakScanner.Findings;
using PakScanner.Rules;

namespace PakScanner;

/// <summary>
/// Scans a single untrusted Chivalry 2 mod .pak read-only via CUE4Parse, runs security rules,
/// and decides a three-state verdict. Never mounts or executes the pak; a parse failure becomes
/// a result with an error, never an exception out of <see cref="Scan"/>.
/// </summary>
public sealed class SecurityScanner
{
    private const string ZeroAesKey =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    private readonly IReadOnlyList<ISecurityRule> _rules;

    public SecurityScanner(IEnumerable<ISecurityRule> rules) => _rules = rules.ToList();

    public ScanResult Scan(string pakPath)
    {
        var findings = new List<Finding>();
        string? error = null;
        string? stageDir = null;

        try
        {
            EnsureZlib();

            // The provider works over a directory; stage just this pak in an isolated temp dir
            // so nothing else is mounted.
            stageDir = StagePak(pakPath);

            using var provider = new DefaultFileProvider(
                stageDir, SearchOption.TopDirectoryOnly, isCaseInsensitive: true,
                new VersionContainer(EGame.GAME_UE4_25));
            provider.Initialize();
            provider.SubmitKey(new FGuid(), new FAesKey(ZeroAesKey));
            provider.LoadVirtualPaths();

            var entryPaths = provider.Files.Keys.ToList();
            var target = new ScanTarget(provider, entryPaths);

            foreach (var rule in _rules)
                findings.AddRange(rule.Inspect(target));
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
        finally
        {
            TryCleanup(stageDir);
        }

        var verdict = error is not null && findings.Count == 0
            ? Verdict.FlaggedLatent           // unparseable/suspect input is not benign
            : VerdictPolicy.Decide(findings);

        return new ScanResult(pakPath, verdict, findings, error);
    }

    private static string StagePak(string pakPath)
    {
        if (!File.Exists(pakPath))
            throw new FileNotFoundException("pak not found", pakPath);
        var dir = Path.Combine(Path.GetTempPath(), "pakscan_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.Copy(pakPath, Path.Combine(dir, Path.GetFileName(pakPath)), overwrite: true);
        return dir;
    }

    private static void TryCleanup(string? dir)
    {
        if (dir is null) return;
        try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
    }

    private static bool _zlibReady;

    private static void EnsureZlib()
    {
        if (_zlibReady) return;
        // CUE4Parse needs the zlib-ng native lib to read Zlib-compressed pak entries (most real
        // paks). Without it, asset reads throw "Zlib decompression failed: not initialized" and a
        // compressed malicious asset would be silently missed. Download it once (cached next to
        // the executable) via CUE4Parse's own helper, then initialize.
        var dllPath = Path.Combine(AppContext.BaseDirectory, ZlibHelper.DLL_NAME);
        if (!File.Exists(dllPath))
            ZlibHelper.DownloadDll(dllPath, ZlibHelper.DOWNLOAD_URL);
        ZlibHelper.Initialize(dllPath);
        _zlibReady = true;
    }
}
