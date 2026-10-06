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

    /// <summary>Default cap on pak size the scanner will ingest (defends against oversized/bomb input).</summary>
    public const long DefaultMaxPakBytes = 4L * 1024 * 1024 * 1024; // 4 GiB

    private readonly IReadOnlyList<ISecurityRule> _rules;
    private readonly long _maxPakBytes;

    public SecurityScanner(IEnumerable<ISecurityRule> rules, long maxPakBytes = DefaultMaxPakBytes)
    {
        _rules = rules.ToList();
        _maxPakBytes = maxPakBytes;
    }

    public ScanResult Scan(string pakPath)
    {
        var findings = new List<Finding>();
        string? error = null;
        string? stageDir = null;
        int unreadable = 0;

        try
        {
            EnsureZlib();

            // The provider works over a directory; stage just this pak in an isolated temp dir
            // so nothing else is mounted.
            stageDir = StagePak(pakPath, _maxPakBytes);

            using var provider = new DefaultFileProvider(
                stageDir, SearchOption.TopDirectoryOnly, isCaseInsensitive: true,
                new VersionContainer(EGame.GAME_UE4_25));
            provider.Initialize();
            provider.SubmitKey(new FGuid(), new FAesKey(ZeroAesKey));
            provider.LoadVirtualPaths();

            var entryPaths = provider.Files.Keys.ToList();

            // A non-empty .pak that mounts zero files did not parse as a valid pak — do not pass
            // it off as Benign; the scanner could not see into it.
            if (entryPaths.Count == 0)
            {
                error = "pak mounted no files; not a readable pak (analysis incomplete)";
            }
            else
            {
                var target = new ScanTarget(provider, entryPaths);
                foreach (var rule in _rules)
                    findings.AddRange(rule.Inspect(target));

                unreadable = target.UnreadablePackages;
                if (unreadable > 0)
                    error = $"{unreadable} asset package(s) could not be read; analysis incomplete";
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
        finally
        {
            TryCleanup(stageDir);
        }

        // Analysis is complete only when nothing errored and every package was readable. An
        // incomplete analysis can never be Benign — a reachable-high finding still escalates to
        // FlaggedActive, otherwise an incomplete scan is Indeterminate (a blocking state).
        var complete = error is null;
        var verdict = VerdictPolicy.Decide(findings, analysisComplete: complete);

        return new ScanResult(pakPath, verdict, findings, error);
    }

    private static string StagePak(string pakPath, long maxBytes)
    {
        if (!File.Exists(pakPath))
            throw new FileNotFoundException("pak not found", pakPath);
        var size = new FileInfo(pakPath).Length;
        if (size > maxBytes)
            throw new InvalidOperationException(
                $"pak is {size} bytes, over the {maxBytes}-byte scan cap; refusing to ingest");
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
    private static readonly object _zlibLock = new();

    private static void EnsureZlib()
    {
        if (_zlibReady) return;
        lock (_zlibLock)
        {
            if (_zlibReady) return;
            // CUE4Parse needs the zlib-ng native lib to read Zlib-compressed pak entries (most real
            // paks). Without it, asset reads throw "Zlib decompression failed: not initialized" and
            // a compressed malicious asset would be silently missed — so a failure here must be
            // LOUD, not a silent degrade. Download it once (cached next to the executable) via
            // CUE4Parse's helper, then initialize. If this throws, Scan() surfaces it as an error
            // and the verdict becomes Indeterminate (never Benign). Only latch on success.
            var dllPath = Path.Combine(AppContext.BaseDirectory, ZlibHelper.DLL_NAME);
            if (!File.Exists(dllPath))
            {
                try
                {
                    ZlibHelper.DownloadDll(dllPath, ZlibHelper.DOWNLOAD_URL);
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException(
                        "zlib-ng native lib is missing and could not be downloaded; cannot read "
                        + "compressed paks (scan would be unreliable). Place "
                        + $"'{ZlibHelper.DLL_NAME}' next to the executable. Inner: {ex.Message}", ex);
                }
            }
            ZlibHelper.Initialize(dllPath);
            _zlibReady = true;
        }
    }
}
