using PakScanner;
using PakScanner.Findings;
using PakScanner.Rules;
using Xunit;

namespace PakScanner.Tests;

public class ScannerScanTests
{
    // pak-corpus is a sibling repo. BaseDirectory is
    // <...>/pak-scanner/tests/PakScanner.Tests/bin/Debug/net8.0 -> up 6 to the workspace root,
    // then into pak-corpus/samples.
    private static string CorpusSample(string name) =>
        Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..",
            "pak-corpus", "samples", name));

    [Fact]
    public void Benign_map_scans_benign()
    {
        var pak = CorpusSample("benign_map.pak");
        Assert.True(File.Exists(pak), $"corpus sample missing: {pak}");
        var scanner = new SecurityScanner(Array.Empty<ISecurityRule>());
        var result = scanner.Scan(pak);
        Assert.Null(result.Error);
        Assert.Equal(Verdict.Benign, result.Verdict);
    }

    [Fact]
    public void Garbage_file_is_handled_not_thrown()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"paktest_{Guid.NewGuid():N}.pak");
        File.WriteAllBytes(tmp, new byte[] { 1, 2, 3, 4, 5 });
        try
        {
            var result = new SecurityScanner(Array.Empty<ISecurityRule>()).Scan(tmp);
            // A malformed pak must not throw; it yields a result (error recorded).
            Assert.NotNull(result);
        }
        finally
        {
            File.Delete(tmp);
        }
    }
}
