using Xunit;

namespace PakScanner.Tests;

public class ScannerSmokeTests
{
    [Fact]
    public void Version_is_present() =>
        Assert.False(string.IsNullOrEmpty(PakScanner.Version.Current));
}
