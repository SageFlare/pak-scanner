using PakScanner.Findings;
using Xunit;

namespace PakScanner.Tests;

public class VerdictTests
{
    [Fact]
    public void No_findings_is_benign() =>
        Assert.Equal(Verdict.Benign, VerdictPolicy.Decide(Array.Empty<Finding>()));

    [Fact]
    public void Reachable_high_is_malicious() =>
        Assert.Equal(
            Verdict.Malicious,
            VerdictPolicy.Decide(new[] { new Finding("r", "p", Severity.High, true, "e") }));

    [Fact]
    public void Unreachable_attempt_is_attempted() =>
        Assert.Equal(
            Verdict.Attempted,
            VerdictPolicy.Decide(new[] { new Finding("r", "p", Severity.High, false, "e") }));

    [Fact]
    public void Low_reachable_is_attempted_not_malicious() =>
        Assert.Equal(
            Verdict.Attempted,
            VerdictPolicy.Decide(new[] { new Finding("r", "p", Severity.Low, true, "e") }));
}
