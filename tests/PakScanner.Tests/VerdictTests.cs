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
            Verdict.FlaggedActive,
            VerdictPolicy.Decide(new[] { new Finding("r", "p", Severity.High, true, "e") }));

    [Fact]
    public void Unreachable_attempt_is_attempted() =>
        Assert.Equal(
            Verdict.FlaggedLatent,
            VerdictPolicy.Decide(new[] { new Finding("r", "p", Severity.High, false, "e") }));

    [Fact]
    public void Low_reachable_is_attempted_not_malicious() =>
        Assert.Equal(
            Verdict.FlaggedLatent,
            VerdictPolicy.Decide(new[] { new Finding("r", "p", Severity.Low, true, "e") }));

    [Fact]
    public void Incomplete_analysis_with_no_findings_is_indeterminate_not_benign() =>
        // C3/C4 regression: a parse failure or unreadable asset must not pass as Benign.
        Assert.Equal(
            Verdict.Indeterminate,
            VerdictPolicy.Decide(Array.Empty<Finding>(), analysisComplete: false));

    [Fact]
    public void Incomplete_analysis_still_escalates_a_reachable_high_finding() =>
        // If we DID find an active threat, incompleteness doesn't downgrade it.
        Assert.Equal(
            Verdict.FlaggedActive,
            VerdictPolicy.Decide(new[] { new Finding("r", "p", Severity.High, true, "e") }, analysisComplete: false));
}
