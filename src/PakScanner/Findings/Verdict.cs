namespace PakScanner.Findings;

public enum Verdict { Benign, Attempted, Malicious }

public enum Severity { Low, Medium, High }

public static class VerdictPolicy
{
    /// <summary>
    /// A reachable high-severity finding means a breach that would take effect: Malicious.
    /// Any other finding means an attempt that would not take effect: Attempted.
    /// No findings: Benign.
    /// </summary>
    public static Verdict Decide(IEnumerable<Finding> findings)
    {
        var list = findings.ToList();
        if (list.Any(f => f.Reachable && f.Severity == Severity.High)) return Verdict.Malicious;
        return list.Count > 0 ? Verdict.Attempted : Verdict.Benign;
    }
}
