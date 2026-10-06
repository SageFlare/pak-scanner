namespace PakScanner.Findings;

/// <summary>
/// What the scanner concluded about a pak. These describe DETECTED BEHAVIOR and whether it
/// would execute — not intent. A flagged pak is a concern for a human to judge (e.g. a URL
/// launch could be a legit server-rules link or a malicious redirect); the scanner does not
/// claim to know which.
/// </summary>
public enum Verdict
{
    /// <summary>No risky behavior detected.</summary>
    Benign,

    /// <summary>A risky capability is present in the pak but would not execute as packaged.</summary>
    FlaggedLatent,

    /// <summary>A risky behavior would execute when the mod loads.</summary>
    FlaggedActive,
}

public enum Severity { Low, Medium, High }

public static class VerdictNames
{
    /// <summary>Canonical lowercase/hyphenated name, matching the corpus manifest states.</summary>
    public static string ToName(this Verdict v) => v switch
    {
        Verdict.Benign => "benign",
        Verdict.FlaggedLatent => "flagged-latent",
        Verdict.FlaggedActive => "flagged-active",
        _ => "unknown",
    };
}

public static class VerdictPolicy
{
    /// <summary>
    /// A reachable high-severity finding means the behavior would execute on load: FlaggedActive.
    /// Any other finding means a capability present but not (known to be) executing: FlaggedLatent.
    /// No findings: Benign.
    /// </summary>
    public static Verdict Decide(IEnumerable<Finding> findings)
    {
        var list = findings.ToList();
        if (list.Any(f => f.Reachable && f.Severity == Severity.High)) return Verdict.FlaggedActive;
        return list.Count > 0 ? Verdict.FlaggedLatent : Verdict.Benign;
    }
}
