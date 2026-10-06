namespace PakScanner.Findings;

/// <summary>
/// What the scanner concluded about a pak. These describe DETECTED BEHAVIOR and whether it
/// would execute — not intent. A flagged pak is a concern for a human to judge (e.g. a URL
/// launch could be a legit server-rules link or a malicious redirect); the scanner does not
/// claim to know which.
/// </summary>
public enum Verdict
{
    /// <summary>No risky behavior detected and the pak was fully analyzed.</summary>
    Benign,

    /// <summary>A risky capability is present in the pak but would not execute as packaged.</summary>
    FlaggedLatent,

    /// <summary>A risky behavior would execute when the mod loads.</summary>
    FlaggedActive,

    /// <summary>
    /// The pak could not be fully analyzed (parse failure, or one or more assets were unreadable).
    /// An untrusted input the scanner cannot see into must NOT be treated as safe — this is a
    /// blocking state, never Benign.
    /// </summary>
    Indeterminate,
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
        Verdict.Indeterminate => "indeterminate",
        _ => "unknown",
    };
}

public static class VerdictPolicy
{
    /// <summary>
    /// Decides a verdict from findings and whether analysis was complete.
    /// A reachable high-severity finding means the behavior would execute on load: FlaggedActive.
    /// Any other finding means a capability present but not (known to be) executing: FlaggedLatent.
    /// If analysis was incomplete (parse error or unreadable assets) and nothing was already
    /// flagged active, the result is Indeterminate — never Benign — so an untrusted pak the
    /// scanner could not see into is not passed off as safe.
    /// </summary>
    public static Verdict Decide(IEnumerable<Finding> findings, bool analysisComplete = true)
    {
        var list = findings.ToList();
        if (list.Any(f => f.Reachable && f.Severity == Severity.High)) return Verdict.FlaggedActive;
        if (!analysisComplete) return Verdict.Indeterminate;
        return list.Count > 0 ? Verdict.FlaggedLatent : Verdict.Benign;
    }
}
