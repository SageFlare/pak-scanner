namespace PakScanner.Findings;

/// <summary>
/// A detected security concern. <paramref name="Reachable"/> distinguishes a capability that
/// would actually take effect (true -> contributes to Malicious) from a breach attempt that
/// would not (false -> Attempted).
/// </summary>
public record Finding(string Rule, string Path, Severity Severity, bool Reachable, string Evidence);
