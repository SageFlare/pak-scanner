namespace PakScanner.Findings;

/// <summary>
/// A detected security concern. <paramref name="Reachable"/> distinguishes a capability that
/// would execute as packaged (true -> contributes to FlaggedActive) from a capability that
/// is only present (false -> FlaggedLatent).
/// </summary>
public record Finding(string Rule, string Path, Severity Severity, bool Reachable, string Evidence);
