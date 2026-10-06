namespace PakScanner.Findings;

public record ScanResult(string Pak, Verdict Verdict, IReadOnlyList<Finding> Findings, string? Error);
