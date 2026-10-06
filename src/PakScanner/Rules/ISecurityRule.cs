using PakScanner.Findings;

namespace PakScanner.Rules;

/// <summary>A security rule inspects a parsed pak and reports findings.</summary>
public interface ISecurityRule
{
    IEnumerable<Finding> Inspect(ScanTarget target);
}
