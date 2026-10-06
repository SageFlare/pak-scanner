using System.Text;
using PakScanner.Findings;

namespace PakScanner.Report;

/// <summary>Renders a <see cref="ScanResult"/> as a human-readable report.</summary>
public static class ReportRenderer
{
    public static string Render(ScanResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"PAK:     {result.Pak}");
        sb.AppendLine($"Verdict: {result.Verdict}");
        if (result.Error is not null)
            sb.AppendLine($"Parse error: {result.Error}");

        if (result.Findings.Count == 0)
        {
            sb.AppendLine("No findings.");
            return sb.ToString();
        }

        // Group by what the reader cares about: confirmed (reachable) vs attempts (not).
        var confirmed = result.Findings.Where(f => f.Reachable).ToList();
        var attempts = result.Findings.Where(f => !f.Reachable).ToList();

        if (confirmed.Count > 0)
        {
            sb.AppendLine($"Confirmed issues ({confirmed.Count}):");
            foreach (var f in confirmed)
                sb.AppendLine($"  [{f.Severity}] {f.Rule}: {f.Path} — {f.Evidence}");
        }
        if (attempts.Count > 0)
        {
            sb.AppendLine($"Attempts ({attempts.Count}):");
            foreach (var f in attempts)
                sb.AppendLine($"  [{f.Severity}] {f.Rule}: {f.Path} — {f.Evidence}");
        }
        return sb.ToString();
    }
}
