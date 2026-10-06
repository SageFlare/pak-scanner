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
        sb.AppendLine($"Verdict: {result.Verdict.ToName()}");
        if (result.Error is not null)
            sb.AppendLine($"Parse error: {result.Error}");

        if (result.Findings.Count == 0)
        {
            sb.AppendLine("No findings.");
            return sb.ToString();
        }

        // Group by whether the behavior would execute as packaged (active) or is only present
        // in the file (latent). Neither label asserts intent — a human judges each concern.
        var active = result.Findings.Where(f => f.Reachable).ToList();
        var latent = result.Findings.Where(f => !f.Reachable).ToList();

        if (active.Count > 0)
        {
            sb.AppendLine($"Active (would execute on load) ({active.Count}):");
            foreach (var f in active)
                sb.AppendLine($"  [{f.Severity}] {f.Rule}: {f.Path} — {f.Evidence}");
        }
        if (latent.Count > 0)
        {
            sb.AppendLine($"Latent (present, not executing as packaged) ({latent.Count}):");
            foreach (var f in latent)
                sb.AppendLine($"  [{f.Severity}] {f.Rule}: {f.Path} — {f.Evidence}");
        }
        return sb.ToString();
    }
}
