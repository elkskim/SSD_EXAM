namespace SSD_EXAM.AuditLogSystem.Verification;

public class VerificationReport
{
    public bool IsValid { get; set; }

    public int TotalEntries { get; set; }

    public int ValidEntries { get; set; }

    public int InvalidEntries { get; set; }

    public List<EntryVerificationResult> EntryResults { get; set; } = new();

    public List<string> FailureReasons { get; set; } = new();

    public DateTime VerificationTime { get; set; }

    public string GetSummary()
    {
        var summary = new System.Text.StringBuilder();
        summary.AppendLine($"=== Verification Report ===");
        summary.AppendLine($"Status: {(IsValid ? "✓ VALID" : "✗ INVALID")}");
        summary.AppendLine($"Verified at: {VerificationTime:yyyy-MM-dd HH:mm:ss}");
        summary.AppendLine($"Total Entries: {TotalEntries}");
        summary.AppendLine($"Valid Entries: {ValidEntries}");
        summary.AppendLine($"Invalid Entries: {InvalidEntries}");

        if (FailureReasons.Count > 0)
        {
            summary.AppendLine("\nFailure Reasons:");
            foreach (var reason in FailureReasons)
            {
                summary.AppendLine($"  - {reason}");
            }
        }

        return summary.ToString();
    }
}

public class EntryVerificationResult
{
    public int EntryIndex { get; set; }

    public bool IsValid { get; set; }

    public DateTime Timestamp { get; set; }

    public string? Event { get; set; }

    public string FailureReason { get; set; } = string.Empty;

    public bool HashChainValid { get; set; }

    public bool HmacValid { get; set; }

    public bool HashComputationValid { get; set; }

    public override string ToString()
    {
        return $"Entry {EntryIndex} [{Timestamp:yyyy-MM-dd HH:mm:ss}] {Event}: {(IsValid ? "✓ VALID" : "✗ INVALID")}";
    }
}

