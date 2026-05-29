using SSD_EXAM.AuditLogSystem.Core;

namespace SSD_EXAM.AuditLogSystem.Verification;

public class LogVerifier
{
    private readonly KeyManager _keyManager;

    public LogVerifier(KeyManager keyManager)
    {
        if (keyManager == null)
            throw new ArgumentNullException(nameof(keyManager));

        if (keyManager.KeyCount == 0)
            throw new ArgumentException("KeyManager must have at least one key.", nameof(keyManager));

        _keyManager = keyManager;
    }

    public bool VerifyIntegrity(List<LogEntry> entries)
    {
        if (entries == null)
            throw new ArgumentNullException(nameof(entries), "Entries list cannot be null.");

        try
        {
            if (!entries.Any())
                return true;

            string expectedPreviousHash = "0";

            foreach (var entry in entries)
            {
                if (entry.PrevHash != expectedPreviousHash)
                    return false;

                var keyVersion = _keyManager.GetKeyByVersion(entry.KeyVersion);
                if (keyVersion == null)
                    return false;

                string entryContent = CryptoUtil.BuildEntryContent(entry.Timestamp, entry.Event, entry.Data, entry.PrevHash);
                string computedHmac = CryptoUtil.ComputeHmac(entryContent, keyVersion.SecretKey);

                if (computedHmac != entry.Hmac)
                    return false;

                string computedHash = CryptoUtil.ComputeSha256(entryContent);
                if (computedHash != entry.Hash)
                    return false;

                expectedPreviousHash = entry.Hash;
            }

            return true;
        }
        catch (Exception ex)
        {
            throw new AuditLogException($"Error during integrity verification: {ex.Message}", ex);
        }
    }

    public VerificationReport VerifyWithReport(List<LogEntry> entries)
    {
        if (entries == null)
            throw new ArgumentNullException(nameof(entries), "Entries list cannot be null.");

        var report = new VerificationReport
        {
            TotalEntries = entries.Count,
            VerificationTime = DateTime.UtcNow
        };

        try
        {
            if (!entries.Any())
            {
                report.IsValid = true;
                report.ValidEntries = 0;
                report.InvalidEntries = 0;
                return report;
            }

            string expectedPreviousHash = "0";

            for (int i = 0; i < entries.Count; i++)
            {
                var entry = entries[i];
                var result = new EntryVerificationResult
                {
                    EntryIndex = i,
                    Timestamp = entry.Timestamp,
                    Event = entry.Event
                };

                if (entry.PrevHash != expectedPreviousHash)
                {
                    result.HashChainValid = false;
                    result.IsValid = false;
                    result.FailureReason = $"Hash chain broken: expected '{expectedPreviousHash}', got '{entry.PrevHash}'";
                    report.FailureReasons.Add($"Entry {i}: {result.FailureReason}");
                }
                else
                {
                    result.HashChainValid = true;
                }

                var keyVersion = _keyManager.GetKeyByVersion(entry.KeyVersion);
                if (keyVersion == null)
                {
                    result.HmacValid = false;
                    result.IsValid = false;
                    result.FailureReason = $"Key version {entry.KeyVersion} not found";
                    report.FailureReasons.Add($"Entry {i}: {result.FailureReason}");
                }
                else
                {
                    string entryContent = CryptoUtil.BuildEntryContent(entry.Timestamp, entry.Event, entry.Data, entry.PrevHash);
                    string computedHmac = CryptoUtil.ComputeHmac(entryContent, keyVersion.SecretKey);

                    if (computedHmac != entry.Hmac)
                    {
                        result.HmacValid = false;
                        result.IsValid = false;
                        result.FailureReason = "HMAC authentication failed: entry may be forged or tampered";
                        report.FailureReasons.Add($"Entry {i}: {result.FailureReason}");
                    }
                    else
                    {
                        result.HmacValid = true;
                    }

                    string computedHash = CryptoUtil.ComputeSha256(entryContent);
                    if (computedHash != entry.Hash)
                    {
                        result.HashComputationValid = false;
                        result.IsValid = false;
                        result.FailureReason = $"Hash mismatch: expected '{computedHash}', got '{entry.Hash}'";
                        report.FailureReasons.Add($"Entry {i}: {result.FailureReason}");
                    }
                    else
                    {
                        result.HashComputationValid = true;
                    }
                }
                
                if (!result.IsValid)
                {
                    result.IsValid = result.HashChainValid && result.HmacValid && result.HashComputationValid;
                }
                else
                {
                    result.IsValid = true;
                }

                report.EntryResults.Add(result);

                if (result.IsValid)
                    report.ValidEntries++;
                else
                    report.InvalidEntries++;

                expectedPreviousHash = entry.Hash;
            }

            report.IsValid = report.InvalidEntries == 0;
            return report;
        }
        catch (Exception ex)
        {
            throw new AuditLogException($"Error during detailed verification: {ex.Message}", ex);
        }
    }

    public bool VerifyEntry(LogEntry entry, string previousHash)
    {
        if (entry == null)
            throw new ArgumentNullException(nameof(entry), "Entry cannot be null.");
        
        if (previousHash == null)
            throw new ArgumentNullException(nameof(previousHash), "Previous hash cannot be null.");

        try
        {
            var keyVersion = _keyManager.GetKeyByVersion(entry.KeyVersion);
            if (keyVersion == null)
                return false;

            string entryContent = CryptoUtil.BuildEntryContent(entry.Timestamp, entry.Event, entry.Data, previousHash);
            string computedHmac = CryptoUtil.ComputeHmac(entryContent, keyVersion.SecretKey);
            string computedHash = CryptoUtil.ComputeSha256(entryContent);

            return entry.PrevHash == previousHash && entry.Hmac == computedHmac && entry.Hash == computedHash;
        }
        catch (Exception ex)
        {
            throw new AuditLogException($"Error during entry verification: {ex.Message}", ex);
        }
    }
}