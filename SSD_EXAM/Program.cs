using SSD_EXAM.AuditLogSystem.Core;
using SSD_EXAM.AuditLogSystem.Storage;
using SSD_EXAM.AuditLogSystem.Verification;

var storage = new JsonLogStorage();
var keyManager = new KeyManager();
var logFilePath = "audit_log.json";

keyManager.AddKey("first-secret-key-v1-12345");

var auditLog = new AuditLog(keyManager, storage, logFilePath);

Console.WriteLine("=== Adding audit log entries with Key v1 ===");
auditLog.Append("USERLOGIN", "User 'Alice' logged in.");
auditLog.Append("FILE_ACCESSED", "User 'Alice' accessed 'report.pdf'.");
auditLog.Append("CONFIG_CHANGED", "Setting: security_level changed from LOW to HIGH");

Console.WriteLine("\n=== Current Key Configuration ===");
Console.WriteLine(keyManager.GetKeySummary());

Console.WriteLine("=== Rotating to a new key (simulating compromise scenario) ===");
keyManager.RotateKey("second-secret-key-v2-98765");
Console.WriteLine(keyManager.GetKeySummary());

Console.WriteLine("\n=== Adding entries with new Key v2 ===");
auditLog.Append("USERLOGIN", "User 'Bob' logged in.");
auditLog.Append("PERMISSION_GRANT", "User 'Bob' granted admin access.");

Console.WriteLine("\n=== Loading entries for verification ===");
var verifier = new LogVerifier(keyManager);
var entries = storage.LoadEntries(logFilePath);

Console.WriteLine("=== Detailed Verification Report ===");
var report = verifier.VerifyWithReport(entries);
Console.WriteLine(report.GetSummary());

Console.WriteLine("=== Entry-by-Entry Details (with Key Version Info) ===");
foreach (var result in report.EntryResults)
{
    var entry = entries.FirstOrDefault(e => e.Timestamp == result.Timestamp && e.Event == result.Event);
    if (entry != null)
    {
        Console.Write(result);
        Console.WriteLine($" [KeyV{entry.KeyVersion}]");
        if (!result.IsValid)
        {
            Console.WriteLine($"  Reason: {result.FailureReason}");
        }
    }
}

Console.WriteLine("\n=== Verifying audit log entries ===");
foreach (var entry in entries)
{
    Console.WriteLine(entry);
}

Console.WriteLine("\n=== Testing Tampering Detection (with Multi-Key Verification) ===");
Console.WriteLine("Attempting to tamper with entry signed with Key v1...\n");

if (entries.Count >= 2)
{
    var secondEntry = entries[1];
    var tamperedEntries = new List<LogEntry>(entries);
    
    var tamperedEntry = new LogEntry(
        secondEntry.Timestamp,
        secondEntry.Event,
        "TAMPERED DATA - Should fail verification!",
        secondEntry.PrevHash,
        secondEntry.Hash,
        secondEntry.Hmac,
        secondEntry.KeyVersion
    );
    tamperedEntries[1] = tamperedEntry;
    
    bool isTamperedValid = verifier.VerifyIntegrity(tamperedEntries);
    Console.WriteLine($"Quick check - Tampered log integrity: {(isTamperedValid ? "✓ VALID" : "✗ INVALID - TAMPERING DETECTED!")}\n");

    Console.WriteLine("=== Detailed Tamper Analysis Report ===");
    var tamperedReport = verifier.VerifyWithReport(tamperedEntries);
    Console.WriteLine(tamperedReport.GetSummary());

    Console.WriteLine("=== Entry-by-Entry Analysis ===");
    foreach (var result in tamperedReport.EntryResults)
    {
        var entry = tamperedEntries.FirstOrDefault(e => e.Timestamp == result.Timestamp && e.Event == result.Event);
        if (entry != null)
        {
            Console.Write(result);
            Console.WriteLine($" [KeyV{entry.KeyVersion}]");
            if (!result.IsValid)
            {
                Console.WriteLine($"  Reason: {result.FailureReason}");
            }
        }
    }
}
