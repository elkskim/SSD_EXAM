namespace SSD_EXAM.AuditLogSystem.Core;

public class LogEntry
{
    public DateTime Timestamp { get; }
    public string Event { get; }
    public string Data { get; }
    public string PrevHash { get; }
    public string Hash { get; }
    public string Hmac { get; }
    
    public int KeyVersion { get; }
    
    public LogEntry(DateTime timestamp, string @event, string data, string prevHash, string hash, string hmac, int keyVersion = 1)
    {
        Timestamp = timestamp;
        Event = @event;
        Data = data;
        PrevHash = prevHash;
        Hash = hash;
        Hmac = hmac;
        KeyVersion = keyVersion;
    }

    public override string ToString()
    {
        return $"[{Timestamp:yyyy-MM-dd HH:mm:ss}] {Event} | Data: {Data} | Hash: {Hash} | KeyV{KeyVersion}";
    }
}