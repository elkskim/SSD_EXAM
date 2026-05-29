using SSD_EXAM.AuditLogSystem.Storage;

namespace SSD_EXAM.AuditLogSystem.Core;

public class AuditLog
{
    private readonly List<LogEntry> _entries;
    private readonly KeyManager _keyManager;
    private readonly string _storageFilePath;
    private readonly ILogStorage _storage;
    
    public AuditLog(KeyManager keyManager, ILogStorage storage, string storageFilePath)
    {
        _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));
        
        if (_keyManager.KeyCount == 0)
            throw new ArgumentException("KeyManager must have at least one key.", nameof(keyManager));
        
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _storageFilePath = storageFilePath ?? throw new ArgumentException("Storage path can't be null or empty", nameof(storageFilePath));
        
        try
        {
            _entries = _storage.LoadEntries(_storageFilePath);
        }
        catch (Exception ex)
        {
            throw new AuditLogException($"Failed to load audit log from '{_storageFilePath}'.", ex);
        }
    }
    
    public void Append(string @event, string data)
    {
        if (string.IsNullOrWhiteSpace(@event))
            throw new ArgumentException("Event type cannot be null or empty.", nameof(@event));
        
        if (data == null)
            throw new ArgumentNullException(nameof(data), "Data cannot be null (empty string is allowed).");
        
        try
        {
            string previousHash = _entries.Any() ? _entries.Last().Hash : "0";
            var timestamp = DateTime.UtcNow;
            string entryContent = CryptoUtil.BuildEntryContent(timestamp, @event, data, previousHash);
            string currentHash = CryptoUtil.ComputeSha256(entryContent);
            
            var activeKey = _keyManager.GetActiveKey();
            string hmac = CryptoUtil.ComputeHmac(entryContent, activeKey.SecretKey);

            var entry = new LogEntry(timestamp, @event, data, previousHash, currentHash, hmac, activeKey.Version);
            _entries.Add(entry);
            _storage.SaveEntries(_entries, _storageFilePath);
        }
        catch (AuditLogException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AuditLogException($"Failed to append entry with event '{@event}'.", ex);
        }
    }

    public string GetLastHash()
    {
        return _entries.Any() ? _entries.Last().Hash : "0";
    }

    public KeyManager GetKeyManager()
    {
        return _keyManager;
    }
}