namespace SSD_EXAM.AuditLogSystem.Core;

public class KeyManager
{
    private readonly List<KeyVersion> _keys;
    private KeyVersion? _activeKey;

    public KeyManager()
    {
        _keys = new List<KeyVersion>();
    }

    public void AddKey(string secretKey, int? version = null)
    {
        if (string.IsNullOrEmpty(secretKey))
            throw new ArgumentException("Secret key cannot be null or empty.", nameof(secretKey));

        // Auto-increment version if not provided
        int keyVersion = version ?? (_keys.Count + 1);

        // Check for duplicate versions
        if (_keys.Any(k => k.Version == keyVersion))
            throw new ArgumentException($"Key version {keyVersion} already exists.", nameof(version));

        var keyObj = new KeyVersion(keyVersion, secretKey, DateTime.UtcNow, isActive: true);

        // Mark previous active key as inactive
        if (_activeKey != null)
        {
            _activeKey.Rotate();
        }

        _keys.Add(keyObj);
        _activeKey = keyObj;
    }

    public KeyVersion GetActiveKey()
    {
        if (_activeKey == null)
            throw new InvalidOperationException("No active key available. Add a key first.");
        return _activeKey;
    }

    public List<KeyVersion> GetAllKeys()
    {
        return new List<KeyVersion>(_keys);
    }

    public KeyVersion? GetKeyByVersion(int version)
    {
        return _keys.FirstOrDefault(k => k.Version == version);
    }

    public void RotateKey(string newSecretKey)
    {
        AddKey(newSecretKey);
    }

    public int KeyCount => _keys.Count;

    public string GetKeySummary()
    {
        if (_keys.Count == 0)
            return "No keys configured.";

        var summary = new System.Text.StringBuilder();
        summary.AppendLine("=== Key Version Summary ===");
        foreach (var key in _keys.OrderBy(k => k.Version))
        {
            summary.AppendLine(key.ToString());
        }
        return summary.ToString();
    }
}

