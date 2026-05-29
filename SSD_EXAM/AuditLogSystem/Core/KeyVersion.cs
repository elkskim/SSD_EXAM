namespace SSD_EXAM.AuditLogSystem.Core;

public class KeyVersion
{
    public int Version { get; set; }

    public string SecretKey { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime? RotatedAt { get; set; }

    public bool IsActive { get; set; }

    public KeyVersion(int version, string secretKey, DateTime createdAt, bool isActive = false)
    {
        if (string.IsNullOrEmpty(secretKey))
            throw new ArgumentException("Secret key cannot be null or empty.", nameof(secretKey));

        if (secretKey.Length < 16)
            throw new ArgumentException("Secret key must be at least 16 characters for security.", nameof(secretKey));

        Version = version;
        SecretKey = secretKey;
        CreatedAt = createdAt;
        IsActive = isActive;
        RotatedAt = null;
    }

    public void Rotate()
    {
        IsActive = false;
        RotatedAt = DateTime.UtcNow;
    }

    public override string ToString()
    {
        string status = IsActive ? "ACTIVE" : (RotatedAt.HasValue ? "ROTATED" : "INACTIVE");
        return $"Key v{Version} ({status}) - Created: {CreatedAt:yyyy-MM-dd HH:mm:ss}" +
               (RotatedAt.HasValue ? $", Rotated: {RotatedAt:yyyy-MM-dd HH:mm:ss}" : "");
    }
}

