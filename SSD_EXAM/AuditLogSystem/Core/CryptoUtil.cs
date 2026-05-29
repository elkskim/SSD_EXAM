
using System.Security.Cryptography;
using System.Text;

namespace SSD_EXAM.AuditLogSystem.Core;

public static class CryptoUtil
{
    public static string ComputeSha256(string input)
    {
        using (var sha256 = SHA256.Create())
        {
            byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(hashedBytes).ToLower();
        }
    }

    public static string ComputeHmac(string data, string key)
    {
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
        {
            byte[] hashedBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            return Convert.ToHexString(hashedBytes).ToLower();
        }
    }
    
    public static string BuildEntryContent(DateTime timestamp, string @event, string data, string previousHash)
    {
        return $"{timestamp:O}|{@event}|{data}|{previousHash}";
    }
}