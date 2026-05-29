using System.Text.Json;
using SSD_EXAM.AuditLogSystem.Core;

namespace SSD_EXAM.AuditLogSystem.Storage;

public class JsonLogStorage : ILogStorage
{
    public void SaveEntries(List<LogEntry> entries, string filePath)
    {
        if (entries == null)
            throw new ArgumentNullException(nameof(entries));
        
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

        try
        {
            var options = new JsonSerializerOptions {WriteIndented = true};
            string json = JsonSerializer.Serialize(entries, options);
            File.WriteAllText(filePath, json);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new AuditLogException($"Access denied: Cannot write to file '{filePath}'. Check file permissions.", ex);
        }
        catch (DirectoryNotFoundException ex)
        {
            throw new AuditLogException($"Directory not found for path '{filePath}'.", ex);
        }
        catch (IOException ex)
        {
            throw new AuditLogException($"I/O error while writing to '{filePath}': {ex.Message}", ex);
        }
        catch (Exception ex)
        {
            throw new AuditLogException($"Failed to save audit log entries to '{filePath}'.", ex);
        }
    }
    
    public List<LogEntry> LoadEntries(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));

        try
        {
            if (!File.Exists(filePath))
                return new List<LogEntry>();

            string json = File.ReadAllText(filePath);
            
            if (string.IsNullOrWhiteSpace(json))
                return new List<LogEntry>();

            var entries = JsonSerializer.Deserialize<List<LogEntry>>(json);
            return entries ?? new List<LogEntry>();
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new AuditLogException($"Access denied: Cannot read file '{filePath}'. Check file permissions.", ex);
        }
        catch (FileNotFoundException ex)
        {
            throw new AuditLogException($"File not found: '{filePath}'.", ex);
        }
        catch (JsonException ex)
        {
            throw new AuditLogException($"Invalid JSON format in '{filePath}'. File may be corrupted.", ex);
        }
        catch (IOException ex)
        {
            throw new AuditLogException($"I/O error while reading from '{filePath}': {ex.Message}", ex);
        }
        catch (Exception ex)
        {
            throw new AuditLogException($"Failed to load audit log entries from '{filePath}'.", ex);
        }
    }
}