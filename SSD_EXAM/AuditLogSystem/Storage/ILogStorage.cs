using SSD_EXAM.AuditLogSystem.Core;

namespace SSD_EXAM.AuditLogSystem.Storage;

public interface ILogStorage
{
    void SaveEntries(List<LogEntry> entries, string filePath);
    List<LogEntry> LoadEntries(string filePath);
}