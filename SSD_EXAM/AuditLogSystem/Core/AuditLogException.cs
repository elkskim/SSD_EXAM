namespace SSD_EXAM.AuditLogSystem.Core;

public class AuditLogException : Exception
{
    public AuditLogException(string message) : base(message) { }

    public AuditLogException(string message, Exception innerException) 
        : base(message, innerException) { }
}

