namespace ClientCertApp.Models
{
    public class CertificateValidationResult
    {
        public bool HasCertificate { get; set; }
        public string Subject { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        
        // Validation results
        public CertificateValidationStatus OverallStatus { get; set; }
        public List<ValidationIssue> ValidationIssues { get; set; } = new();
        public int CriticalIssuesCount { get; set; }
        public int WarningIssuesCount { get; set; }
        
        // Specific validation flags
        public bool IsDateValid { get; set; }
        public bool IsChainValid { get; set; }
        public bool IsRevocationValid { get; set; }
        public bool HasKeyUsage { get; set; }
        public bool HasExtendedKeyUsage { get; set; }
        public bool HasClientAuthEKU { get; set; }
        public bool HasSubjectAlternativeName { get; set; }
        
        // Certificate details
        public string KeyAlgorithm { get; set; } = string.Empty;
        public int KeySize { get; set; }
        public string SignatureAlgorithm { get; set; } = string.Empty;
        public List<string> ExtendedKeyUsages { get; set; } = new();
        public int ChainLength { get; set; }
        public List<ChainElementInfo> ChainElements { get; set; } = new();
        public int CriticalExtensionsCount { get; set; }

        public static CertificateValidationResult NoCertificate()
        {
            return new CertificateValidationResult
            {
                HasCertificate = false,
                OverallStatus = CertificateValidationStatus.NoCertificate
            };
        }
    }

    public enum CertificateValidationStatus
    {
        NoCertificate,
        Valid,
        ValidWithWarnings,
        Invalid
    }

    public enum ValidationSeverity
    {
        Info,
        Warning,
        Critical
    }

    public class ValidationIssue
    {
        public ValidationSeverity Severity { get; set; }
        public string Category { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    public class ChainElementInfo
    {
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public bool IsRoot { get; set; }
    }
}