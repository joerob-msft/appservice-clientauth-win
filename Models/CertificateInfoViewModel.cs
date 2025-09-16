namespace ClientCertApp.Models
{
    public class CertificateInfoViewModel
    {
        public bool HasCertificate { get; set; }
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public bool IsValid { get; set; }
        public int Version { get; set; }
        public string SignatureAlgorithm { get; set; } = string.Empty;
        public string PublicKeyAlgorithm { get; set; } = string.Empty;
        public int KeySize { get; set; }
        
        public bool ChainIsValid { get; set; }
        public List<string> ChainErrors { get; set; } = new List<string>();
        public string? ChainValidationError { get; set; }
        public List<CertificateChainElement> ChainElements { get; set; } = new List<CertificateChainElement>();
        public List<string> Extensions { get; set; } = new List<string>();
    }

    public class CertificateChainElement
    {
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
    }
}