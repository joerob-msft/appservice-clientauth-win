using System.Security.Cryptography.X509Certificates;

namespace ClientCertApp.Models
{
    public class CertificateInfoViewModel
    {
        // Client certificate from request
        public bool HasClientCertificate { get; set; }
        public ClientCertificateInfo? ClientCertificate { get; set; }
        
        // All loaded certificates from certificate store
        public List<LoadedCertificateInfo> LoadedCertificates { get; set; } = new List<LoadedCertificateInfo>();
        
        // Test results
        public string? TestResult { get; set; }
        public bool TestSuccessful { get; set; }
        public string? TestError { get; set; }
        
        // Configuration
        public string? TestUrl { get; set; }
    }

    public class ClientCertificateInfo
    {
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
        public List<string> ExtendedKeyUsages { get; set; } = new List<string>();
    }

    public class LoadedCertificateInfo
    {
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public bool IsValid { get; set; }
        public string StoreLocation { get; set; } = string.Empty;
        public string StoreName { get; set; } = string.Empty;
        public bool HasPrivateKey { get; set; }
        public List<string> ExtendedKeyUsages { get; set; } = new List<string>();
        public bool HasClientAuthenticationEKU { get; set; }
        public List<string> KeyUsages { get; set; } = new List<string>();
        public string FriendlyName { get; set; } = string.Empty;
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