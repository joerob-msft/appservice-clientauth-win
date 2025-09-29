using System.Security.Cryptography.X509Certificates;

namespace ClientCertApp.Models
{
    public class CertificateInfoViewModel
    {
        // Client certificate from request
        public bool HasClientCertificate { get; set; }
        public ClientCertificateInfo? ClientCertificate { get; set; }
        
        // Certificate validation results
        public CertificateValidationResult ValidationResult { get; set; } = new();
        
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
        
        // Add these properties for chain information
        public List<CertificateChainElement> ChainElements { get; set; } = new List<CertificateChainElement>();
        public bool ChainIsValid { get; set; }
        public List<string> ChainErrors { get; set; } = new List<string>();
        public int ChainLength => ChainElements.Count;
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

/* filepath: d:\github\appservice-clientauth-win\wwwroot\js\site.js */
// Initialize Bootstrap components when DOM is ready
document.addEventListener('DOMContentLoaded', function () {
    console.log('Site.js loaded successfully');
    
    // Initialize tooltips if any
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers if any
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Certificate details modal function
function showCertDetails(thumbprint) {
    var modalId = '#certModal-' + thumbprint;
    var modalElement = document.querySelector(modalId);
    
    if (modalElement) {
        var modal = new bootstrap.Modal(modalElement);
        modal.show();
    } else {
        console.error('Modal not found:', modalId);
        alert('Certificate details modal not found. Please refresh the page and try again.');
    }
}