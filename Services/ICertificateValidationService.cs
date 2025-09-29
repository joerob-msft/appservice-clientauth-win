using ClientCertApp.Models;
using System.Security.Cryptography.X509Certificates;

namespace ClientCertApp.Services
{
    public interface ICertificateValidationService
    {
        CertificateValidationResult ValidateClientCertificate(X509Certificate2? certificate);
    }
}