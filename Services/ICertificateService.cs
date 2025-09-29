using ClientCertApp.Models;
using System.Security.Cryptography.X509Certificates;

namespace ClientCertApp.Services
{
    public interface ICertificateService
    {
        Task<List<LoadedCertificateInfo>> LoadCertificatesFromStoresAsync();
        X509Certificate2? GetCertificateFromStore(string thumbprint, string storeLocation, string storeName);
        ClientCertificateInfo? ProcessClientCertificate(X509Certificate2? clientCert);
        Task<CertificateTestResult> TestCertificateAsync(LoadedCertificateInfo certInfo, string testUrl);
    }
}