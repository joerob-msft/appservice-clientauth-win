using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using ClientCertApp.Models;

namespace ClientCertApp.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            var model = new CertificateInfoViewModel();

            // Process client certificate from request
            ProcessClientCertificate(model);
            
            // Get all loaded certificates from certificate stores
            LoadCertificatesFromStores(model);

            return View(model);
        }

        [HttpPost]
        public IActionResult TestClientCertificate(string thumbprint)
        {
            var model = new CertificateInfoViewModel();
            
            // Process client certificate from request
            ProcessClientCertificate(model);
            
            // Get all loaded certificates from certificate stores
            LoadCertificatesFromStores(model);

            // Find the certificate to test
            var certToTest = model.LoadedCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
            
            if (certToTest == null)
            {
                model.TestError = "Certificate not found";
                model.TestSuccessful = false;
            }
            else
            {
                // Test the certificate
                TestCertificateClientAuth(certToTest, model);
            }

            return View("Index", model);
        }

        private void ProcessClientCertificate(CertificateInfoViewModel model)
        {
            var clientCert = HttpContext.Connection.ClientCertificate;

            if (clientCert != null)
            {
                model.HasClientCertificate = true;
                model.ClientCertificate = new ClientCertificateInfo
                {
                    Subject = clientCert.Subject,
                    Issuer = clientCert.Issuer,
                    Thumbprint = clientCert.Thumbprint,
                    SerialNumber = clientCert.SerialNumber,
                    NotBefore = clientCert.NotBefore,
                    NotAfter = clientCert.NotAfter,
                    IsValid = DateTime.Now >= clientCert.NotBefore && DateTime.Now <= clientCert.NotAfter,
                    Version = clientCert.Version,
                    SignatureAlgorithm = clientCert.SignatureAlgorithm.FriendlyName ?? "Unknown",
                    PublicKeyAlgorithm = clientCert.PublicKey.Oid.FriendlyName ?? "Unknown"
                };

                // Get key size
                if (clientCert.PublicKey.Oid.FriendlyName == "RSA")
                {
                    using var rsa = clientCert.GetRSAPublicKey();
                    model.ClientCertificate.KeySize = rsa?.KeySize ?? 0;
                }
                else if (clientCert.PublicKey.Oid.FriendlyName == "DSA")
                {
                    using var dsa = clientCert.GetDSAPublicKey();
                    model.ClientCertificate.KeySize = dsa?.KeySize ?? 0;
                }
                else if (clientCert.PublicKey.Oid.FriendlyName == "ECDSA")
                {
                    using var ecdsa = clientCert.GetECDsaPublicKey();
                    model.ClientCertificate.KeySize = ecdsa?.KeySize ?? 0;
                }

                // Get certificate chain validation details
                try
                {
                    var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    
                    model.ClientCertificate.ChainIsValid = chain.Build(clientCert);
                    
                    if (!model.ClientCertificate.ChainIsValid)
                    {
                        model.ClientCertificate.ChainErrors = new List<string>();
                        foreach (X509ChainStatus status in chain.ChainStatus)
                        {
                            model.ClientCertificate.ChainErrors.Add($"{status.Status}: {status.StatusInformation}");
                        }
                    }

                    // Get chain information
                    model.ClientCertificate.ChainElements = new List<CertificateChainElement>();
                    foreach (X509ChainElement element in chain.ChainElements)
                    {
                        model.ClientCertificate.ChainElements.Add(new CertificateChainElement
                        {
                            Subject = element.Certificate.Subject,
                            Issuer = element.Certificate.Issuer,
                            Thumbprint = element.Certificate.Thumbprint,
                            NotBefore = element.Certificate.NotBefore,
                            NotAfter = element.Certificate.NotAfter
                        });
                    }
                }
                catch (Exception ex)
                {
                    model.ClientCertificate.ChainValidationError = ex.Message;
                }

                // Extensions and Extended Key Usage
                model.ClientCertificate.Extensions = new List<string>();
                model.ClientCertificate.ExtendedKeyUsages = new List<string>();
                
                foreach (X509Extension extension in clientCert.Extensions)
                {
                    model.ClientCertificate.Extensions.Add($"{extension.Oid?.FriendlyName ?? extension.Oid?.Value ?? "Unknown"}: {extension.Format(false)}");
                    
                    // Check for Extended Key Usage
                    if (extension.Oid?.Value == "2.5.29.37") // Extended Key Usage OID
                    {
                        var eku = extension as X509EnhancedKeyUsageExtension;
                        if (eku != null)
                        {
                            foreach (var usage in eku.EnhancedKeyUsages)
                            {
                                model.ClientCertificate.ExtendedKeyUsages.Add(usage.FriendlyName ?? usage.Value ?? "Unknown");
                            }
                        }
                    }
                }
            }
        }

        private void LoadCertificatesFromStores(CertificateInfoViewModel model)
        {
            // Check multiple certificate stores where WEBSITE_LOAD_CERTIFICATES might load certificates
            var storesToCheck = new[]
            {
                new { Location = StoreLocation.CurrentUser, Name = StoreName.My },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.My },
                new { Location = StoreLocation.CurrentUser, Name = StoreName.Root },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.Root },
                new { Location = StoreLocation.CurrentUser, Name = StoreName.CertificateAuthority },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.CertificateAuthority }
            };

            foreach (var storeInfo in storesToCheck)
            {
                try
                {
                    using var store = new X509Store(storeInfo.Name, storeInfo.Location);
                    store.Open(OpenFlags.ReadOnly);

                    foreach (X509Certificate2 cert in store.Certificates)
                    {
                        var certInfo = new LoadedCertificateInfo
                        {
                            Subject = cert.Subject,
                            Issuer = cert.Issuer,
                            Thumbprint = cert.Thumbprint,
                            SerialNumber = cert.SerialNumber,
                            NotBefore = cert.NotBefore,
                            NotAfter = cert.NotAfter,
                            IsValid = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter,
                            StoreLocation = storeInfo.Location.ToString(),
                            StoreName = storeInfo.Name.ToString(),
                            HasPrivateKey = cert.HasPrivateKey,
                            FriendlyName = cert.FriendlyName ?? ""
                        };

                        // Get Extended Key Usage and Key Usage
                        foreach (X509Extension extension in cert.Extensions)
                        {
                            if (extension.Oid?.Value == "2.5.29.37") // Extended Key Usage
                            {
                                var eku = extension as X509EnhancedKeyUsageExtension;
                                if (eku != null)
                                {
                                    foreach (var usage in eku.EnhancedKeyUsages)
                                    {
                                        var friendlyName = usage.FriendlyName ?? usage.Value ?? "Unknown";
                                        certInfo.ExtendedKeyUsages.Add(friendlyName);
                                        
                                        // Check for Client Authentication EKU (1.3.6.1.5.5.7.3.2)
                                        if (usage.Value == "1.3.6.1.5.5.7.3.2")
                                        {
                                            certInfo.HasClientAuthenticationEKU = true;
                                        }
                                    }
                                }
                            }
                            else if (extension.Oid?.Value == "2.5.29.15") // Key Usage
                            {
                                var keyUsage = extension as X509KeyUsageExtension;
                                if (keyUsage != null)
                                {
                                    var usages = keyUsage.KeyUsages;
                                    if ((usages & X509KeyUsageFlags.DigitalSignature) != 0)
                                        certInfo.KeyUsages.Add("Digital Signature");
                                    if ((usages & X509KeyUsageFlags.KeyEncipherment) != 0)
                                        certInfo.KeyUsages.Add("Key Encipherment");
                                    if ((usages & X509KeyUsageFlags.DataEncipherment) != 0)
                                        certInfo.KeyUsages.Add("Data Encipherment");
                                    if ((usages & X509KeyUsageFlags.KeyAgreement) != 0)
                                        certInfo.KeyUsages.Add("Key Agreement");
                                    if ((usages & X509KeyUsageFlags.KeyCertSign) != 0)
                                        certInfo.KeyUsages.Add("Certificate Signing");
                                    if ((usages & X509KeyUsageFlags.CrlSign) != 0)
                                        certInfo.KeyUsages.Add("CRL Signing");
                                    if ((usages & X509KeyUsageFlags.NonRepudiation) != 0)
                                        certInfo.KeyUsages.Add("Non-Repudiation");
                                    if ((usages & X509KeyUsageFlags.DecipherOnly) != 0)
                                        certInfo.KeyUsages.Add("Decipher Only");
                                    if ((usages & X509KeyUsageFlags.EncipherOnly) != 0)
                                        certInfo.KeyUsages.Add("Encipher Only");
                                }
                            }
                        }

                        model.LoadedCertificates.Add(certInfo);
                    }
                }
                catch (Exception)
                {
                    // Store might not be accessible, skip it
                    continue;
                }
            }

            // Remove duplicates based on thumbprint
            model.LoadedCertificates = model.LoadedCertificates
                .GroupBy(c => c.Thumbprint)
                .Select(g => g.First())
                .OrderBy(c => c.Subject)
                .ToList();
        }

        private void TestCertificateClientAuth(LoadedCertificateInfo certInfo, CertificateInfoViewModel model)
        {
            try
            {
                // Check if certificate has Client Authentication EKU
                if (!certInfo.HasClientAuthenticationEKU)
                {
                    model.TestError = $"Certificate '{certInfo.Subject}' does not have Client Authentication Extended Key Usage (1.3.6.1.5.5.7.3.2). " +
                                     $"Available EKUs: {string.Join(", ", certInfo.ExtendedKeyUsages)}";
                    model.TestSuccessful = false;
                    return;
                }

                // Check if certificate has private key
                if (!certInfo.HasPrivateKey)
                {
                    model.TestError = $"Certificate '{certInfo.Subject}' does not have a private key accessible.";
                    model.TestSuccessful = false;
                    return;
                }

                // Check if certificate is valid (not expired)
                if (!certInfo.IsValid)
                {
                    model.TestError = $"Certificate '{certInfo.Subject}' is not currently valid (expired or not yet valid). " +
                                     $"Valid from {certInfo.NotBefore:yyyy-MM-dd} to {certInfo.NotAfter:yyyy-MM-dd}";
                    model.TestSuccessful = false;
                    return;
                }

                // Simulate a successful client certificate operation
                // In a real implementation, this would make an actual HTTPS call using the certificate
                model.TestResult = $"✅ Certificate '{certInfo.Subject}' successfully passed client authentication validation!\n\n" +
                                  $"Certificate Details:\n" +
                                  $"- Thumbprint: {certInfo.Thumbprint}\n" +
                                  $"- Has Client Authentication EKU: Yes\n" +
                                  $"- Has Private Key: Yes\n" +
                                  $"- Valid Until: {certInfo.NotAfter:yyyy-MM-dd HH:mm:ss}\n" +
                                  $"- Store: {certInfo.StoreName} ({certInfo.StoreLocation})\n\n" +
                                  $"🔧 This is a simulated test. In a real scenario, this would:\n" +
                                  $"1. Create an HttpClient with the certificate attached\n" +
                                  $"2. Make an HTTPS request to a server requiring client certificates\n" +
                                  $"3. Verify the server accepts the certificate for authentication";
                
                model.TestSuccessful = true;
            }
            catch (Exception ex)
            {
                model.TestError = $"Error testing certificate: {ex.Message}";
                model.TestSuccessful = false;
            }
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}