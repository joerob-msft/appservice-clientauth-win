using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using ClientCertApp.Models;
using System.Text;
using System.Net.Security;
using System.Security.Authentication;

namespace ClientCertApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<HomeController> _logger;

        public HomeController(IConfiguration configuration, ILogger<HomeController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public IActionResult Index()
        {
            var model = new CertificateInfoViewModel();
            
            // Set the test URL from configuration
            model.TestUrl = _configuration["ClientCertificateTestUrl"];

            // Process client certificate from request
            ProcessClientCertificate(model);
            
            // Get all loaded certificates from certificate stores
            LoadCertificatesFromStores(model);

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> TestClientCertificate(string thumbprint)
        {
            _logger.LogInformation($"🔍 TestClientCertificate POST called with thumbprint: '{thumbprint}'");
            
            var model = new CertificateInfoViewModel();
            
            // Set the test URL from configuration
            model.TestUrl = _configuration["ClientCertificateTestUrl"];
            _logger.LogInformation($"🔧 Test URL configured: '{model.TestUrl ?? "null"}'");
            
            // Process client certificate from request
            ProcessClientCertificate(model);
            
            // Get all loaded certificates from certificate stores
            LoadCertificatesFromStores(model);
            
            _logger.LogInformation($"📊 Loaded {model.LoadedCertificates.Count} certificates total");

            // Find the certificate to test
            var certToTest = model.LoadedCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
            
            if (certToTest == null)
            {
                _logger.LogWarning($"❌ Certificate not found with thumbprint: '{thumbprint}'");
                _logger.LogInformation($"📋 Available thumbprints:");
                foreach (var cert in model.LoadedCertificates.Take(10)) // Show first 10
                {
                    _logger.LogInformation($"   - '{cert.Thumbprint}' ({cert.Subject.Substring(0, Math.Min(50, cert.Subject.Length))})");
                }
                if (model.LoadedCertificates.Count > 10)
                {
                    _logger.LogInformation($"   ... and {model.LoadedCertificates.Count - 10} more certificates");
                }
                
                model.TestError = $"Certificate not found with thumbprint: {thumbprint}";
                model.TestSuccessful = false;
                _logger.LogInformation($"🔍 Set TestError: '{model.TestError}'");
            }
            else
            {
                _logger.LogInformation($"✅ Found certificate to test: '{certToTest.Subject}'");
                _logger.LogInformation($"   Thumbprint: '{certToTest.Thumbprint}'");
                _logger.LogInformation($"   HasPrivateKey: {certToTest.HasPrivateKey}");
                _logger.LogInformation($"   StoreLocation: {certToTest.StoreLocation}");
                _logger.LogInformation($"   StoreName: {certToTest.StoreName}");
                
                // Test the certificate
                try
                {
                    _logger.LogInformation($"🚀 About to call TestCertificateClientAuthAsync...");
                    await TestCertificateClientAuthAsync(certToTest, model);
                    _logger.LogInformation($"✅ TestCertificateClientAuthAsync completed");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"❌ Exception in TestCertificateClientAuthAsync");
                    model.TestError = $"Exception during certificate test: {ex.Message}";
                    model.TestSuccessful = false;
                }
            }

            // 🚨 CRITICAL DEBUG: Log the final model state
            _logger.LogInformation($"🔍 FINAL MODEL STATE:");
            _logger.LogInformation($"   TestResult: {(string.IsNullOrEmpty(model.TestResult) ? "NULL/EMPTY" : $"SET ({model.TestResult.Length} chars)")}");
            _logger.LogInformation($"   TestError: {(string.IsNullOrEmpty(model.TestError) ? "NULL/EMPTY" : $"SET ({model.TestError.Length} chars)")}");
            _logger.LogInformation($"   TestSuccessful: {model.TestSuccessful}");
            _logger.LogInformation($"   TestUrl: '{model.TestUrl ?? "NULL"}'");
            
            // Also set a simple test message to ensure the view condition works
            if (string.IsNullOrEmpty(model.TestResult) && string.IsNullOrEmpty(model.TestError))
            {
                _logger.LogWarning($"⚠️ Both TestResult and TestError are empty! Setting fallback message.");
                model.TestError = "DEBUG: Test completed but no result was set. Check logs for details.";
                _logger.LogInformation($"🔍 Set fallback TestError: '{model.TestError}'");
            }

            _logger.LogInformation($"🏁 Returning view with model");
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
            _logger.LogInformation("📚 Loading certificates from certificate stores...");
            
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
                    
                    _logger.LogInformation($"📂 Checking store: {storeInfo.Name} ({storeInfo.Location}) - Found {store.Certificates.Count} certificates");

                    foreach (X509Certificate2 cert in store.Certificates)
                    {
                        _logger.LogDebug($"📜 Processing certificate: {cert.Subject}, HasPrivateKey: {cert.HasPrivateKey}, Thumbprint: {cert.Thumbprint}");
                        
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
                catch (Exception ex)
                {
                    // Store might not be accessible, skip it
                    _logger.LogWarning(ex, $"⚠️ Could not access certificate store: {storeInfo.Name} ({storeInfo.Location})");
                    continue;
                }
            }

            // Remove duplicates based on thumbprint
            var uniqueCerts = model.LoadedCertificates
                .GroupBy(c => c.Thumbprint)
                .Select(g => g.First())
                .OrderBy(c => c.Subject)
                .ToList();
            
            model.LoadedCertificates = uniqueCerts;
            
            _logger.LogInformation($"✅ Loaded {model.LoadedCertificates.Count} unique certificates, {model.LoadedCertificates.Count(c => c.HasPrivateKey)} have private keys");
        }

        private async Task TestCertificateClientAuthAsync(LoadedCertificateInfo certInfo, CertificateInfoViewModel model)
        {
            _logger.LogInformation($"🧪 Starting certificate test for: '{certInfo.Subject}'");
            
            var testUrl = model.TestUrl;
            
            if (string.IsNullOrEmpty(testUrl))
            {
                _logger.LogWarning("❌ Test URL is not configured");
                model.TestError = "ClientCertificateTestUrl is not configured in application settings.";
                model.TestSuccessful = false;
                _logger.LogInformation($"🔍 Set TestError due to missing URL: '{model.TestError}'");
                return;
            }

            try
            {
                _logger.LogInformation($"🔑 Loading certificate from store...");
                // Load the actual certificate from the store for the HTTP call
                var certificate = GetCertificateFromStore(certInfo.Thumbprint, certInfo.StoreLocation, certInfo.StoreName);
                
                if (certificate == null)
                {
                    _logger.LogError($"❌ Could not load certificate from store: '{certInfo.Subject}'");
                    model.TestError = $"Could not load certificate from store: {certInfo.Subject}";
                    model.TestSuccessful = false;
                    _logger.LogInformation($"🔍 Set TestError due to cert load failure: '{model.TestError}'");
                    return;
                }

                _logger.LogInformation($"✅ Successfully loaded certificate from store");

                // Check if certificate has private key (required for client authentication)
                if (!certificate.HasPrivateKey)
                {
                    _logger.LogWarning($"⚠️ Certificate has no private key: '{certInfo.Subject}'");
                    model.TestError = $"Certificate '{certInfo.Subject}' does not have a private key accessible. Cannot use for client authentication.";
                    model.TestSuccessful = false;
                    _logger.LogInformation($"🔍 Set TestError due to no private key: '{model.TestError}'");
                    return;
                }

                var startTime = DateTime.UtcNow;
                _logger.LogInformation($"🌐 Making HTTP request to: {testUrl}");

                // Create HTTP client handler with the certificate
                using var handler = new HttpClientHandler();
                handler.ClientCertificates.Add(certificate);
                
                // Configure SSL/TLS options
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) =>
                {
                    _logger.LogInformation($"🔒 Server certificate validation: {sslPolicyErrors}");
                    return true; // Accept all certificates for testing
                };

                using var httpClient = new HttpClient(handler);
                httpClient.Timeout = TimeSpan.FromSeconds(30);

                // Add some headers to help with debugging
                httpClient.DefaultRequestHeaders.Add("User-Agent", "Azure-AppService-ClientCert-Tester/1.0");
                httpClient.DefaultRequestHeaders.Add("X-Test-Certificate-Thumbprint", certInfo.Thumbprint);

                // Make the HTTP request
                var response = await httpClient.GetAsync(testUrl);
                var responseContent = await response.Content.ReadAsStringAsync();
                var endTime = DateTime.UtcNow;
                var duration = endTime - startTime;

                _logger.LogInformation($"✅ HTTP request completed. Status: {response.StatusCode}, Duration: {duration.TotalMilliseconds}ms");

                // Build detailed result message
                var resultBuilder = new StringBuilder();
                resultBuilder.AppendLine($"🚀 HTTP Request completed!");
                resultBuilder.AppendLine();
                resultBuilder.AppendLine($"📋 Test Details:");
                resultBuilder.AppendLine($"   • URL: {testUrl}");
                resultBuilder.AppendLine($"   • Certificate: {certInfo.Subject}");
                resultBuilder.AppendLine($"   • Thumbprint: {certInfo.Thumbprint}");
                resultBuilder.AppendLine($"   • Has Client Auth EKU: {(certInfo.HasClientAuthenticationEKU ? "✅ Yes" : "⚠️ No")}");
                resultBuilder.AppendLine($"   • Request Duration: {duration.TotalMilliseconds:F0}ms");
                resultBuilder.AppendLine();
                
                resultBuilder.AppendLine($"📡 HTTP Response:");
                resultBuilder.AppendLine($"   • Status: {(int)response.StatusCode} {response.ReasonPhrase}");
                resultBuilder.AppendLine($"   • Content Length: {responseContent.Length} bytes");
                
                // Add response headers
                if (response.Headers.Any())
                {
                    resultBuilder.AppendLine($"   • Response Headers:");
                    foreach (var header in response.Headers)
                    {
                        resultBuilder.AppendLine($"     - {header.Key}: {string.Join(", ", header.Value)}");
                    }
                }

                // Add content headers
                if (response.Content.Headers.Any())
                {
                    resultBuilder.AppendLine($"   • Content Headers:");
                    foreach (var header in response.Content.Headers)
                    {
                        resultBuilder.AppendLine($"     - {header.Key}: {string.Join(", ", header.Value)}");
                    }
                }

                resultBuilder.AppendLine();
                resultBuilder.AppendLine($"📄 Response Body (first 1000 chars):");
                resultBuilder.AppendLine(responseContent.Length > 1000 ? 
                    responseContent.Substring(0, 1000) + "..." : 
                    responseContent);

                // Warning if no Client Auth EKU
                if (!certInfo.HasClientAuthenticationEKU)
                {
                    resultBuilder.AppendLine();
                    resultBuilder.AppendLine($"⚠️ WARNING: This certificate does not have Client Authentication Extended Key Usage (1.3.6.1.5.5.7.3.2).");
                    resultBuilder.AppendLine($"   Some servers may reject this certificate for client authentication.");
                    resultBuilder.AppendLine($"   Available EKUs: {string.Join(", ", certInfo.ExtendedKeyUsages)}");
                }

                model.TestResult = resultBuilder.ToString();
                model.TestSuccessful = response.IsSuccessStatusCode;
                
                _logger.LogInformation($"🔍 Set TestResult with {model.TestResult.Length} characters");
                _logger.LogInformation($"🔍 TestResult preview: {model.TestResult.Substring(0, Math.Min(200, model.TestResult.Length))}...");
                
                if (!response.IsSuccessStatusCode)
                {
                    model.TestError = $"HTTP request returned error status: {(int)response.StatusCode} {response.ReasonPhrase}";
                    _logger.LogInformation($"🔍 Also set TestError: '{model.TestError}'");
                }
                
                _logger.LogInformation($"✅ Certificate test completed. Success: {model.TestSuccessful}");
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError(httpEx, "❌ HTTP request failed");
                
                var errorBuilder = new StringBuilder();
                errorBuilder.AppendLine($"❌ HTTP Request Failed");
                errorBuilder.AppendLine($"URL: {testUrl}");
                errorBuilder.AppendLine($"Certificate: {certInfo.Subject}");
                errorBuilder.AppendLine($"Error: {httpEx.Message}");
                
                if (httpEx.InnerException != null)
                {
                    errorBuilder.AppendLine($"Inner Exception: {httpEx.InnerException.Message}");
                }
                
                if (!certInfo.HasClientAuthenticationEKU)
                {
                    errorBuilder.AppendLine();
                    errorBuilder.AppendLine($"⚠️ NOTE: This certificate does not have Client Authentication EKU.");
                    errorBuilder.AppendLine($"This may be the reason for the failure if the server requires it.");
                }

                model.TestError = errorBuilder.ToString();
                model.TestSuccessful = false;
                _logger.LogInformation($"🔍 Set TestError due to HTTP exception: '{model.TestError}'");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Unexpected error during certificate test");
                
                model.TestError = $"❌ Unexpected error testing certificate '{certInfo.Subject}': {ex.Message}";
                model.TestSuccessful = false;
                _logger.LogInformation($"🔍 Set TestError due to unexpected exception: '{model.TestError}'");
            }
        }

        private X509Certificate2? GetCertificateFromStore(string thumbprint, string storeLocation, string storeName)
        {
            try
            {
                _logger.LogInformation($"🔍 Looking for certificate with thumbprint '{thumbprint}' in {storeName} ({storeLocation})");
                
                var location = Enum.Parse<StoreLocation>(storeLocation);
                var name = Enum.Parse<StoreName>(storeName);
                
                using var store = new X509Store(name, location);
                store.Open(OpenFlags.ReadOnly);
                
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                
                _logger.LogInformation($"🔍 Found {certs.Count} certificates matching thumbprint");
                
                if (certs.Count > 0)
                {
                    _logger.LogInformation($"✅ Successfully found certificate: {certs[0].Subject}");
                    return certs[0];
                }
                else
                {
                    _logger.LogWarning($"❌ No certificate found with thumbprint '{thumbprint}' in {storeName} ({storeLocation})");
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"❌ Error loading certificate {thumbprint} from {storeLocation}/{storeName}");
                return null;
            }
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}