using ClientCertApp.Models;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ClientCertApp.Services
{
    public class CertificateService : ICertificateService
    {
        private readonly ILogger<CertificateService> _logger;

        public CertificateService(ILogger<CertificateService> logger)
        {
            _logger = logger;
        }

        public async Task<List<LoadedCertificateInfo>> LoadCertificatesFromStoresAsync()
        {
            _logger.LogInformation("📚 Loading certificates from certificate stores...");
            
            var certificates = new List<LoadedCertificateInfo>();
            
            var storesToCheck = new[]
            {
                new { Location = StoreLocation.CurrentUser, Name = StoreName.My },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.My },
                new { Location = StoreLocation.CurrentUser, Name = StoreName.Root },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.Root },
                new { Location = StoreLocation.CurrentUser, Name = StoreName.CertificateAuthority },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.CertificateAuthority }
            };

            await Task.Run(() =>
            {
                foreach (var storeInfo in storesToCheck)
                {
                    try
                    {
                        LoadCertificatesFromStore(certificates, storeInfo.Location, storeInfo.Name);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, $"⚠️ Could not access certificate store: {storeInfo.Name} ({storeInfo.Location})");
                    }
                }
            });

            // Remove duplicates and sort
            var uniqueCerts = certificates
                .GroupBy(c => c.Thumbprint)
                .Select(g => g.First())
                .OrderBy(c => c.Subject)
                .ToList();
            
            _logger.LogInformation($"✅ Loaded {uniqueCerts.Count} unique certificates, {uniqueCerts.Count(c => c.HasPrivateKey)} have private keys");
            return uniqueCerts;
        }

        private void LoadCertificatesFromStore(List<LoadedCertificateInfo> certificates, StoreLocation location, StoreName name)
        {
            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);
            
            _logger.LogInformation($"📂 Checking store: {name} ({location}) - Found {store.Certificates.Count} certificates");

            foreach (X509Certificate2 cert in store.Certificates)
            {
                _logger.LogDebug($"📜 Processing certificate: {cert.Subject}, HasPrivateKey: {cert.HasPrivateKey}");
                
                var certInfo = CreateCertificateInfo(cert, location, name);
                certificates.Add(certInfo);
            }
        }

        private LoadedCertificateInfo CreateCertificateInfo(X509Certificate2 cert, StoreLocation location, StoreName name)
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
                StoreLocation = location.ToString(),
                StoreName = name.ToString(),
                HasPrivateKey = cert.HasPrivateKey,
                FriendlyName = cert.FriendlyName ?? ""
            };

            // Process extensions
            ProcessCertificateExtensions(cert, certInfo);
            
            return certInfo;
        }

        private void ProcessCertificateExtensions(X509Certificate2 cert, LoadedCertificateInfo certInfo)
        {
            foreach (X509Extension extension in cert.Extensions)
            {
                if (extension.Oid?.Value == "2.5.29.37") // Extended Key Usage
                {
                    ProcessExtendedKeyUsage(extension, certInfo);
                }
                else if (extension.Oid?.Value == "2.5.29.15") // Key Usage
                {
                    ProcessKeyUsage(extension, certInfo);
                }
            }
        }

        private void ProcessExtendedKeyUsage(X509Extension extension, LoadedCertificateInfo certInfo)
        {
            if (extension is X509EnhancedKeyUsageExtension eku)
            {
                foreach (var usage in eku.EnhancedKeyUsages)
                {
                    var friendlyName = usage.FriendlyName ?? usage.Value ?? "Unknown";
                    certInfo.ExtendedKeyUsages.Add(friendlyName);
                    
                    if (usage.Value == "1.3.6.1.5.5.7.3.2") // Client Authentication
                    {
                        certInfo.HasClientAuthenticationEKU = true;
                    }
                }
            }
        }

        private void ProcessKeyUsage(X509Extension extension, LoadedCertificateInfo certInfo)
        {
            if (extension is X509KeyUsageExtension keyUsage)
            {
                var usages = keyUsage.KeyUsages;
                var keyUsageFlags = new[]
                {
                    (X509KeyUsageFlags.DigitalSignature, "Digital Signature"),
                    (X509KeyUsageFlags.KeyEncipherment, "Key Encipherment"),
                    (X509KeyUsageFlags.DataEncipherment, "Data Encipherment"),
                    (X509KeyUsageFlags.KeyAgreement, "Key Agreement"),
                    (X509KeyUsageFlags.KeyCertSign, "Certificate Signing"),
                    (X509KeyUsageFlags.CrlSign, "CRL Signing"),
                    (X509KeyUsageFlags.NonRepudiation, "Non-Repudiation"),
                    (X509KeyUsageFlags.DecipherOnly, "Decipher Only"),
                    (X509KeyUsageFlags.EncipherOnly, "Encipher Only")
                };

                foreach (var (flag, name) in keyUsageFlags)
                {
                    if ((usages & flag) != 0)
                        certInfo.KeyUsages.Add(name);
                }
            }
        }

        public X509Certificate2? GetCertificateFromStore(string thumbprint, string storeLocation, string storeName)
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
                
                _logger.LogWarning($"❌ No certificate found with thumbprint '{thumbprint}'");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"❌ Error loading certificate {thumbprint}");
                return null;
            }
        }

        public ClientCertificateInfo? ProcessClientCertificate(X509Certificate2? clientCert)
        {
            if (clientCert == null) return null;

            var certInfo = new ClientCertificateInfo
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
                PublicKeyAlgorithm = clientCert.PublicKey.Oid.FriendlyName ?? "Unknown",
                KeySize = GetKeySize(clientCert)
            };

            ProcessClientCertificateChain(clientCert, certInfo);
            ProcessClientCertificateExtensions(clientCert, certInfo);

            return certInfo;
        }

        private int GetKeySize(X509Certificate2 cert)
        {
            return cert.PublicKey.Oid.FriendlyName switch
            {
                "RSA" => cert.GetRSAPublicKey()?.KeySize ?? 0,
                "DSA" => cert.GetDSAPublicKey()?.KeySize ?? 0,
                "ECDSA" => cert.GetECDsaPublicKey()?.KeySize ?? 0,
                _ => 0
            };
        }

        private void ProcessClientCertificateChain(X509Certificate2 cert, ClientCertificateInfo certInfo)
        {
            try
            {
                var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                
                certInfo.ChainIsValid = chain.Build(cert);
                
                if (!certInfo.ChainIsValid)
                {
                    certInfo.ChainErrors = chain.ChainStatus
                        .Select(status => $"{status.Status}: {status.StatusInformation}")
                        .ToList();
                }

                certInfo.ChainElements = chain.ChainElements
                    .Cast<X509ChainElement>()
                    .Select(element => new CertificateChainElement
                    {
                        Subject = element.Certificate.Subject,
                        Issuer = element.Certificate.Issuer,
                        Thumbprint = element.Certificate.Thumbprint,
                        NotBefore = element.Certificate.NotBefore,
                        NotAfter = element.Certificate.NotAfter
                    })
                    .ToList();
            }
            catch (Exception ex)
            {
                certInfo.ChainValidationError = ex.Message;
            }
        }

        private void ProcessClientCertificateExtensions(X509Certificate2 cert, ClientCertificateInfo certInfo)
        {
            foreach (X509Extension extension in cert.Extensions)
            {
                certInfo.Extensions.Add($"{extension.Oid?.FriendlyName ?? extension.Oid?.Value ?? "Unknown"}: {extension.Format(false)}");
                
                if (extension.Oid?.Value == "2.5.29.37" && extension is X509EnhancedKeyUsageExtension eku)
                {
                    foreach (var usage in eku.EnhancedKeyUsages)
                    {
                        certInfo.ExtendedKeyUsages.Add(usage.FriendlyName ?? usage.Value ?? "Unknown");
                    }
                }
            }
        }

        public async Task<CertificateTestResult> TestCertificateAsync(LoadedCertificateInfo certInfo, string testUrl)
        {
            _logger.LogInformation($"🧪 Starting certificate test for: '{certInfo.Subject}'");
            
            if (string.IsNullOrEmpty(testUrl))
            {
                return CertificateTestResult.Error("ClientCertificateTestUrl is not configured in application settings.");
            }

            var certificate = GetCertificateFromStore(certInfo.Thumbprint, certInfo.StoreLocation, certInfo.StoreName);
            
            if (certificate == null)
            {
                return CertificateTestResult.Error($"Could not load certificate from store: {certInfo.Subject}");
            }

            if (!certificate.HasPrivateKey)
            {
                return CertificateTestResult.Error($"Certificate '{certInfo.Subject}' does not have a private key accessible.");
            }

            return await PerformHttpRequestAsync(certificate, certInfo, testUrl);
        }

        private async Task<CertificateTestResult> PerformHttpRequestAsync(X509Certificate2 certificate, LoadedCertificateInfo certInfo, string testUrl)
        {
            try
            {
                var startTime = DateTime.UtcNow;
                _logger.LogInformation($"🌐 Making HTTP request to: {testUrl}");

                using var handler = new HttpClientHandler();
                handler.ClientCertificates.Add(certificate);
                handler.ServerCertificateCustomValidationCallback = (_, _, _, sslPolicyErrors) =>
                {
                    _logger.LogInformation($"🔒 Server certificate validation: {sslPolicyErrors}");
                    return true;
                };

                using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
                httpClient.DefaultRequestHeaders.Add("User-Agent", "Azure-AppService-ClientCert-Tester/1.0");
                httpClient.DefaultRequestHeaders.Add("X-Test-Certificate-Thumbprint", certInfo.Thumbprint);

                var response = await httpClient.GetAsync(testUrl);
                var responseContent = await response.Content.ReadAsStringAsync();
                var duration = DateTime.UtcNow - startTime;

                _logger.LogInformation($"✅ HTTP request completed. Status: {response.StatusCode}, Duration: {duration.TotalMilliseconds}ms");

                var result = BuildTestResult(response, responseContent, duration, certInfo, testUrl);
                return CertificateTestResult.Success(result, response.IsSuccessStatusCode);
            }
            catch (HttpRequestException httpEx)
            {
                _logger.LogError(httpEx, "❌ HTTP request failed");
                return CertificateTestResult.Error(BuildErrorMessage(httpEx, certInfo, testUrl));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Unexpected error during certificate test");
                return CertificateTestResult.Error($"❌ Unexpected error testing certificate '{certInfo.Subject}': {ex.Message}");
            }
        }

        private string BuildTestResult(HttpResponseMessage response, string responseContent, TimeSpan duration, LoadedCertificateInfo certInfo, string testUrl)
        {
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
            
            AppendHeaders(resultBuilder, response);
            
            resultBuilder.AppendLine();
            resultBuilder.AppendLine($"📄 Response Body (first 1000 chars):");
            resultBuilder.AppendLine(responseContent.Length > 1000 ? 
                responseContent.Substring(0, 1000) + "..." : 
                responseContent);

            if (!certInfo.HasClientAuthenticationEKU)
            {
                resultBuilder.AppendLine();
                resultBuilder.AppendLine($"⚠️ WARNING: This certificate does not have Client Authentication Extended Key Usage.");
                resultBuilder.AppendLine($"   Available EKUs: {string.Join(", ", certInfo.ExtendedKeyUsages)}");
            }

            return resultBuilder.ToString();
        }

        private void AppendHeaders(StringBuilder builder, HttpResponseMessage response)
        {
            if (response.Headers.Any())
            {
                builder.AppendLine($"   • Response Headers:");
                foreach (var header in response.Headers)
                {
                    builder.AppendLine($"     - {header.Key}: {string.Join(", ", header.Value)}");
                }
            }

            if (response.Content.Headers.Any())
            {
                builder.AppendLine($"   • Content Headers:");
                foreach (var header in response.Content.Headers)
                {
                    builder.AppendLine($"     - {header.Key}: {string.Join(", ", header.Value)}");
                }
            }
        }

        private string BuildErrorMessage(HttpRequestException httpEx, LoadedCertificateInfo certInfo, string testUrl)
        {
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
            }

            return errorBuilder.ToString();
        }
    }
}