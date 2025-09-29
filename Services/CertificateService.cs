using ClientCertApp.Models;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
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
            await Task.Delay(1); // Make it async to satisfy interface
            
            var certificates = new List<LoadedCertificateInfo>();

            // Load from Current User stores
            LoadCertificatesFromStore(certificates, StoreLocation.CurrentUser, StoreName.My);
            LoadCertificatesFromStore(certificates, StoreLocation.CurrentUser, StoreName.Root);
            LoadCertificatesFromStore(certificates, StoreLocation.CurrentUser, StoreName.CertificateAuthority);

            // Load from Local Machine stores
            LoadCertificatesFromStore(certificates, StoreLocation.LocalMachine, StoreName.My);
            LoadCertificatesFromStore(certificates, StoreLocation.LocalMachine, StoreName.Root);
            LoadCertificatesFromStore(certificates, StoreLocation.LocalMachine, StoreName.CertificateAuthority);

            _logger.LogInformation($"📋 Loaded {certificates.Count} certificates from certificate stores");

            return certificates;
        }

        private void LoadCertificatesFromStore(List<LoadedCertificateInfo> certificates, StoreLocation location, StoreName name)
        {
            try
            {
                using var store = new X509Store(name, location);
                store.Open(OpenFlags.ReadOnly);

                _logger.LogDebug($"🔍 Checking {location}\\{name} store ({store.Certificates.Count} certificates)");

                foreach (X509Certificate2 cert in store.Certificates)
                {
                    try
                    {
                        var certInfo = CreateCertificateInfo(cert, location, name);
                        certificates.Add(certInfo);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, $"❌ Error processing certificate {cert.Thumbprint}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"❌ Error accessing certificate store {location}\\{name}");
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
            
            // Build certificate chain
            BuildCertificateChain(cert, certInfo);
            
            return certInfo;
        }

        private void BuildCertificateChain(X509Certificate2 certificate, LoadedCertificateInfo certInfo)
        {
            try
            {
                // Build all possible certificate chains (cross-signed paths)
                var allChains = BuildAllCertificateChains(certificate);
                
                if (allChains.Any())
                {
                    // Use the best chain (longest valid chain, or first if all invalid)
                    var bestChain = SelectBestChain(allChains);
                    
                    certInfo.ChainIsValid = bestChain.IsValid;
                    certInfo.ChainElements.AddRange(bestChain.Elements);
                    certInfo.ChainErrors.AddRange(bestChain.Errors);
                    
                    // If multiple chains exist, add information about cross-signing
                    if (allChains.Count > 1)
                    {
                        certInfo.ChainErrors.Add($"Certificate has {allChains.Count} possible chain paths (cross-signed)");
                        
                        for (int i = 0; i < allChains.Count; i++)
                        {
                            var chain = allChains[i];
                            var status = chain.IsValid ? "✅ Valid" : "❌ Invalid";
                            var rootCert = chain.Elements.LastOrDefault();
                            var rootName = rootCert?.Subject ?? "Unknown";
                            
                            certInfo.ChainErrors.Add($"Path {i + 1}: {status} - {chain.Elements.Count} certs to root: {rootName}");
                        }
                    }
                }
                else
                {
                    certInfo.ChainIsValid = false;
                    certInfo.ChainErrors.Add("Unable to build any certificate chain");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to build certificate chain for {Thumbprint}", certificate.Thumbprint);
                certInfo.ChainErrors.Add($"Chain building failed: {ex.Message}");
                certInfo.ChainIsValid = false;
            }
        }

        private List<CertificateChainInfo> BuildAllCertificateChains(X509Certificate2 certificate)
        {
            var allChains = new List<CertificateChainInfo>();
            
            // Try different chain building policies to discover cross-signed paths
            var policies = new[]
            {
                // Standard policy
                new ChainPolicy { RevocationMode = X509RevocationMode.Online, AllowUnknownCA = true },
                // Offline policy (may find different paths)
                new ChainPolicy { RevocationMode = X509RevocationMode.Offline, AllowUnknownCA = true },
                // No revocation check (may find additional paths)
                new ChainPolicy { RevocationMode = X509RevocationMode.NoCheck, AllowUnknownCA = true },
                // Strict policy
                new ChainPolicy { RevocationMode = X509RevocationMode.Online, AllowUnknownCA = false }
            };
            
            foreach (var policy in policies)
            {
                try
                {
                    using var chain = new X509Chain();
                    
                    // Configure chain policy
                    chain.ChainPolicy.RevocationMode = policy.RevocationMode;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    
                    if (policy.AllowUnknownCA)
                    {
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                    }
                    
                    // Add client authentication EKU
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                    
                    // Build the chain
                    bool isValid = chain.Build(certificate);
                    
                    var chainInfo = new CertificateChainInfo
                    {
                        IsValid = isValid,
                        PolicyDescription = GetPolicyDescription(policy)
                    };
                    
                    // Extract chain elements
                    foreach (X509ChainElement chainElement in chain.ChainElements)
                    {
                        var element = new CertificateChainElement
                        {
                            Subject = chainElement.Certificate.Subject,
                            Issuer = chainElement.Certificate.Issuer,
                            Thumbprint = chainElement.Certificate.Thumbprint,
                            NotBefore = chainElement.Certificate.NotBefore,
                            NotAfter = chainElement.Certificate.NotAfter,
                            IsRoot = chainElement.Certificate.Subject == chainElement.Certificate.Issuer
                        };
                        
                        chainInfo.Elements.Add(element);
                    }
                    
                    // Extract chain errors
                    if (chain.ChainStatus.Length > 0)
                    {
                        foreach (var status in chain.ChainStatus)
                        {
                            chainInfo.Errors.Add($"{status.Status}: {status.StatusInformation}");
                        }
                    }
                    
                    // Only add unique chains (avoid duplicates)
                    if (!allChains.Any(c => ChainsAreEquivalent(c, chainInfo)))
                    {
                        allChains.Add(chainInfo);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Chain building failed for policy {Policy}", policy);
                }
            }
            
            // Try to discover additional cross-signed paths by examining intermediate certificates
            TryDiscoverCrossSignedPaths(certificate, allChains);
            
            return allChains;
        }

        private void TryDiscoverCrossSignedPaths(X509Certificate2 certificate, List<CertificateChainInfo> existingChains)
        {
            try
            {
                // Look for the certificate's issuer in different certificate stores
                var issuerName = certificate.Issuer;
                var potentialIssuers = FindCertificatesBySubject(issuerName);
                
                foreach (var issuer in potentialIssuers)
                {
                    // Skip if this issuer is already part of existing chains
                    if (existingChains.Any(c => c.Elements.Any(e => e.Thumbprint == issuer.Thumbprint)))
                        continue;
                        
                    try
                    {
                        // Try building a chain starting with this specific issuer
                        using var chain = new X509Chain();
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                        
                        // Add the potential issuer to the extra store
                        chain.ChainPolicy.ExtraStore.Add(issuer);
                        
                        bool isValid = chain.Build(certificate);
                        
                        var chainInfo = new CertificateChainInfo
                        {
                            IsValid = isValid,
                            PolicyDescription = $"Cross-signed path via {GetCommonName(issuer.Subject)}"
                        };
                        
                        foreach (X509ChainElement chainElement in chain.ChainElements)
                        {
                            var element = new CertificateChainElement
                            {
                                Subject = chainElement.Certificate.Subject,
                                Issuer = chainElement.Certificate.Issuer,
                                Thumbprint = chainElement.Certificate.Thumbprint,
                                NotBefore = chainElement.Certificate.NotBefore,
                                NotAfter = chainElement.Certificate.NotAfter,
                                IsRoot = chainElement.Certificate.Subject == chainElement.Certificate.Issuer
                            };
                            
                            chainInfo.Elements.Add(element);
                        }
                        
                        if (chain.ChainStatus.Length > 0)
                        {
                            foreach (var status in chain.ChainStatus)
                            {
                                chainInfo.Errors.Add($"{status.Status}: {status.StatusInformation}");
                            }
                        }
                        
                        // Add if it's a unique chain
                        if (!existingChains.Any(c => ChainsAreEquivalent(c, chainInfo)))
                        {
                            existingChains.Add(chainInfo);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Cross-chain discovery failed for issuer {Issuer}", issuer.Subject);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Cross-signed path discovery failed");
            }
        }

        private List<X509Certificate2> FindCertificatesBySubject(string subjectName)
        {
            var certificates = new List<X509Certificate2>();
            
            var stores = new[]
            {
                new { Location = StoreLocation.CurrentUser, Name = StoreName.My },
                new { Location = StoreLocation.CurrentUser, Name = StoreName.CertificateAuthority },
                new { Location = StoreLocation.CurrentUser, Name = StoreName.Root },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.My },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.CertificateAuthority },
                new { Location = StoreLocation.LocalMachine, Name = StoreName.Root }
            };
            
            foreach (var storeInfo in stores)
            {
                try
                {
                    using var store = new X509Store(storeInfo.Name, storeInfo.Location);
                    store.Open(OpenFlags.ReadOnly);
                    
                    var matchingCerts = store.Certificates
                        .Cast<X509Certificate2>()
                        .Where(c => c.Subject.Equals(subjectName, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                        
                    certificates.AddRange(matchingCerts);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error searching store {Location}\\{Name}", storeInfo.Location, storeInfo.Name);
                }
            }
            
            return certificates.DistinctBy(c => c.Thumbprint).ToList();
        }

        private CertificateChainInfo SelectBestChain(List<CertificateChainInfo> chains)
        {
            // Prefer valid chains over invalid ones
            var validChains = chains.Where(c => c.IsValid).ToList();
            if (validChains.Any())
            {
                // Among valid chains, prefer the longest (most complete)
                return validChains.OrderByDescending(c => c.Elements.Count).First();
            }
            
            // If no valid chains, return the longest invalid chain
            return chains.OrderByDescending(c => c.Elements.Count).First();
        }

        private bool ChainsAreEquivalent(CertificateChainInfo chain1, CertificateChainInfo chain2)
        {
            if (chain1.Elements.Count != chain2.Elements.Count)
                return false;
                
            for (int i = 0; i < chain1.Elements.Count; i++)
            {
                if (chain1.Elements[i].Thumbprint != chain2.Elements[i].Thumbprint)
                    return false;
            }
            
            return true;
        }

        private string GetPolicyDescription(ChainPolicy policy)
        {
            var parts = new List<string>();
            
            parts.Add($"Revocation: {policy.RevocationMode}");
            parts.Add($"Unknown CA: {(policy.AllowUnknownCA ? "Allowed" : "Blocked")}");
            
            return string.Join(", ", parts);
        }

        private string GetCommonName(string distinguishedName)
        {
            try
            {
                var cnMatch = System.Text.RegularExpressions.Regex.Match(distinguishedName, @"CN=([^,]+)");
                return cnMatch.Success ? cnMatch.Groups[1].Value : distinguishedName;
            }
            catch
            {
                return distinguishedName;
            }
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
            if (extension is X509EnhancedKeyUsageExtension ekuExt)
            {
                foreach (Oid oid in ekuExt.EnhancedKeyUsages)
                {
                    var friendlyName = oid.FriendlyName ?? oid.Value ?? "Unknown";
                    certInfo.ExtendedKeyUsages.Add(friendlyName);
                    
                    if (oid.Value == "1.3.6.1.5.5.7.3.2") // Client Authentication
                    {
                        certInfo.HasClientAuthenticationEKU = true;
                    }
                }
            }
        }

        private void ProcessKeyUsage(X509Extension extension, LoadedCertificateInfo certInfo)
        {
            if (extension is X509KeyUsageExtension kuExt)
            {
                var keyUsages = kuExt.KeyUsages;
                
                if (keyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
                    certInfo.KeyUsages.Add("Digital Signature");
                if (keyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment))
                    certInfo.KeyUsages.Add("Key Encipherment");
                if (keyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment))
                    certInfo.KeyUsages.Add("Data Encipherment");
                if (keyUsages.HasFlag(X509KeyUsageFlags.KeyAgreement))
                    certInfo.KeyUsages.Add("Key Agreement");
                if (keyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
                    certInfo.KeyUsages.Add("Certificate Signing");
                if (keyUsages.HasFlag(X509KeyUsageFlags.CrlSign))
                    certInfo.KeyUsages.Add("CRL Signing");
            }
        }

        public X509Certificate2? GetCertificateFromStore(string thumbprint, string storeLocation, string storeName)
        {
            try
            {
                var location = Enum.Parse<StoreLocation>(storeLocation, true);
                var name = Enum.Parse<StoreName>(storeName, true);

                using var store = new X509Store(name, location);
                store.Open(OpenFlags.ReadOnly);

                var cert = store.Certificates
                    .Cast<X509Certificate2>()
                    .FirstOrDefault(c => c.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase));

                return cert;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"❌ Error getting certificate {thumbprint} from {storeLocation}\\{storeName}");
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

            // Process extensions and chain for client certificate
            ProcessClientCertificateExtensions(clientCert, certInfo);
            BuildClientCertificateChain(clientCert, certInfo);

            return certInfo;
        }

        private void ProcessClientCertificateExtensions(X509Certificate2 cert, ClientCertificateInfo certInfo)
        {
            foreach (X509Extension extension in cert.Extensions)
            {
                certInfo.Extensions.Add($"{extension.Oid?.FriendlyName ?? extension.Oid?.Value ?? "Unknown"}: {extension.Format(true)}");

                if (extension.Oid?.Value == "2.5.29.37") // Extended Key Usage
                {
                    if (extension is X509EnhancedKeyUsageExtension ekuExt)
                    {
                        foreach (Oid oid in ekuExt.EnhancedKeyUsages)
                        {
                            certInfo.ExtendedKeyUsages.Add(oid.FriendlyName ?? oid.Value ?? "Unknown");
                        }
                    }
                }
            }
        }

        private void BuildClientCertificateChain(X509Certificate2 certificate, ClientCertificateInfo certInfo)
        {
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

                certInfo.ChainIsValid = chain.Build(certificate);

                // Extract chain elements
                foreach (X509ChainElement chainElement in chain.ChainElements)
                {
                    var element = new CertificateChainElement
                    {
                        Subject = chainElement.Certificate.Subject,
                        Issuer = chainElement.Certificate.Issuer,
                        Thumbprint = chainElement.Certificate.Thumbprint,
                        NotBefore = chainElement.Certificate.NotBefore,
                        NotAfter = chainElement.Certificate.NotAfter,
                        IsRoot = chainElement.Certificate.Subject == chainElement.Certificate.Issuer
                    };
                    
                    certInfo.ChainElements.Add(element);
                }

                // Extract chain errors
                if (chain.ChainStatus.Length > 0)
                {
                    foreach (var status in chain.ChainStatus)
                    {
                        certInfo.ChainErrors.Add($"{status.Status}: {status.StatusInformation}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to build client certificate chain for {Thumbprint}", certificate.Thumbprint);
                certInfo.ChainErrors.Add($"Chain building failed: {ex.Message}");
                certInfo.ChainIsValid = false;
            }
        }

        private int GetKeySize(X509Certificate2 certificate)
        {
            try
            {
                // Use the appropriate method based on the key algorithm
                var publicKey = certificate.PublicKey;
                
                // Try RSA first (most common)
                try
                {
                    using var rsa = certificate.GetRSAPublicKey();
                    if (rsa != null)
                        return rsa.KeySize;
                }
                catch { }

                // Try ECDSA
                try
                {
                    using var ecdsa = certificate.GetECDsaPublicKey();
                    if (ecdsa != null)
                        return ecdsa.KeySize;
                }
                catch { }

                // Try DSA (less common)
                try
                {
                    using var dsa = certificate.GetDSAPublicKey();
                    if (dsa != null)
                        return dsa.KeySize;
                }
                catch { }

                // Fallback: parse from the OID and parameters
                if (publicKey.Oid.Value == "1.2.840.113549.1.1.1") // RSA
                {
                    // For RSA, we can estimate from the key blob size
                    var keyBlob = publicKey.EncodedKeyValue.RawData;
                    return (keyBlob.Length - 32) * 8; // Rough estimation
                }

                return 0;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not determine key size for certificate {Thumbprint}", certificate.Thumbprint);
                return 0;
            }
        }

        public async Task<CertificateTestResult> TestCertificateAsync(LoadedCertificateInfo certInfo, string testUrl)
        {
            _logger.LogInformation($"🧪 Testing certificate: {certInfo.Subject} ({certInfo.Thumbprint})");

            try
            {
                var certificate = GetCertificateFromStore(certInfo.Thumbprint, certInfo.StoreLocation, certInfo.StoreName);
                if (certificate == null)
                {
                    return CertificateTestResult.Error("Certificate not found in store");
                }

                if (!certificate.HasPrivateKey)
                {
                    return CertificateTestResult.Error("Certificate does not have a private key");
                }

                return await PerformHttpRequestAsync(certificate, certInfo, testUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"❌ Exception testing certificate {certInfo.Thumbprint}");
                return CertificateTestResult.Error($"Exception during test: {ex.Message}");
            }
        }

        private async Task<CertificateTestResult> PerformHttpRequestAsync(X509Certificate2 certificate, LoadedCertificateInfo certInfo, string testUrl)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                using var handler = new HttpClientHandler();
                handler.ClientCertificates.Add(certificate);
                handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;

                using var client = new HttpClient(handler);
                client.Timeout = TimeSpan.FromSeconds(30);

                _logger.LogInformation($"🌐 Making HTTP request to {testUrl}");
                var response = await client.GetAsync(testUrl);
                var responseContent = await response.Content.ReadAsStringAsync();

                stopwatch.Stop();

                if (response.IsSuccessStatusCode)
                {
                    var result = BuildTestResult(response, responseContent, stopwatch.Elapsed, certInfo, testUrl);
                    return CertificateTestResult.Success(result, true);
                }
                else
                {
                    var result = BuildTestResult(response, responseContent, stopwatch.Elapsed, certInfo, testUrl);
                    return CertificateTestResult.Success(result, false);
                }
            }
            catch (HttpRequestException httpEx)
            {
                stopwatch.Stop();
                var errorMessage = BuildErrorMessage(httpEx, certInfo, testUrl);
                return CertificateTestResult.Error(errorMessage);
            }
            catch (TaskCanceledException)
            {
                stopwatch.Stop();
                return CertificateTestResult.Error($"Request timed out after 30 seconds");
            }
        }

        private string BuildTestResult(HttpResponseMessage response, string responseContent, TimeSpan duration, LoadedCertificateInfo certInfo, string testUrl)
        {
            var result = new StringBuilder();
            result.AppendLine($"✅ HTTP Request Completed");
            result.AppendLine($"🌐 URL: {testUrl}");
            result.AppendLine($"📋 Certificate: {certInfo.Subject}");
            result.AppendLine($"🔍 Thumbprint: {certInfo.Thumbprint}");
            result.AppendLine($"⏱️ Duration: {duration.TotalMilliseconds:F0}ms");
            result.AppendLine();
            
            result.AppendLine($"📊 Response Details:");
            result.AppendLine($"Status: {(int)response.StatusCode} {response.StatusCode}");
            result.AppendLine($"Content Type: {response.Content.Headers.ContentType?.ToString() ?? "Not specified"}");
            result.AppendLine($"Content Length: {response.Content.Headers.ContentLength?.ToString() ?? "Unknown"}");
            result.AppendLine();

            result.AppendLine($"📋 Response Headers:");
            foreach (var header in response.Headers)
            {
                result.AppendLine($"{header.Key}: {string.Join(", ", header.Value)}");
            }
            
            foreach (var header in response.Content.Headers)
            {
                result.AppendLine($"{header.Key}: {string.Join(", ", header.Value)}");
            }
            
            result.AppendLine();
            result.AppendLine($"📄 Response Body (first 1000 chars):");
            result.AppendLine(responseContent.Length > 1000 ? responseContent.Substring(0, 1000) + "..." : responseContent);

            return result.ToString();
        }

        private string BuildErrorMessage(HttpRequestException httpEx, LoadedCertificateInfo certInfo, string testUrl)
        {
            var result = new StringBuilder();
            result.AppendLine($"❌ HTTP Request Failed");
            result.AppendLine($"🌐 URL: {testUrl}");
            result.AppendLine($"📋 Certificate: {certInfo.Subject}");
            result.AppendLine($"🔍 Thumbprint: {certInfo.Thumbprint}");
            result.AppendLine();
            result.AppendLine($"🚨 Error Details:");
            result.AppendLine(httpEx.Message);
            
            if (httpEx.InnerException != null)
            {
                result.AppendLine();
                result.AppendLine($"🔍 Inner Exception:");
                result.AppendLine(httpEx.InnerException.Message);
            }

            return result.ToString();
        }

        
        private class CertificateChainInfo
        {
            public bool IsValid { get; set; }
            public string PolicyDescription { get; set; } = string.Empty;
            public List<CertificateChainElement> Elements { get; set; } = new();
            public List<string> Errors { get; set; } = new();
        }

        private class ChainPolicy
        {
            public X509RevocationMode RevocationMode { get; set; }
            public bool AllowUnknownCA { get; set; }
        }

    }
}
