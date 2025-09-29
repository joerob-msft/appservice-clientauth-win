using ClientCertApp.Models;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace ClientCertApp.Services
{
    public class CertificateValidationService : ICertificateValidationService
    {
        private readonly ILogger<CertificateValidationService> _logger;

        public CertificateValidationService(ILogger<CertificateValidationService> logger)
        {
            _logger = logger;
        }

        public CertificateValidationResult ValidateClientCertificate(X509Certificate2? certificate)
        {
            if (certificate == null)
            {
                return CertificateValidationResult.NoCertificate();
            }

            _logger.LogInformation($"🔍 Validating client certificate: {certificate.Subject}");

            var result = new CertificateValidationResult
            {
                HasCertificate = true,
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint,
                Issuer = certificate.Issuer,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter
            };

            // Perform all validation checks
            ValidateDateRange(certificate, result);
            ValidateChain(certificate, result);
            ValidateRevocation(certificate, result);
            ValidateKeyUsage(certificate, result);
            ValidateExtendedKeyUsage(certificate, result);
            ValidateKeyStrength(certificate, result);
            ValidateSignatureAlgorithm(certificate, result);
            ValidateSubjectAlternativeName(certificate, result);
            ValidateBasicConstraints(certificate, result);
            ValidateCriticalExtensions(certificate, result);

            // Determine overall validation status
            DetermineOverallStatus(result);

            _logger.LogInformation($"✅ Certificate validation completed. Overall status: {result.OverallStatus}");
            return result;
        }

        private void ValidateDateRange(X509Certificate2 certificate, CertificateValidationResult result)
        {
            var now = DateTime.UtcNow;
            
            if (now < certificate.NotBefore)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Critical,
                    Category = "Date Validity",
                    Message = $"Certificate is not yet valid. Valid from: {certificate.NotBefore:yyyy-MM-dd HH:mm:ss} UTC"
                });
                result.IsDateValid = false;
            }
            else if (now > certificate.NotAfter)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Critical,
                    Category = "Date Validity",
                    Message = $"Certificate has expired. Expired on: {certificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC"
                });
                result.IsDateValid = false;
            }
            else
            {
                result.IsDateValid = true;
                
                // Warn if expiring soon (within 30 days)
                var daysUntilExpiry = (certificate.NotAfter - now).TotalDays;
                if (daysUntilExpiry <= 30)
                {
                    result.ValidationIssues.Add(new ValidationIssue
                    {
                        Severity = ValidationSeverity.Warning,
                        Category = "Date Validity",
                        Message = $"Certificate expires soon: {certificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC ({daysUntilExpiry:F0} days remaining)"
                    });
                }
            }
        }

        private void ValidateChain(X509Certificate2 certificate, CertificateValidationResult result)
        {
            try
            {
                using var chain = new X509Chain();
                
                // Configure chain policy for comprehensive validation
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

                result.IsChainValid = chain.Build(certificate);
                
                if (!result.IsChainValid)
                {
                    foreach (var status in chain.ChainStatus)
                    {
                        var severity = GetChainStatusSeverity(status.Status);
                        result.ValidationIssues.Add(new ValidationIssue
                        {
                            Severity = severity,
                            Category = "Certificate Chain",
                            Message = $"{status.Status}: {status.StatusInformation}"
                        });
                    }
                }

                // Add chain information
                result.ChainLength = chain.ChainElements.Count;
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    result.ChainElements.Add(new ChainElementInfo
                    {
                        Subject = element.Certificate.Subject,
                        Issuer = element.Certificate.Issuer,
                        Thumbprint = element.Certificate.Thumbprint,
                        IsRoot = element.Certificate.Subject == element.Certificate.Issuer
                    });
                }
            }
            catch (Exception ex)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Critical,
                    Category = "Certificate Chain",
                    Message = $"Chain validation failed: {ex.Message}"
                });
                result.IsChainValid = false;
            }
        }

        private void ValidateRevocation(X509Certificate2 certificate, CertificateValidationResult result)
        {
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                
                var isValid = chain.Build(certificate);
                
                var revocationIssues = chain.ChainStatus
                    .Where(s => s.Status.ToString().Contains("Revocation"))
                    .ToList();

                if (revocationIssues.Any())
                {
                    foreach (var issue in revocationIssues)
                    {
                        var severity = issue.Status == X509ChainStatusFlags.Revoked 
                            ? ValidationSeverity.Critical 
                            : ValidationSeverity.Warning;
                            
                        result.ValidationIssues.Add(new ValidationIssue
                        {
                            Severity = severity,
                            Category = "Revocation",
                            Message = $"{issue.Status}: {issue.StatusInformation}"
                        });
                    }
                    result.IsRevocationValid = false;
                }
                else
                {
                    result.IsRevocationValid = true;
                }
            }
            catch (Exception ex)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Warning,
                    Category = "Revocation",
                    Message = $"Revocation check failed: {ex.Message}"
                });
                result.IsRevocationValid = false;
            }
        }

        private void ValidateKeyUsage(X509Certificate2 certificate, CertificateValidationResult result)
        {
            var keyUsageExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            
            if (keyUsageExt == null)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Warning,
                    Category = "Key Usage",
                    Message = "No Key Usage extension found. This may limit certificate acceptance."
                });
                return;
            }

            result.HasKeyUsage = true;
            var keyUsages = keyUsageExt.KeyUsages;

            // For client certificates, we typically expect Digital Signature and/or Key Encipherment
            if ((keyUsages & X509KeyUsageFlags.DigitalSignature) == 0 && 
                (keyUsages & X509KeyUsageFlags.KeyEncipherment) == 0)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Warning,
                    Category = "Key Usage",
                    Message = "Certificate lacks typical client authentication key usages (Digital Signature or Key Encipherment)"
                });
            }

            // Check for inappropriate usages for client certificates
            if ((keyUsages & X509KeyUsageFlags.KeyCertSign) != 0)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Warning,
                    Category = "Key Usage",
                    Message = "Certificate has Certificate Signing usage, which is unusual for client certificates"
                });
            }
        }

        private void ValidateExtendedKeyUsage(X509Certificate2 certificate, CertificateValidationResult result)
        {
            var ekuExt = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            
            if (ekuExt == null)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Critical,
                    Category = "Extended Key Usage",
                    Message = "No Extended Key Usage extension found. Client certificates should have Client Authentication EKU."
                });
                result.HasClientAuthEKU = false;
                return;
            }

            result.HasExtendedKeyUsage = true;
            
            // Check for Client Authentication EKU (1.3.6.1.5.5.7.3.2)
            var hasClientAuth = ekuExt.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2");

            if (hasClientAuth)
            {
                result.HasClientAuthEKU = true;
            }
            else
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Critical,
                    Category = "Extended Key Usage",
                    Message = "Certificate lacks Client Authentication Extended Key Usage (1.3.6.1.5.5.7.3.2)"
                });
                result.HasClientAuthEKU = false;
            }

            // List all EKUs for reference
            var ekuList = ekuExt.EnhancedKeyUsages.Cast<Oid>()
                .Select(oid => oid.FriendlyName ?? oid.Value ?? "Unknown")
                .ToList();
            
            result.ExtendedKeyUsages = ekuList;
        }

        private void ValidateKeyStrength(X509Certificate2 certificate, CertificateValidationResult result)
        {
            try
            {
                var keySize = GetKeySize(certificate);
                result.KeySize = keySize;

                var algorithm = certificate.PublicKey.Oid.FriendlyName ?? "Unknown";
                result.KeyAlgorithm = algorithm;

                // Validate key strength according to current standards
                switch (algorithm.ToUpper())
                {
                    case "RSA":
                        if (keySize < 2048)
                        {
                            result.ValidationIssues.Add(new ValidationIssue
                            {
                                Severity = ValidationSeverity.Critical,
                                Category = "Key Strength",
                                Message = $"RSA key size ({keySize} bits) is below minimum recommended size (2048 bits)"
                            });
                        }
                        else if (keySize < 3072)
                        {
                            result.ValidationIssues.Add(new ValidationIssue
                            {
                                Severity = ValidationSeverity.Warning,
                                Category = "Key Strength",
                                Message = $"RSA key size ({keySize} bits) is acceptable but 3072+ bits recommended for new certificates"
                            });
                        }
                        break;

                    case "ECC":
                    case "ECDSA":
                        if (keySize < 256)
                        {
                            result.ValidationIssues.Add(new ValidationIssue
                            {
                                Severity = ValidationSeverity.Critical,
                                Category = "Key Strength",
                                Message = $"ECDSA key size ({keySize} bits) is below minimum recommended size (256 bits)"
                            });
                        }
                        break;

                    case "DSA":
                        result.ValidationIssues.Add(new ValidationIssue
                        {
                            Severity = ValidationSeverity.Warning,
                            Category = "Key Strength",
                            Message = "DSA algorithm is deprecated. RSA or ECDSA recommended."
                        });
                        break;
                }
            }
            catch (Exception ex)
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Warning,
                    Category = "Key Strength",
                    Message = $"Could not determine key strength: {ex.Message}"
                });
            }
        }

        private void ValidateSignatureAlgorithm(X509Certificate2 certificate, CertificateValidationResult result)
        {
            var sigAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "Unknown";
            result.SignatureAlgorithm = sigAlgorithm;

            // Check for weak signature algorithms
            var weakAlgorithms = new[] { "md5", "sha1" };
            var algorithmLower = sigAlgorithm.ToLower();

            if (weakAlgorithms.Any(weak => algorithmLower.Contains(weak)))
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Critical,
                    Category = "Signature Algorithm",
                    Message = $"Weak signature algorithm detected: {sigAlgorithm}. SHA-256 or stronger recommended."
                });
            }
            else if (!algorithmLower.Contains("sha256") && !algorithmLower.Contains("sha384") && !algorithmLower.Contains("sha512"))
            {
                result.ValidationIssues.Add(new ValidationIssue
                {
                    Severity = ValidationSeverity.Warning,
                    Category = "Signature Algorithm",
                    Message = $"Unknown or potentially weak signature algorithm: {sigAlgorithm}"
                });
            }
        }

        private void ValidateSubjectAlternativeName(X509Certificate2 certificate, CertificateValidationResult result)
        {
            var sanExt = certificate.Extensions.Cast<X509Extension>()
                .FirstOrDefault(ext => ext.Oid?.Value == "2.5.29.17"); // Subject Alternative Name

            if (sanExt != null)
            {
                result.HasSubjectAlternativeName = true;
                // For client certificates, SAN is not always required, but can be useful
            }
        }

        private void ValidateBasicConstraints(X509Certificate2 certificate, CertificateValidationResult result)
        {
            var bcExt = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            
            if (bcExt != null)
            {
                if (bcExt.CertificateAuthority)
                {
                    result.ValidationIssues.Add(new ValidationIssue
                    {
                        Severity = ValidationSeverity.Warning,
                        Category = "Basic Constraints",
                        Message = "Certificate is marked as a Certificate Authority, which is unusual for client certificates"
                    });
                }
            }
        }

        private void ValidateCriticalExtensions(X509Certificate2 certificate, CertificateValidationResult result)
        {
            var criticalExtensions = certificate.Extensions
                .Cast<X509Extension>()
                .Where(ext => ext.Critical)
                .ToList();

            result.CriticalExtensionsCount = criticalExtensions.Count;

            // Check for unknown critical extensions
            var knownCriticalOids = new[]
            {
                "2.5.29.15", // Key Usage
                "2.5.29.37", // Extended Key Usage
                "2.5.29.19", // Basic Constraints
                "2.5.29.32", // Certificate Policies
            };

            var unknownCritical = criticalExtensions
                .Where(ext => !knownCriticalOids.Contains(ext.Oid?.Value))
                .ToList();

            if (unknownCritical.Any())
            {
                foreach (var ext in unknownCritical)
                {
                    result.ValidationIssues.Add(new ValidationIssue
                    {
                        Severity = ValidationSeverity.Warning,
                        Category = "Critical Extensions",
                        Message = $"Unknown critical extension: {ext.Oid?.FriendlyName ?? ext.Oid?.Value ?? "Unknown"}"
                    });
                }
            }
        }

        private void DetermineOverallStatus(CertificateValidationResult result)
        {
            var criticalIssues = result.ValidationIssues.Count(i => i.Severity == ValidationSeverity.Critical);
            var warningIssues = result.ValidationIssues.Count(i => i.Severity == ValidationSeverity.Warning);

            if (criticalIssues > 0)
            {
                result.OverallStatus = CertificateValidationStatus.Invalid;
            }
            else if (warningIssues > 0)
            {
                result.OverallStatus = CertificateValidationStatus.ValidWithWarnings;
            }
            else
            {
                result.OverallStatus = CertificateValidationStatus.Valid;
            }

            result.CriticalIssuesCount = criticalIssues;
            result.WarningIssuesCount = warningIssues;
        }

        private ValidationSeverity GetChainStatusSeverity(X509ChainStatusFlags status)
        {
            return status switch
            {
                X509ChainStatusFlags.NotTimeValid => ValidationSeverity.Critical,
                X509ChainStatusFlags.NotTimeNested => ValidationSeverity.Critical,
                X509ChainStatusFlags.Revoked => ValidationSeverity.Critical,
                X509ChainStatusFlags.NotSignatureValid => ValidationSeverity.Critical,
                X509ChainStatusFlags.NotValidForUsage => ValidationSeverity.Critical,
                X509ChainStatusFlags.UntrustedRoot => ValidationSeverity.Warning,
                X509ChainStatusFlags.RevocationStatusUnknown => ValidationSeverity.Warning,
                X509ChainStatusFlags.Cyclic => ValidationSeverity.Critical,
                X509ChainStatusFlags.InvalidExtension => ValidationSeverity.Warning,
                X509ChainStatusFlags.InvalidPolicyConstraints => ValidationSeverity.Warning,
                X509ChainStatusFlags.InvalidBasicConstraints => ValidationSeverity.Critical,
                X509ChainStatusFlags.InvalidNameConstraints => ValidationSeverity.Critical,
                X509ChainStatusFlags.HasNotSupportedNameConstraint => ValidationSeverity.Warning,
                X509ChainStatusFlags.HasNotDefinedNameConstraint => ValidationSeverity.Warning,
                X509ChainStatusFlags.HasNotPermittedNameConstraint => ValidationSeverity.Critical,
                X509ChainStatusFlags.HasExcludedNameConstraint => ValidationSeverity.Critical,
                X509ChainStatusFlags.PartialChain => ValidationSeverity.Warning,
                X509ChainStatusFlags.CtlNotTimeValid => ValidationSeverity.Warning,
                X509ChainStatusFlags.CtlNotSignatureValid => ValidationSeverity.Critical,
                X509ChainStatusFlags.CtlNotValidForUsage => ValidationSeverity.Warning,
                X509ChainStatusFlags.OfflineRevocation => ValidationSeverity.Warning,
                X509ChainStatusFlags.NoIssuanceChainPolicy => ValidationSeverity.Warning,
                _ => ValidationSeverity.Warning
            };
        }

        private int GetKeySize(X509Certificate2 certificate)
        {
            return certificate.PublicKey.Oid.FriendlyName switch
            {
                "RSA" => certificate.GetRSAPublicKey()?.KeySize ?? 0,
                "DSA" => certificate.GetDSAPublicKey()?.KeySize ?? 0,
                "ECDSA" => certificate.GetECDsaPublicKey()?.KeySize ?? 0,
                _ => 0
            };
        }
    }
}