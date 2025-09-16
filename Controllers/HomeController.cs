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

            // Get the client certificate from the request
            var clientCert = HttpContext.Connection.ClientCertificate;

            if (clientCert != null)
            {
                model.HasCertificate = true;
                model.Subject = clientCert.Subject;
                model.Issuer = clientCert.Issuer;
                model.Thumbprint = clientCert.Thumbprint;
                model.SerialNumber = clientCert.SerialNumber;
                model.NotBefore = clientCert.NotBefore;
                model.NotAfter = clientCert.NotAfter;
                model.IsValid = DateTime.Now >= clientCert.NotBefore && DateTime.Now <= clientCert.NotAfter;

                // Get certificate chain validation details
                try
                {
                    var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    
                    model.ChainIsValid = chain.Build(clientCert);
                    
                    if (!model.ChainIsValid)
                    {
                        model.ChainErrors = new List<string>();
                        foreach (X509ChainStatus status in chain.ChainStatus)
                        {
                            model.ChainErrors.Add($"{status.Status}: {status.StatusInformation}");
                        }
                    }

                    // Get chain information
                    model.ChainElements = new List<CertificateChainElement>();
                    foreach (X509ChainElement element in chain.ChainElements)
                    {
                        model.ChainElements.Add(new CertificateChainElement
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
                    model.ChainValidationError = ex.Message;
                }

                // Additional certificate details
                model.Version = clientCert.Version;
                model.SignatureAlgorithm = clientCert.SignatureAlgorithm.FriendlyName ?? "Unknown";
                model.PublicKeyAlgorithm = clientCert.PublicKey.Oid.FriendlyName ?? "Unknown";
                // Replace this line:
                // model.KeySize = clientCert.PublicKey.Key?.KeySize ?? 0;

                // With the following code to avoid using the obsolete PublicKey.Key property:
                if (clientCert.PublicKey.Oid.FriendlyName == "RSA")
                {
                    using var rsa = clientCert.GetRSAPublicKey();
                    model.KeySize = rsa?.KeySize ?? 0;
                }
                else if (clientCert.PublicKey.Oid.FriendlyName == "DSA")
                {
                    using var dsa = clientCert.GetDSAPublicKey();
                    model.KeySize = dsa?.KeySize ?? 0;
                }
                else if (clientCert.PublicKey.Oid.FriendlyName == "ECDSA")
                {
                    using var ecdsa = clientCert.GetECDsaPublicKey();
                    model.KeySize = ecdsa?.KeySize ?? 0;
                }
                else
                {
                    model.KeySize = 0;
                }

                // Extensions
                model.Extensions = new List<string>();
                foreach (X509Extension extension in clientCert.Extensions)
                {
                    model.Extensions.Add($"{extension.Oid?.FriendlyName ?? extension.Oid?.Value ?? "Unknown"}: {extension.Format(false)}");
                }
            }

            return View(model);
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}