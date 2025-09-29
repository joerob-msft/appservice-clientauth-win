using Microsoft.AspNetCore.Mvc;
using ClientCertApp.Models;
using ClientCertApp.Services;

namespace ClientCertApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<HomeController> _logger;
        private readonly ICertificateService _certificateService;
        private readonly ICertificateValidationService _validationService;

        public HomeController(
            IConfiguration configuration, 
            ILogger<HomeController> logger, 
            ICertificateService certificateService,
            ICertificateValidationService validationService)
        {
            _configuration = configuration;
            _logger = logger;
            _certificateService = certificateService;
            _validationService = validationService;
        }

        public async Task<IActionResult> Index()
        {
            var clientCert = HttpContext.Connection.ClientCertificate;
            
            var model = new CertificateInfoViewModel
            {
                TestUrl = _configuration["ClientCertificateTestUrl"],
                ClientCertificate = _certificateService.ProcessClientCertificate(clientCert),
                HasClientCertificate = clientCert != null,
                LoadedCertificates = await _certificateService.LoadCertificatesFromStoresAsync(),
                ValidationResult = _validationService.ValidateClientCertificate(clientCert)
            };

            return View(model);
        }

        public async Task<IActionResult> OutgoingCertificates()
        {
            var model = new OutgoingCertificatesViewModel
            {
                TestUrl = _configuration["ClientCertificateTestUrl"],
                LoadedCertificates = await _certificateService.LoadCertificatesFromStoresAsync()
            };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> TestOutgoingCertificate(string thumbprint)
        {
            _logger.LogInformation($"🔍 Testing outgoing certificate with thumbprint: '{thumbprint}'");
            
            var model = new OutgoingCertificatesViewModel
            {
                TestUrl = _configuration["ClientCertificateTestUrl"],
                LoadedCertificates = await _certificateService.LoadCertificatesFromStoresAsync()
            };

            var certToTest = model.LoadedCertificates.FirstOrDefault(c => c.Thumbprint == thumbprint);
            
            if (certToTest == null)
            {
                LogCertificateNotFound(thumbprint, model.LoadedCertificates);
                model.TestError = $"Certificate not found with thumbprint: {thumbprint}";
                model.TestSuccessful = false;
            }
            else
            {
                await TestOutgoingCertificateAsync(certToTest, model);
            }

            // Fallback message if no results were set
            if (string.IsNullOrEmpty(model.TestResult) && string.IsNullOrEmpty(model.TestError))
            {
                _logger.LogWarning($"⚠️ No test results set! Setting fallback message.");
                model.TestError = "DEBUG: Test completed but no result was set. Check logs for details.";
            }

            _logger.LogInformation($"🏁 Returning outgoing certificates view with test results");
            return View("OutgoingCertificates", model);
        }

        private void LogCertificateNotFound(string thumbprint, List<LoadedCertificateInfo> certificates)
        {
            _logger.LogWarning($"❌ Certificate not found with thumbprint: '{thumbprint}'");
            _logger.LogInformation($"📋 Available certificates ({certificates.Count} total):");
            
            foreach (var cert in certificates.Take(10))
            {
                _logger.LogInformation($"   - '{cert.Thumbprint}' ({cert.Subject.Substring(0, Math.Min(50, cert.Subject.Length))})");
            }
            
            if (certificates.Count > 10)
            {
                _logger.LogInformation($"   ... and {certificates.Count - 10} more certificates");
            }
        }

        private async Task TestOutgoingCertificateAsync(LoadedCertificateInfo certToTest, OutgoingCertificatesViewModel model)
        {
            _logger.LogInformation($"✅ Found certificate to test: '{certToTest.Subject}'");
            
            try
            {
                var result = await _certificateService.TestCertificateAsync(certToTest, model.TestUrl!);
                
                if (result.IsSuccess)
                {
                    model.TestResult = result.ResultMessage;
                    model.TestSuccessful = result.HttpSuccess;
                    
                    if (!result.HttpSuccess)
                    {
                        model.TestError = "HTTP request returned error status";
                    }
                }
                else
                {
                    model.TestError = result.ErrorMessage;
                    model.TestSuccessful = false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"❌ Exception testing outgoing certificate");
                model.TestError = $"Exception during certificate test: {ex.Message}";
                model.TestSuccessful = false;
            }
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}