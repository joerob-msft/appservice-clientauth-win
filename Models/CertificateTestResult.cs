namespace ClientCertApp.Models
{
    public class CertificateTestResult
    {
        public bool IsSuccess { get; set; }
        public string? ResultMessage { get; set; }
        public string? ErrorMessage { get; set; }
        public bool HttpSuccess { get; set; }

        public static CertificateTestResult Success(string message, bool httpSuccess = true)
        {
            return new CertificateTestResult
            {
                IsSuccess = true,
                ResultMessage = message,
                HttpSuccess = httpSuccess
            };
        }

        public static CertificateTestResult Error(string errorMessage)
        {
            return new CertificateTestResult
            {
                IsSuccess = false,
                ErrorMessage = errorMessage
            };
        }
    }
}