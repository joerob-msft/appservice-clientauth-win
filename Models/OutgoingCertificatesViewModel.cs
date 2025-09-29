namespace ClientCertApp.Models
{
    public class OutgoingCertificatesViewModel
    {
        public List<LoadedCertificateInfo> LoadedCertificates { get; set; } = new();
        public string? TestResult { get; set; }
        public bool TestSuccessful { get; set; }
        public string? TestError { get; set; }
        public string? TestUrl { get; set; }
    }
}