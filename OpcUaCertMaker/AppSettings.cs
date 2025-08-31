using System;

namespace OpcUaCertMaker
{
    public class AppSettings
    {
        public string OutputFolder { get; set; }
        public string BaseFileName { get; set; }
        public string PrivateKeyFormat { get; set; }
        public string CommonName { get; set; }
        public string Organization { get; set; }
        public string OrganizationUnit { get; set; }
        public string Locality { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public string SanUris { get; set; }
        public string SanDnsNames { get; set; }
        public string SanIPAddresses { get; set; }
        public string RootCAPrivateKeyInput { get; set; }
        public string RootCACertificateInput { get; set; }
        public bool UseExistingPrivateKey { get; set; }
    }
}
