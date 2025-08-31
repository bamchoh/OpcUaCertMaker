using Microsoft.Win32;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Prism.Commands;
using Prism.Mvvm;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;

namespace OpcUaCertMaker
{
    public enum PrivateKeyFormat
    {
        PEM,
        PFX
    }

    class MainWindowVM : BindableBase
    {
        private string _title = "OpcUaCertMaker";
        public string Title
        {
            get { return _title; }
            set { SetProperty(ref _title, value); }
        }

        private string _outputFolder = Environment.CurrentDirectory;
        public string OutputFolder
        {
            get => _outputFolder;
            set => SetProperty(ref _outputFolder, value);
        }

        private string _baseFileName = "OpcUaServer";
        public string BaseFileName
        {
            get => _baseFileName;
            set => SetProperty(ref _baseFileName, value);
        }

        private string _commonName = "OpcUaServer";
        public string CommonName
        {
            get => _commonName;
            set => SetProperty(ref _commonName, value);
        }

        private string _organization = "MyCompany";
        public string Organization
        {
            get => _organization;
            set => SetProperty(ref _organization, value);
        }

        private string _organizationUnit = "IT";
        public string OrganizationUnit
        {
            get => _organizationUnit;
            set => SetProperty(ref _organizationUnit, value);
        }

        private string _locality = "Tokyo";
        public string Locality
        {
            get => _locality;
            set => SetProperty(ref _locality, value);
        }

        private string _state = "Tokyo";
        public string State
        {
            get => _state;
            set => SetProperty(ref _state, value);
        }

        private string _country = "JP";
        public string Country
        {
            get => _country;
            set => SetProperty(ref _country, value);
        }

        private string _sanUris = $"urn:{Environment.MachineName}:UA:Application";
        public string SanUris
        {
            get => _sanUris;
            set => SetProperty(ref _sanUris, value);
        }

        private string _sanDnsNames = Environment.MachineName;
        public string SanDnsNames
        {
            get => _sanDnsNames;
            set => SetProperty(ref _sanDnsNames, value);
        }

        private string _sanIPAddresses = "";
        public string SanIPAddresses
        {
            get => _sanIPAddresses;
            set => SetProperty(ref _sanIPAddresses, value);
        }

        private PrivateKeyFormat _privateKeyFormat = PrivateKeyFormat.PEM;
        public PrivateKeyFormat PrivateKeyFormat
        {
            get => _privateKeyFormat;
            set => SetProperty(ref _privateKeyFormat, value);
        }

        private DateTime _notBefore = DateTime.Now;
        public DateTime NotBefore
        {
            get => _notBefore;
            set => SetProperty(ref _notBefore, value);
        }

        private DateTime _notAfter = DateTime.Now.AddYears(1);
        public DateTime NotAfter
        {
            get => _notAfter;
            set => SetProperty(ref _notAfter, value);
        }

        private bool _useExistingPrivateKey = false;
        public bool UseExistingPrivateKey
        {
            get => _useExistingPrivateKey;
            set => SetProperty(ref _useExistingPrivateKey, value);
        }

        private DelegateCommand _createSelfSignedCertificateCommand;
        public DelegateCommand CreateSelfSignedCertificateCommand =>
            _createSelfSignedCertificateCommand ?? (_createSelfSignedCertificateCommand = new DelegateCommand(ExecuteCreateSelfSignedCertificate));


        private string _rootCAPrivateKeyInput;
        public string RootCAPrivateKeyInput
        {
            get => _rootCAPrivateKeyInput;
            set => SetProperty(ref _rootCAPrivateKeyInput, value);
        }

        private string _rootCACertificateInput;
        public string RootCACertificateInput
        {
            get => _rootCACertificateInput;
            set => SetProperty(ref _rootCACertificateInput, value);
        }

        private DelegateCommand _createIntermediateCertificateCommand;
        public DelegateCommand CreateIntermediateCertificateCommand =>
            _createIntermediateCertificateCommand ?? (_createIntermediateCertificateCommand = new DelegateCommand(ExecuteCreateIntermediateCertificate));

        private DelegateCommand _selectFolderCommand;
        public DelegateCommand SelectFolderCommand =>
            _selectFolderCommand ?? (_selectFolderCommand = new DelegateCommand(ExecuteSelectFolder));

        private DelegateCommand _createCrlCommand;
        public DelegateCommand CreateCrlCommand =>
            _createCrlCommand ?? (_createCrlCommand = new DelegateCommand(ExecuteCreateCrl));

        private string _revokeCertificateInput;
        public string RevokeCertificateInput
        {
            get => _revokeCertificateInput;
            set => SetProperty(ref _revokeCertificateInput, value);
        }

        private DelegateCommand _revokeCertificateCommand;
        public DelegateCommand RevokeCertificateCommand =>
            _revokeCertificateCommand ?? (_revokeCertificateCommand = new DelegateCommand(ExecuteRevokeCertificate));

        private void ExecuteCreateCertificateBase(AsymmetricKeyParameter rootPrivateKey = null, Org.BouncyCastle.X509.X509Certificate rootCert = null)
        {
            var random = new SecureRandom();

            string interKeyPath = null;
            if (PrivateKeyFormat == PrivateKeyFormat.PEM)
            {
                interKeyPath = Path.Combine(OutputFolder, BaseFileName + ".key");
            }
            else if (PrivateKeyFormat == PrivateKeyFormat.PFX)
            {
                interKeyPath = Path.Combine(OutputFolder, BaseFileName + ".pfx");
            }

            AsymmetricCipherKeyPair intermediateKeyPair = null;
            bool writePrivateKey = true;
            if (UseExistingPrivateKey)
            {
                if (PrivateKeyFormat == PrivateKeyFormat.PEM)
                {
                    if (File.Exists(interKeyPath))
                    {
                        using (var reader = File.OpenText(interKeyPath))
                        {
                            var pemReader = new PemReader(reader, new PasswordFinder(""));
                            var obj = pemReader.ReadObject();
                            if (obj is AsymmetricCipherKeyPair kp)
                                intermediateKeyPair = kp;
                            else if (obj is AsymmetricKeyParameter pk)
                            {
                                var publicKeyCertPath = Path.Combine(OutputFolder, BaseFileName + ".der");
                                AsymmetricKeyParameter publicKey = null;
                                if (File.Exists(publicKeyCertPath))
                                {
                                    var certRaw = File.ReadAllBytes(publicKeyCertPath);
                                    var publicKeyCert = new X509CertificateParser().ReadCertificate(certRaw);
                                    publicKey = publicKeyCert.GetPublicKey();
                                }
                                intermediateKeyPair = new AsymmetricCipherKeyPair(publicKey, pk);
                            }
                        }
                        writePrivateKey = false;
                    }
                }
                else if (PrivateKeyFormat == PrivateKeyFormat.PFX)
                {
                    if (File.Exists(interKeyPath))
                    {
                        using (var stream = new FileStream(interKeyPath, FileMode.Open, FileAccess.Read))
                        {
                            var store = new Pkcs12Store(stream, new char[0]);
                            string alias = null;
                            foreach (string a in store.Aliases)
                            {
                                if (store.IsKeyEntry(a)) { alias = a; break; }
                            }
                            var keyEntry = store.GetKey(alias);
                            var certEntry = store.GetCertificate(alias);
                            var privateKey = keyEntry.Key;
                            var publicKey = certEntry.Certificate.GetPublicKey();
                            intermediateKeyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);
                        }
                        writePrivateKey = false;
                    }
                }
            }

            if (intermediateKeyPair == null)
            {
                // Generate intermediate CA key pair
                var keyGen = new RsaKeyPairGenerator();
                keyGen.Init(new KeyGenerationParameters(random, 2048));
                intermediateKeyPair = keyGen.GenerateKeyPair();
            }

            var certGen = new X509V3CertificateGenerator();
            var serialNumber = BigInteger.ProbablePrime(120, random);
            certGen.SetSerialNumber(serialNumber);
            var subjectDN = new X509Name(BuildDistinguishedName());
            if (rootCert == null)
            {
                certGen.SetIssuerDN(subjectDN);
            }
            else
            {
                certGen.SetIssuerDN(rootCert.SubjectDN);
            }
            certGen.SetSubjectDN(subjectDN);
            certGen.SetNotBefore(NotBefore.ToUniversalTime());
            certGen.SetNotAfter(NotAfter.ToUniversalTime());
            certGen.SetPublicKey(intermediateKeyPair.Public);

            // KeyUsage: 0xf4
            certGen.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment | KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyCertSign | KeyUsage.CrlSign));

            // EKU: Server/Client Auth
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
                new ExtendedKeyUsage(new[] {
                        KeyPurposeID.IdKPServerAuth,
                        KeyPurposeID.IdKPClientAuth
                }));

            // Subject Alternative Name (SAN)
            var sanList = new List<GeneralName>();
            foreach (var dns in SanDnsNames.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!string.IsNullOrWhiteSpace(dns))
                    sanList.Add(new GeneralName(GeneralName.DnsName, dns));
            }
            if (!string.IsNullOrWhiteSpace(SanUris))
            {
                sanList.Add(new GeneralName(GeneralName.UniformResourceIdentifier, SanUris));
            }
            foreach (var ipStr in SanIPAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!string.IsNullOrWhiteSpace(ipStr))
                    sanList.Add(new GeneralName(GeneralName.IPAddress, ipStr));
            }
            if (sanList.Count > 0)
            {
                var sanSeq = new DerSequence(sanList.ToArray());
                certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, sanSeq);
            }

            // Subject Key Identifier
            var pubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(intermediateKeyPair.Public);
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(pubKeyInfo));

            if (rootCert == null)
            {
                // Authority Key Identifier (自己署名なのでSKIと同じ)
                certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(pubKeyInfo, new GeneralNames(new GeneralName(subjectDN)), serialNumber));
            } else
            {
                var rootPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rootCert.GetPublicKey());
                certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(rootPubKeyInfo, new GeneralNames(new GeneralName(rootCert.SubjectDN)), rootCert.SerialNumber));
            }

            // Netscape Comment (IA5String)
            certGen.AddExtension(new DerObjectIdentifier("2.16.840.1.113730.1.13"), false,
                new DerIA5String("Generated by OpcUaCertMaker"));

            // Basic Constraints (CA: true)
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));

            Asn1SignatureFactory signatureFactory = null;
            if (rootPrivateKey == null)
            {
                signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", intermediateKeyPair.Private, random);
            }
            else
            {
                signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", rootPrivateKey, random);
            }
            var intermediateCert = certGen.Generate(signatureFactory);

            if (writePrivateKey)
            {
                switch (PrivateKeyFormat)
                {
                    case PrivateKeyFormat.PEM:
                        using (var sw = new StreamWriter(interKeyPath, false, Encoding.ASCII))
                        {
                            var pkcs8 = new Pkcs8Generator(intermediateKeyPair.Private, Pkcs8Generator.PbeSha1_3DES);
                            var pemWriter = new PemWriter(sw);
                            pemWriter.WriteObject(pkcs8);
                        }
                        break;

                    case PrivateKeyFormat.PFX:
                        var store = new Pkcs12StoreBuilder().Build();
                        store.SetKeyEntry("OpcUaCert", new AsymmetricKeyEntry(intermediateKeyPair.Private), new[] { new X509CertificateEntry(intermediateCert) });
                        using (var fs = File.Create(interKeyPath))
                        {
                            store.Save(fs, new char[0], random);
                        }
                        break;

                    default:
                        throw new NotSupportedException($"Unsupported private key format: {PrivateKeyFormat}");
                }
            }

            // Save intermediate certificate (DER)
            var intermCertPath = Path.Combine(OutputFolder, BaseFileName + ".der");
            File.WriteAllBytes(intermCertPath, intermediateCert.GetEncoded());

            System.Windows.MessageBox.Show(
                $"Intermediate CA certificate and private key were created successfully.\nCertificate: {intermCertPath}\nPrivate Key: {interKeyPath}",
                "Success",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Information);
        }

        private void ExecuteCreateSelfSignedCertificate()
        {
            try
            {
                ExecuteCreateCertificateBase();
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    $"An error occurred while creating the certificate.\n{ex.Message}",
                    "Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
            }
        }



        /// <summary>
        /// Generate an intermediate CA certificate using UI parameters and sign it with the root CA.
        /// </summary>
        public void ExecuteCreateIntermediateCertificate()
        {
            try
            {
                // Load root CA private key and certificate
                var (rootPrivateKey, rootCert) = LoadCaCertificateAndKey(RootCAPrivateKeyInput, RootCACertificateInput);

                ExecuteCreateCertificateBase(rootPrivateKey, rootCert);
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    $"An error occurred while creating the intermediate certificate.\n{ex.Message}",
                    "Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
            }
        }



        private void ExecuteSelectFolder()
        {
            var dialog = new OpenFolderDialog();
            dialog.InitialDirectory = OutputFolder;
            if (dialog.ShowDialog() == true)
            {
                OutputFolder = dialog.FolderName;
            }
        }

        private void ExecuteCreateCrl()
        {
            try
            {
                var random = new SecureRandom();

                var (privateKey, cert) = LoadCaCertificateAndKey(RootCAPrivateKeyInput, RootCACertificateInput);

                var issuerDN = cert.SubjectDN;
                var signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", privateKey, random);

                var crlGen = new X509V2CrlGenerator();
                crlGen.SetIssuerDN(issuerDN);
                crlGen.SetThisUpdate(DateTime.Now.ToUniversalTime());
                crlGen.SetNextUpdate(DateTime.Now.AddDays(30).ToUniversalTime());
                // 失効リストは空
                // 拡張例: crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(...));

                var crl = crlGen.Generate(signatureFactory);
                var crlPath = Path.Combine(OutputFolder, BaseFileName + ".crl");
                File.WriteAllBytes(crlPath, crl.GetEncoded());

                System.Windows.MessageBox.Show(
                    $"CRL was created successfully.\nCRL: {crlPath}",
                    "Success",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    $"An error occurred while creating the CRL.\n{ex.Message}",
                    "Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
            }
        }

        private void ExecuteRevokeCertificate()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(RevokeCertificateInput))
                {
                    System.Windows.MessageBox.Show("Please specify a certificate file path or Base64 string.", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                    return;
                }

                Org.BouncyCastle.X509.X509Certificate certToRevoke = null;
                if (File.Exists(RevokeCertificateInput))
                {
                    // ファイルから証明書を読み込み
                    var raw = File.ReadAllBytes(RevokeCertificateInput);
                    certToRevoke = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(raw);
                }
                else
                {
                    // Base64文字列として読み込み
                    try
                    {
                        var raw = Convert.FromBase64String(RevokeCertificateInput);
                        certToRevoke = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(raw);
                    }
                    catch
                    {
                        System.Windows.MessageBox.Show("Invalid certificate input.", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                        return;
                    }
                }

                var serial = certToRevoke.SerialNumber;

                var random = new SecureRandom();
                var (privateKey, cert) = LoadCaCertificateAndKey(RootCAPrivateKeyInput, RootCACertificateInput);
                var issuerDN = cert.SubjectDN;

                var signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", privateKey, random);

                var crlGen = new X509V2CrlGenerator();
                crlGen.SetIssuerDN(issuerDN);
                crlGen.SetThisUpdate(DateTime.Now.ToUniversalTime());
                crlGen.SetNextUpdate(DateTime.Now.AddDays(30).ToUniversalTime());
                crlGen.AddCrlEntry(serial, DateTime.Now.ToUniversalTime(), CrlReason.PrivilegeWithdrawn);

                var crl = crlGen.Generate(signatureFactory);
                var crlPath = Path.Combine(OutputFolder, BaseFileName + ".crl");
                File.WriteAllBytes(crlPath, crl.GetEncoded());

                System.Windows.MessageBox.Show(
                    $"CRL with revoked certificate was created successfully.\nCRL: {crlPath}",
                    "Success",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    $"An error occurred while creating the CRL.\n{ex.Message}",
                    "Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
            }
        }

        private (AsymmetricKeyParameter, Org.BouncyCastle.X509.X509Certificate) LoadCaCertificateAndKey(string privateKeyPath, string certPath)
        {
            AsymmetricKeyParameter privateKey = null;
            Org.BouncyCastle.X509.X509Certificate cert = null;


            switch(Path.GetExtension(privateKeyPath).ToLower())
            {
                case ".pem":
                case ".key":
                    {
                        using (var reader = File.OpenText(privateKeyPath))
                        {
                            var pemReader = new PemReader(reader, new PasswordFinder(""));
                            var obj = pemReader.ReadObject();
                            if (obj is AsymmetricCipherKeyPair kp)
                                privateKey = kp.Private;
                            else if (obj is AsymmetricKeyParameter pk)
                                privateKey = pk;
                        }
                        var certRaw = File.ReadAllBytes(certPath);
                        cert = new X509CertificateParser().ReadCertificate(certRaw);
                    }
                    break;
                case ".pfx":
                case ".p12":
                    {
                        using (var stream = new FileStream(privateKeyPath, FileMode.Open, FileAccess.Read))
                        {
                            var store = new Pkcs12Store(stream, new char[0]);
                            string alias = null;
                            foreach (string a in store.Aliases)
                            {
                                if (store.IsKeyEntry(a)) { alias = a; break; }
                            }
                            var keyEntry = store.GetKey(alias);
                            privateKey = keyEntry.Key;
                            var certEntry = store.GetCertificate(alias);
                            cert = certEntry.Certificate;
                        }
                    }
                    break;
                default:
                    throw new NotSupportedException("Unsupported private key format for CA loading.");
            }
            return (privateKey, cert);
        }

        private string BuildDistinguishedName()
        {
            var dn = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(CommonName)) dn.Append($"CN={CommonName}, ");
            if (!string.IsNullOrWhiteSpace(Organization)) dn.Append($"O={Organization}, ");
            if (!string.IsNullOrWhiteSpace(OrganizationUnit)) dn.Append($"OU={OrganizationUnit}, ");
            if (!string.IsNullOrWhiteSpace(Locality)) dn.Append($"L={Locality}, ");
            if (!string.IsNullOrWhiteSpace(State)) dn.Append($"ST={State}, ");
            if (!string.IsNullOrWhiteSpace(Country)) dn.Append($"C={Country}, ");
            if (dn.Length > 2) dn.Length -= 2; // remove last comma and space
            return dn.ToString();
        }

        // PasswordFinderクラス追加
        private class PasswordFinder : IPasswordFinder
        {
            private readonly char[] _password;
            public PasswordFinder(string password)
            {
                _password = password?.ToCharArray() ?? new char[0];
            }
            public char[] GetPassword()
            {
                return _password;
            }
        }

        public void SaveSettings()
        {
            var dialog = new SaveFileDialog();
            dialog.FileName = SettingsFilePath;
            var directoryPath = Path.GetDirectoryName(SettingsFilePath);
            if (Directory.Exists(directoryPath))
            {
                dialog.InitialDirectory = directoryPath;
            }
            dialog.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*";
            if (dialog.ShowDialog() == true)
            {
                SettingsFilePath = dialog.FileName;
            }

            var settings = new AppSettings
            {
                OutputFolder = this.OutputFolder,
                BaseFileName = this.BaseFileName,
                PrivateKeyFormat = this.PrivateKeyFormat.ToString(),
                CommonName = this.CommonName,
                Organization = this.Organization,
                OrganizationUnit = this.OrganizationUnit,
                Locality = this.Locality,
                State = this.State,
                Country = this.Country,
                SanUris = this.SanUris,
                SanDnsNames = this.SanDnsNames,
                SanIPAddresses = this.SanIPAddresses,
                RootCAPrivateKeyInput = this.RootCAPrivateKeyInput,
                RootCACertificateInput = this.RootCACertificateInput,
                UseExistingPrivateKey = this.UseExistingPrivateKey
            };
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsFilePath, json);
        }

        public void LoadSettings()
        {
            var dialog = new OpenFileDialog();
            dialog.FileName = SettingsFilePath;
            var directoryPath = Path.GetDirectoryName(SettingsFilePath);
            if (Directory.Exists(directoryPath))
            {
                dialog.InitialDirectory = directoryPath;
            }
            dialog.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*";
            if (dialog.ShowDialog() == true)
            {
                SettingsFilePath = dialog.FileName;
            }

            if (!File.Exists(SettingsFilePath)) return;
            var json = File.ReadAllText(SettingsFilePath);
            var settings = JsonSerializer.Deserialize<AppSettings>(json);
            if (settings == null) return;
            this.OutputFolder = settings.OutputFolder;
            this.BaseFileName = settings.BaseFileName;
            if (Enum.TryParse<PrivateKeyFormat>(settings.PrivateKeyFormat, out var fmt))
                this.PrivateKeyFormat = fmt;
            this.CommonName = settings.CommonName;
            this.Organization = settings.Organization;
            this.OrganizationUnit = settings.OrganizationUnit;
            this.Locality = settings.Locality;
            this.State = settings.State;
            this.Country = settings.Country;
            this.SanUris = settings.SanUris;
            this.SanDnsNames = settings.SanDnsNames;
            this.SanIPAddresses = settings.SanIPAddresses;
            this.RootCAPrivateKeyInput = settings.RootCAPrivateKeyInput;
            this.RootCACertificateInput = settings.RootCACertificateInput;
            this.UseExistingPrivateKey = settings.UseExistingPrivateKey;
        }

        private string _settingsFilePath = Path.Combine(Environment.CurrentDirectory, "settings.json");
        public string SettingsFilePath
        {
            get => _settingsFilePath;
            set => SetProperty(ref _settingsFilePath, value);
        }

        private DelegateCommand _saveSettingsCommand;
        public DelegateCommand SaveSettingsCommand =>
            _saveSettingsCommand ?? (_saveSettingsCommand = new DelegateCommand(SaveSettings));

        private DelegateCommand _loadSettingsCommand;
        public DelegateCommand LoadSettingsCommand =>
            _loadSettingsCommand ?? (_loadSettingsCommand = new DelegateCommand(LoadSettings));
    }
}
