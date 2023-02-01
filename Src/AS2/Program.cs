using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Security.Cryptography.X509Certificates;

namespace AS2
{
    internal class Program
    {
        static string CertificateFolderPath = @"..\..\..\Certificates";

        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            //var certificate = GenerateCertificate();

            var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\b2buatcrtsha256.cer");
            //var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var privateAlvysTenantKey = LoadPrivateKey($"{CertificateFolderPath}\\AH100-Alvys-private.pem");

            var data = AS2HelperV2.Package("Test text 123", publicNiagaraCert, privateAlvysTenantKey);
        }

        static X509Certificate2 GenerateCertificate()
        {
            AsymmetricCipherKeyPair CertificateKey;
            var X509RootCert = Cryptography.CreateCertificate("C=US, O=Alvys", "CN=ALVYS", 5, out CertificateKey);

            var fileName = "AH100-Alvys";

            //now let us write the certificates files to the folder 
            File.WriteAllBytes($"{CertificateFolderPath}\\{fileName}.cer", X509RootCert.RawData);
            //File.WriteAllBytes(folder + "\\" + "X509Cert.der", X509RootCert.RawData);

            string PublicPEMFile = $"{CertificateFolderPath}\\{fileName}-public.pem";
            string PrivatePEMFile = $"{CertificateFolderPath}\\{fileName}-private.pem";

            //now let us also create the PEM file as well in case we need it
            using (TextWriter textWriter = new StreamWriter(PublicPEMFile, false))
            {
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(CertificateKey.Public);
                pemWriter.Writer.Flush();
            }

            //now let us also create the PEM file as well in case we need it
            using (TextWriter textWriter = new StreamWriter(PrivatePEMFile, false))
            {
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(CertificateKey.Private);
                pemWriter.Writer.Flush();
            }

            return X509RootCert;
        }

        /// <summary>
        /// per file
        /// </summary>
        /// <param name="privateKeyPath"></param>
        /// <returns></returns>
        static AsymmetricCipherKeyPair LoadPrivateKey(string privateKeyPath)
        {
            using (TextReader reader = File.OpenText(privateKeyPath))
            {
                PemReader pemReader = new PemReader(reader);
                return (AsymmetricCipherKeyPair)pemReader.ReadObject();
            }
        }

        /// <summary>
        /// pem file // AsymmetricKeyParameter publicKey = LoadPublicKey(recipientPublicKey);
        /// </summary>
        /// <param name="publicKeyPath"></param>
        /// <returns></returns>
        static RsaKeyParameters LoadPublicKey(string publicKeyPath)
        {
            using (TextReader reader = File.OpenText(publicKeyPath))
            {
                PemReader pemReader = new PemReader(reader);
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pemReader.ReadObject();
                return (RsaKeyParameters)publicKey;
            }
        }
    }
}