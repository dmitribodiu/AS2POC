using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AS2
{
    internal class Program
    {
        static string CertificateFolderPath = @"..\..\..\Certificates";

        static void Main(string[] args)
        {
            //var certificate = GenerateCertificate();

            //EncryptDecryptFlow();

            SignAndVerifyFlow();

            //FullFlow();



            //var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\b2buatcrtsha256.cer");
            //var data = AS2HelperV2.Package("Test text 123", publicNiagaraCert, privateAlvysTenantKey);
        }

        static void EncryptDecryptFlow()
        {
            var message = "Test text 123";

            var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\Niagara.cer");
            var encrypted = AS2HelperV2.Encrypt(Encoding.UTF8.GetBytes(message), publicNiagaraCert);

            var privateNiagaraKey = LoadPrivateKey($"{CertificateFolderPath}\\Niagara-private.pem");
            var decrypted = AS2HelperV2.Decrypt(encrypted, privateNiagaraKey.Private);

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("encrypted message: " + Encoding.UTF8.GetString(encrypted));
            Console.WriteLine();
            Console.WriteLine("decrypted message: " + Encoding.UTF8.GetString(decrypted));
        }

        static void SignAndVerifyFlow()
        {
            var message = "Test text 123";

            var privateKey = LoadPrivateKey($"{CertificateFolderPath}\\AH100-Alvys-private.pem");
            var signed = AS2HelperV2.Sign(Encoding.UTF8.GetBytes(message), privateKey);

            var publicCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var publicKey = new X509CertificateParser().ReadCertificate(publicCert.GetRawCertData()).GetPublicKey();
            var verifySigned = AS2HelperV2.VerifySignature(Encoding.UTF8.GetBytes(message), publicKey);

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("signed message: " + Encoding.UTF8.GetString(signed));
            Console.WriteLine();
            Console.WriteLine("is verified message: " + verifySigned);
        }

        static void FullFlow()
        {
            // Alvys part
            var message = "Test text 123";

            var alvysPrivateKey = LoadPrivateKey($"{CertificateFolderPath}\\AH100-Alvys-private.pem");
            var signed = AS2HelperV2.Sign(Encoding.UTF8.GetBytes(message), alvysPrivateKey);

            var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\Niagara.cer");
            var encrypted = AS2HelperV2.Encrypt(signed, publicNiagaraCert);

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("encrypted message: " + Encoding.UTF8.GetString(encrypted));
            Console.WriteLine();

            // Niagara part
            var privateNiagaraKey = LoadPrivateKey($"{CertificateFolderPath}\\Niagara-private.pem");
            var decrypted = AS2HelperV2.Decrypt(encrypted, privateNiagaraKey.Private);

            var alvysPublicCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var alvysPublicKey = new X509CertificateParser().ReadCertificate(alvysPublicCert.GetRawCertData()).GetPublicKey();
            var verifySigned = AS2HelperV2.VerifySignature(Encoding.UTF8.GetBytes(message), alvysPublicKey);

            Console.WriteLine("decrypted message: " + Encoding.UTF8.GetString(decrypted));
            Console.WriteLine();
            Console.WriteLine("is verified message: " + verifySigned);
            Console.WriteLine();
            Console.WriteLine("final message: " + verifySigned);
        }

        static X509Certificate2 GenerateCertificate()
        {
            AsymmetricCipherKeyPair CertificateKey;
            var X509RootCert = Cryptography.CreateCertificate("C=US, O=Alvys", "CN=ALVYS", 5, out CertificateKey);

            var fileName = "Niagara";

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