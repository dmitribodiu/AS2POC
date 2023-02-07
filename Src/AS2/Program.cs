using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Net;
using System.Security.Cryptography.Pkcs;
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

            //SignAndVerifyFlow();

            //FullFlow();

            SenderFlow();
        }

        static void SenderFlow()
        {
            byte[] message = Encoding.UTF8.GetBytes("This is the EDI message.");


            // Load the S/MIME certificate
            //X509Certificate2 cert = new X509Certificate2(@"cert.pfx", "password");
            //var cert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");


            // Create the S/MIME message
            //ContentInfo contentInfo = new ContentInfo(message);
            //EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);
            //CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, cert);
            //envelopedCms.Encrypt(recipient);

            //var asd = envelopedCms.Encode();

            //var encrypted = AS2HelperV2.Encrypt(message, cert);

            // Create the HTTP request
            //HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://example.com/as2");
            //request.Method = "POST";
            //request.ContentType = "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=unique-boundary-1";
            //request.Headers["AS2-From"] = "sender";
            //request.Headers["AS2-To"] = "receiver";
            //request.Headers["Message-ID"] = "12345";
            //request.Headers["Disposition-Notification-To"] = "notification@example.com";




            // sign message
            var alvysPrivateKey = LoadPrivateKey($"{CertificateFolderPath}\\AH100-Alvys-private.pem");
            var signature = AS2HelperV2.Sign(message, alvysPrivateKey);

            // verify signature
            var alvysPublicCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var alvysPublicKey = new X509CertificateParser().ReadCertificate(alvysPublicCert.GetRawCertData()).GetPublicKey();
            var validSignature = AS2HelperV2.VerifySignature(message, signature, alvysPublicKey);

            if (validSignature == false)
            {
                throw new Exception("Signature check failed");
            }

            // Create the HTTP request body
            var body = AS2HelperV2.PackMessageToBeSend(message, signature, "fileName", "txt", $"fileName_{DateTimeOffset.UtcNow}");

            Console.WriteLine(body);

            var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\Niagara.cer");

            var encryptedBody = AS2HelperV2.Encrypt(Encoding.UTF8.GetBytes(body), publicNiagaraCert);

            Console.WriteLine(Convert.ToBase64String(encryptedBody));

            // test decrypt
            var privateNiagaraKey = LoadPrivateKey($"{CertificateFolderPath}\\Niagara-private.pem");
            var decrypted = AS2HelperV2.Decrypt(encryptedBody, privateNiagaraKey.Private);

            Console.WriteLine("-----------------------------------------------------");
            Console.WriteLine(Convert.ToBase64String(decrypted));

            //MemoryStream memoryStream = new MemoryStream();
            //StreamWriter streamWriter = new StreamWriter(memoryStream);
            //streamWriter.Write("--unique-boundary-1\r\n");
            //streamWriter.Write("Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n\r\n");
            //streamWriter.Flush();
            //memoryStream.Write(envelopedCms.Encode(), 0, envelopedCms.Encode().Length);
            //streamWriter.Write("\r\n--unique-boundary-1\r\n");
            //streamWriter.Write("Content-Type: application/pkcs7-signature; name=smime.p7s\r\n\r\n");
            //streamWriter.Flush();
            //memoryStream.Write(signature, 0, signature.Length);
            //streamWriter.Write("\r\n--unique-boundary-1--\r\n");
            //streamWriter.Flush();
            //request.ContentLength = memoryStream.Length;


            // Send the S/MIME message
            //using (Stream requestStream = request.GetRequestStream())
            //{
            //    memoryStream.WriteTo(requestStream);
            //}
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
            var signature = AS2HelperV2.Sign(Encoding.UTF8.GetBytes(message), privateKey);

            var publicCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var publicKey = new X509CertificateParser().ReadCertificate(publicCert.GetRawCertData()).GetPublicKey();
            var verifySigned = AS2HelperV2.VerifySignature(Encoding.UTF8.GetBytes(message), signature, publicKey);

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("signed message: " + Encoding.UTF8.GetString(signature));
            Console.WriteLine();
            Console.WriteLine("is verified message: " + verifySigned);
        }

        static void FullFlow()
        {
            // Alvys part
            var message = "Test text 123";

            var alvysPrivateKey = LoadPrivateKey($"{CertificateFolderPath}\\AH100-Alvys-private.pem");
            var signature = AS2HelperV2.Sign(Encoding.UTF8.GetBytes(message), alvysPrivateKey);

            var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\Niagara.cer");
            var encrypted = AS2HelperV2.Encrypt(Encoding.UTF8.GetBytes(message), publicNiagaraCert);

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("Signature: " + Encoding.UTF8.GetString(signature));
            Console.WriteLine();
            Console.WriteLine("encrypted message: " + Encoding.UTF8.GetString(encrypted));
            Console.WriteLine();

            // Niagara part
            var privateNiagaraKey = LoadPrivateKey($"{CertificateFolderPath}\\Niagara-private.pem");
            var decrypted = AS2HelperV2.Decrypt(encrypted, privateNiagaraKey.Private);

            var alvysPublicCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var alvysPublicKey = new X509CertificateParser().ReadCertificate(alvysPublicCert.GetRawCertData()).GetPublicKey();
            var verifySigned = AS2HelperV2.VerifySignature(decrypted, signature, alvysPublicKey);

            Console.WriteLine("decrypted message: " + Encoding.UTF8.GetString(decrypted));
            Console.WriteLine();
            Console.WriteLine("is verified message: " + verifySigned);
        }

        static X509Certificate2 GenerateCertificate()
        {
            AsymmetricCipherKeyPair CertificateKey;
            var X509RootCert = Cryptography.CreateCertificate("C=US, O=Alvys", "CN=ALVYS", 5, out CertificateKey);

            var fileName = "Alvys";

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
    }
}