using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
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
            //byte[] message = Encoding.UTF8.GetBytes("This is the EDI message.");
            var edi = @"ISA*00*          *00*          *01*027948264      *02*SCAC           *220607*1416*U*00401*000048322*0*P*>~
GS*SM*027948264*SCAC*20220607*1416*204012314*X*004010~
ST*204*34341~
B2**SCAC**NB26199722**CC~
B2A*00*LT~
L11*2186200*IA~
L11*NB26199722*MB~
L11*0*CN~
L11*218.1*BAS~
L11*210*FFR~
L11*287.75*FUE~
G62*64*20220630*1*115913*PT~
MS3*SCAC*S~
AT5*DM*H1*PREFORM~
AT5***TRANSFER_RM~
PLD*0~
NTE**By accepting this tender carrier is agreeing to the terms and conditions found a~
NTE**https?//otmprod.niagarawater.com/PDF/204TermsDisclaimer.pdf~
NTE**NBL.SCAC_TRANSFER,STK,ONT_SHIPPING_REGION,21,106,1~
N7**0*********CN****0000~
N7A*NP~
S5*1*CL*47972.53*L***0*E~
L11*0*BM~
L11*31622443*DJ~
L11*1669889*PO~
L11*14095743*SO~
G62*38*20220613*K*203000*LT~
N1*SF*STOCKTON*93*148~
N3*1025 RUNWAY DRIVE~
N4*STOCKTON*CA*95206*USA~
OID*31622443*1669889*14095743*CA*2560*L*47972.53*E*0~
S5*2*CU*47972.53*L***0*E~
L11*0*BM~
L11*31622443*DJ~
L11*1669889*PO~
L11*14095743*SO~
G62*54*20220614*L*115500*LT~
N1*ST*PHILLY ONTARIO*93*145~
N3*2560 E PHILADELPHIA STREET~
N4*ONTARIO*CA*91761*USA~
OID*31622443*1669889*14095743*CA*2560*L*47972.53*E*0~
L3*47972.53*G~
SE*41*34341~
GE*1*204012314~
IEA*1*000048322~";

            var message = Encoding.UTF8.GetBytes(edi);


            // Load the S/MIME certificate
            //X509Certificate2 cert = new X509Certificate2(@"cert.pfx", "password");
            //var cert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");


            // Create the S/MIME message
            //ContentInfo contentInfo = new ContentInfo(message);
            //EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);
            //CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, cert);
            //envelopedCms.Encrypt(recipient);

            //var asd = envelopedCms.Encode();

            //var encrypted = AS2HelperV3.Encrypt(message, cert);

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
            var signature = AS2HelperV3.Sign(message, alvysPrivateKey.Private);

            // verify signature
            var alvysPublicCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var alvysPublicKey = new X509CertificateParser().ReadCertificate(alvysPublicCert.GetRawCertData()).GetPublicKey();
            var validSignature = AS2HelperV3.VerifySignature(message, signature, alvysPublicKey);

            if (validSignature == false)
            {
                throw new Exception("Signature check failed");
            }

            // Create the HTTP request body
            var body = AS2HelperV3.PackMessageToBeSend(message, signature, "fileName", "txt", $"fileName_{DateTimeOffset.UtcNow}");

            Console.WriteLine(body);

            //var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\Niagara.cer");

            //var encryptedBody = AS2HelperV3.Encrypt(Encoding.UTF8.GetBytes(body), publicNiagaraCert);

            //Console.WriteLine(Convert.ToBase64String(encryptedBody));

            //// test decrypt
            //var privateNiagaraKey = LoadPrivateKey($"{CertificateFolderPath}\\Niagara-private.pem");
            //var decrypted = AS2HelperV3.Decrypt(encryptedBody, privateNiagaraKey.Private);

            //Console.WriteLine("-----------------------------------------------------");
            //Console.WriteLine(Convert.ToBase64String(decrypted));

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
            var encrypted = AS2HelperV3.Encrypt(Encoding.UTF8.GetBytes(message), publicNiagaraCert);

            var privateNiagaraKey = LoadPrivateKey($"{CertificateFolderPath}\\Niagara-private.pem");
            var decrypted = AS2HelperV3.Decrypt(encrypted, privateNiagaraKey.Private);

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
            var signature = AS2HelperV3.Sign(Encoding.UTF8.GetBytes(message), privateKey.Private);

            var publicCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var publicKey = new X509CertificateParser().ReadCertificate(publicCert.GetRawCertData()).GetPublicKey();
            var verifySigned = AS2HelperV3.VerifySignature(Encoding.UTF8.GetBytes(message), signature, publicKey);

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
            var signature = AS2HelperV3.Sign(Encoding.UTF8.GetBytes(message), alvysPrivateKey.Private);

            var publicNiagaraCert = new X509Certificate2($"{CertificateFolderPath}\\Niagara.cer");
            var encrypted = AS2HelperV3.Encrypt(Encoding.UTF8.GetBytes(message), publicNiagaraCert);

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("Signature: " + Encoding.UTF8.GetString(signature));
            Console.WriteLine();
            Console.WriteLine("encrypted message: " + Encoding.UTF8.GetString(encrypted));
            Console.WriteLine();

            // Niagara part
            var privateNiagaraKey = LoadPrivateKey($"{CertificateFolderPath}\\Niagara-private.pem");
            var decrypted = AS2HelperV3.Decrypt(encrypted, privateNiagaraKey.Private);

            var alvysPublicCert = new X509Certificate2($"{CertificateFolderPath}\\AH100-Alvys.cer");
            var alvysPublicKey = new X509CertificateParser().ReadCertificate(alvysPublicCert.GetRawCertData()).GetPublicKey();
            var verifySigned = AS2HelperV3.VerifySignature(decrypted, signature, alvysPublicKey);

            Console.WriteLine("decrypted message: " + Encoding.UTF8.GetString(decrypted));
            Console.WriteLine();
            Console.WriteLine("is verified message: " + verifySigned);
        }

        static X509Certificate2 GenerateCertificate()
        {
            var fileName = $"1AL363-{DateTimeOffset.UtcNow.ToString("yyyyMMdd")}";
            var attributes = "C=US, O=Alvys Logistics, CN=AL363";

            var x509Certificate = Cryptography.GenerateCertificate(attributes, attributes, 6);

            //now let us write the certificates files to the folder 
            File.WriteAllBytes($"{CertificateFolderPath}\\{fileName}.cer", x509Certificate.Certificate.RawData);
            //File.WriteAllBytes(folder + "\\" + "X509Cert.der", X509RootCert.RawData);

            string PublicPEMFile = $"{CertificateFolderPath}\\{fileName}-public.pem";
            string PrivatePEMFile = $"{CertificateFolderPath}\\{fileName}-private.pem";

            //now let us also create the PEM file as well in case we need it
            using (TextWriter textWriter = new StreamWriter(PublicPEMFile, false))
            {
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(x509Certificate.KeyPair.Public);
                pemWriter.Writer.Flush();
            }

            //now let us also create the PEM file as well in case we need it
            using (TextWriter textWriter = new StreamWriter(PrivatePEMFile, false))
            {
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(x509Certificate.KeyPair.Private);
                pemWriter.Writer.Flush();
            }

            return x509Certificate.Certificate;
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