using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AS2
{
    public static class AS2Helper
    {
        public static byte[] Package(byte[] message, string signerCertificate, string signerPassword, string recipientCertificate, string encryptionAlgorithm)
        {
            Sign(message, signerCertificate, signerPassword);
            Encrypt(message, recipientCertificate, encryptionAlgorithm);
            return message;
        }

        public static byte[] Unpackage(byte[] file)
        {
            Decript(file);
            VerifySignature(file);
            return file;
        }

        private static byte[] Sign(byte[] message, string signerCertificate, string signerPassword)
        {
            var certificate = new X509Certificate2(signerCertificate, signerPassword);
            var contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(message);

            var signedCms = new SignedCms(contentInfo, true);
            var cmsSigner = new CmsSigner(certificate);

            signedCms.ComputeSignature(cmsSigner);
            byte[] signature = signedCms.Encode();

            return signature;
        }

        private static byte[] Encrypt(byte[] message, string recipientCerteficate, string encryptionAlgorithm)
        {
            var certificate = new X509Certificate2(recipientCerteficate);
            var contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(message);

            var envelopedCms = new EnvelopedCms(contentInfo, new System.Security.Cryptography.Pkcs.AlgorithmIdentifier(new System.Security.Cryptography.Oid(encryptionAlgorithm))); // should be 3DES or RC2
            var recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, certificate);

            envelopedCms.Encrypt(recipient);
            byte[] encoded = envelopedCms.Encode();

            return encoded;
        }

        private static byte[] Decript(byte[] encodedEncryptedMessage)
        {
            var envelopedCms = new EnvelopedCms();

            // NB. the message will have been encrypted with your public key.
            // The corresponding private key must be installed in the Personal Certificates folder of the user
            // this process is running as.
            envelopedCms.Decode(encodedEncryptedMessage);

            envelopedCms.Decrypt();
            var encryptionAlgorithmName = envelopedCms.ContentEncryptionAlgorithm.Oid.FriendlyName;

            //return envelopedCms.Decrypt();
            //return envelopedCms.Encode();
            return null;
        }

        private static byte[] VerifySignature(byte[] file)
        {
            return file;
        }
    }

    public static class AS2HelperV2
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        /// <param name="recipientCert">Niagara</param>
        /// <param name="senderPrivateKey">Alvys</param>
        /// <returns></returns>
        public static byte[] Package(string message, X509Certificate2 recipientCert, AsymmetricCipherKeyPair senderPrivateKey)
        {
            // Encrypt the message
            byte[] encryptedMessage = Encrypt(Encoding.UTF8.GetBytes(message), recipientCert);
            //byte[] encryptedMessage = Encoding.UTF8.GetBytes(message);

            // Sign the encrypted message
            byte[] signedMessage = Sign(encryptedMessage, senderPrivateKey);

            // Verify the signature
            //var publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(recipientCert.PublicKey.EncodedKeyValue.RawData);
            var publicKey = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(recipientCert.GetRawCertData());
            AsymmetricKeyParameter pubKey = publicKey.GetPublicKey();
            bool isValidSignature = VerifySignature(signedMessage, pubKey);

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("Encrypted message: " + Encoding.UTF8.GetString(encryptedMessage));
            Console.WriteLine();
            Console.WriteLine("Signed message: " + Encoding.UTF8.GetString(signedMessage));
            Console.WriteLine();
            Console.WriteLine("Signature validity: " + isValidSignature);

            return signedMessage;
        }

        static byte[] Encrypt(byte[] data, X509Certificate2 recipientCertificate)
        {
            //RsaKeyParameters publicKey = LoadPublicKey(recipientPublicKeyPath);
            //IBufferedCipher cipher = new Pkcs1Encoding(new RsaEngine());
            //X509Certificate2 recipientCertificate = LoadCertificate(recipientCertificatePath);

            //var rsa = recipientCertificate.PublicKey.GetRSAPublicKey();
            //var x = rsa.ExportParameters(false);


            //SubjectPublicKeyInfo subInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsa);
            //AsymmetricKeyParameter testpublicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(subInfo);

            var privateCertBouncy = new X509CertificateParser().ReadCertificate(recipientCertificate.GetRawCertData());
            AsymmetricKeyParameter pubKey = privateCertBouncy.GetPublicKey();


            ///
            //var key = recipientCertificate.GetPublicKey();
            //var publicKey2 = PublicKeyFactory.CreateKey(key);
            //RsaKeyParameters publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(recipientCertificate.PublicKey.EncodedKeyValue.RawData);



            //var rsa = recipientCertificate.GetRSAPublicKey();
            //var rsaParams = rsa.ExportParameters(false);
            //var publicKey = new RsaKeyParameters(false, new BigInteger(rsaParams.Modulus), new BigInteger(rsaParams.Exponent));

            //RsaKeyParameters key = (RsaKeyParameters)recipientCertificate.GetPublicKey();
            //// Construct a microsoft RSA crypto service provider using the public key in the certificate
            //RSAParameters param = new RSAParameters();
            //param.Exponent = key.Exponent.ToByteArrayUnsigned();
            //param.Modulus = key.Modulus.ToByteArrayUnsigned();

            IBufferedCipher cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            //IAsymmetricBlockCipher cipher = new Pkcs1Encoding(new RsaEngine());

            cipher.Init(true, pubKey);
            return cipher.DoFinal(data);
        }

        private static AsymmetricKeyParameter ToAsymmetricKeyParameter(X509Certificate2 certificate)
        {
            return PublicKeyFactory.CreateKey(certificate.GetPublicKey());
        }

        static byte[] Sign(byte[] data, AsymmetricCipherKeyPair keyPair)
        {
            //X509Certificate2 senderCertificate = LoadCertificate(senderCertificatePath, senderCertificatePassword);
            //AsymmetricCipherKeyPair keyPair = LoadPrivateKey(senderPrivateKeyPath);

            ISigner signer = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            signer.Init(true, keyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        static bool VerifySignature(byte[] signedData, AsymmetricKeyParameter recipientPublicKey)
        {
            //X509Certificate2 recipientCertificate = LoadCertificate(recipientCertificatePath);
            //AsymmetricKeyParameter publicKey = LoadPublicKey(recipientPublicKey);

            ISigner signer = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);

            //var publicKey = recipientPublicKey.GetRSAPublicKey();
            //var publicKey2 = recipientPublicKey.PublicKey.Key;


            signer.Init(false, recipientPublicKey);
            signer.BlockUpdate(signedData, 0, signedData.Length);
            return signer.VerifySignature(signedData);

            //signer.BlockUpdate(signedData, 0, signedData.Length - 128);
            //return signer.VerifySignature(signedData, signedData.Length - 128, 128);

            //signer.Init(false, recipientCertificate.PublicKey.Key);
            //signer.BlockUpdate(signedData, 0, signedData.Length - 20);
            //return signer.VerifySignature(signedData, signedData.Length - 20, 20);

            ////Base64 Decode
            //byte[] encodeBytes = UnicodeEncoding.ASCII.GetBytes(Signature);
            //byte[] decodeBytes;
            //using (MemoryStream decStream = new MemoryStream())
            //{
            //    base64.Decode(encodeBytes, 0, encodeBytes.Length, decStream);
            //    decodeBytes = decStream.ToArray();
            //}

            //return signer.VerifySignature(decodeBytes);
        }

        //static X509Certificate2 LoadCertificate(string certificatePath, string password = null)
        //{
        //    return string.IsNullOrEmpty(password)
        //        ? new X509Certificate2(certificatePath)
        //        : new X509Certificate2(certificatePath, password);
        //}

    }

    public static class AS2HelperV3
    {
        //public static void EncryptMessage(string message, X509Certificate recipientCertificate,
        //AsymmetricKeyParameter recipientPrivateKey, X509Certificate senderCertificate,
        //AsymmetricKeyParameter senderPrivateKey, out byte[] encryptedMessage, out byte[] signature)
        //{
        //    // Encrypt message
        //    IBufferedCipher cipher = CipherUtilities.GetCipher("DES/CBC/PKCS5Padding");
        //    KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), 128);
        //    KeyParameter key = (KeyParameter)new Pkcs5S2KeyWrapper(keyGenerationParameters).GenerateDerivedMacParameters(64);
        //    cipher.Init(true, new ParametersWithIV(key, key.GetKey()));
        //    encryptedMessage = cipher.DoFinal(Encoding.UTF8.GetBytes(message));

        //    // Sign message
        //    ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
        //    signer.Init(true, senderPrivateKey);
        //    signer.BlockUpdate(encryptedMessage, 0, encryptedMessage.Length);
        //    signature = signer.GenerateSignature();

        //    // Create AS2 message
        //    X509Certificate[] chain = new X509Certificate[] { senderCertificate };
        //    X509CertificateStructure[] certStructs = Array.ConvertAll(chain, X509CertificateStructure.GetInstance);
        //    As2SignedDataGenerator gen = new As2SignedDataGenerator();
        //    gen.AddSignerInfoGenerator(new As2SignerInfoGenerator(senderPrivateKey, senderCertificate, "sha256").SetDirectSignature(true));
        //    gen.AddCertificates(new X509Store(certStructs));
        //    gen.AddSignature();
        //    ApplicationPkcs7Mime pkcs7 = gen.Generate(new CmsProcessableByteArray(encryptedMessage), CmsSignedData.DontAddSignatureTimeStampToken);

        //    // Send AS2 message        ...
        //}
    }
}
