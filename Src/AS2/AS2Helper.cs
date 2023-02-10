using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System.IO;
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

            // Sign the encrypted message
            byte[] signature = Sign(encryptedMessage, senderPrivateKey);

            // Verify the signature
            var publicKey = new X509CertificateParser().ReadCertificate(recipientCert.GetRawCertData()).GetPublicKey();
            bool isValidSignature = VerifySignature(Encoding.UTF8.GetBytes(message), signature, publicKey);

            //var decrypted = Decrypt(encryptedMessage, );

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("Signed message: " + Encoding.UTF8.GetString(signature));
            Console.WriteLine();
            Console.WriteLine("Encrypted message: " + Encoding.UTF8.GetString(encryptedMessage));
            Console.WriteLine();
            Console.WriteLine("Signature validity: " + isValidSignature);

            return signature;
        }

        public static byte[] Encrypt(byte[] data, X509Certificate2 recipientCertificate)
        {
            var certificate = new X509CertificateParser().ReadCertificate(recipientCertificate.GetRawCertData());
            var pubKey = certificate.GetPublicKey();

            var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            cipher.Init(true, pubKey);
            return cipher.DoFinal(data);

            //var cipher = new Pkcs1Encoding(new RsaEngine());
            //cipher.Init(true, pubKey);
            //return cipher.ProcessBlock(data, 0, data.Length);

            //var cipher = new RsaEngine();
            //cipher.Init(true, pubKey);
            //return cipher.ProcessBlock(data, 0, data.Length);

            //var cipher = new Pkcs1Encoding(new RsaEngine());
            //cipher.Init(true, pubKey);
            //var blockSize = cipher.GetInputBlockSize();
            //var encryptedData = new List<byte>();
            //for (int i = 0; i < data.Length; i += blockSize)
            //{
            //    int length = Math.Min(blockSize, data.Length - i);
            //    byte[] encryptedBlock = cipher.ProcessBlock(data, i, length);
            //    encryptedData.AddRange(encryptedBlock);
            //}
            //return encryptedData.ToArray();
        }

        private static AsymmetricKeyParameter ToAsymmetricKeyParameter(X509Certificate2 certificate)
        {
            return PublicKeyFactory.CreateKey(certificate.GetPublicKey());
        }

        public static byte[] Sign(byte[] data, AsymmetricCipherKeyPair keyPair)
        {
            //X509Certificate2 senderCertificate = LoadCertificate(senderCertificatePath, senderCertificatePassword);
            //AsymmetricCipherKeyPair keyPair = LoadPrivateKey(senderPrivateKeyPath);

            ISigner signer = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            signer.Init(true, keyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public static bool VerifySignature(byte[] message, byte[] signature, AsymmetricKeyParameter recipientPublicKey)
        {
            //X509Certificate2 recipientCertificate = LoadCertificate(recipientCertificatePath);
            //AsymmetricKeyParameter publicKey = LoadPublicKey(recipientPublicKey);

            ISigner signer = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);

            //var publicKey = recipientPublicKey.GetRSAPublicKey();
            //var publicKey2 = recipientPublicKey.PublicKey.Key;


            signer.Init(false, recipientPublicKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);

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

        public static byte[] Decrypt(byte[] encryptedMessage, AsymmetricKeyParameter privateKey)
        {
            var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            cipher.Init(false, privateKey);
            return cipher.DoFinal(encryptedMessage);

            //var engine = new RsaEngine();
            //engine.Init(false, privateKey);
            //var r = engine.ProcessBlock(encryptedMessage, 0, encryptedMessage.Length);
            //return r;

            //// Create the decrypter
            //CmsEnvelopedDataParser decrypter = new CmsEnvelopedDataParser(encryptedMessage);
            //RecipientInformationStore recipients = decrypter.GetRecipientInfos();
            //RecipientInformation recipient = recipients.GetFirstRecipient();
            //byte[] decryptedContent = recipient.GetContent(privateKey);
            //return decryptedContent;

            //var cipher = new Pkcs1Encoding(new RsaEngine());
            //cipher.Init(false, privateKey);
            //var blockSize = cipher.GetOutputBlockSize();
            //var decryptedData = new List<byte>();
            //for (int i = 0; i < encryptedMessage.Length; i += blockSize)
            //{
            //    int length = Math.Min(blockSize, encryptedMessage.Length - i);
            //    byte[] decryptedBlock = cipher.ProcessBlock(encryptedMessage, i, length);
            //    decryptedData.AddRange(decryptedBlock);
            //}
            //return decryptedData.ToArray();
        }

        //static byte[] VerifySignature(byte[] decryptedContent)
        //{

        //    // Verify the signature
        //    CmsSignedDataParser signedData = new CmsSignedDataParser(decryptedContent);
        //    SignerInformationStore signers = signedData.GetSignerInfos();
        //    SignerInformation signer = signers.GetFirstSigner();
        //    if (signer.Verify(signedData.GetSigningCertificate().GetPublicKey()))
        //    {
        //        // Signature is valid
        //    }
        //    else
        //    {
        //        // Signature is invalid
        //    }
        //}

        public static string PackMessageToBeSend(byte[] message, byte[] signedMessage, string fileName, string fileExtension, string boundary)
        {
            var boundaryWithDash = boundary;

            if (!boundaryWithDash.StartsWith("--"))
            {
                boundaryWithDash = "--" + boundary;
            }

            var m = new StringBuilder();

            //m.Append(@"To: someone@somewhere.com
            //        From: another@somewhereelse.com
            //        Subject: Welcome to MIME
            //        Message-ID: <7649a04d-1466-3493-e8a7-7c5084d12285@adroitlogic.com>
            //        Date: Sun, 15 Aug 2021 23:00:30 +0530
            //        MIME-Version: 1.0");

            m.AppendLine($"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=\"sha-256\"; boundary=\"{boundary}\""); //multipart/report; report-type=\"disposition-notification\";
            m.AppendLine($"Subject: Transfer EDI file {fileName}.{fileExtension}");
            m.AppendLine();

            m.AppendLine(boundaryWithDash);
            //m.Append($"Content-Disposition: attachment; filename=\"{fileName}.{fileExtension}\"");
            //m.Append($"Content-Type: application/octet-stream; charset=\"ascii\"; name=\"{fileName}.{fileExtension}\"");
            m.AppendLine("Content-Type: application/octet-stream");
            m.AppendLine("Content-Transfer-Encoding: base64"); // or "binary"?
            m.AppendLine();
            m.AppendLine(Convert.ToBase64String(message));

            m.AppendLine(boundaryWithDash);
            m.AppendLine("Content-Type: application/pkcs7-signature; name=smime.p7s; smime-type=signed-data");
            m.AppendLine("Content-Transfer-Encoding: base64"); // or "binary"?
            m.AppendLine("Content-Disposition: attachment; filename=\"smime.p7s\"");
            m.AppendLine("Content-Description: S/MIME Cryptographic Signature");
            m.AppendLine();
            m.AppendLine(Convert.ToBase64String(signedMessage));

            m.Append(boundaryWithDash);

            return m.ToString();
        }
    }

    public static class AS2HelperV3
    {
        public static byte[] Sign(byte[] message, AsymmetricKeyParameter privateKey)
        {
            var signer = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            signer.Init(true, privateKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }

        public static bool VerifySignature(byte[] message, byte[] signedMessage, AsymmetricKeyParameter publicKey)
        {
            var signer = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
            signer.Init(false, publicKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signedMessage);
        }

        public static byte[] Encrypt(byte[] message, X509Certificate2 recipientCertificate)
        {
            var certificate = new X509CertificateParser().ReadCertificate(recipientCertificate.GetRawCertData());
            var pubKey = certificate.GetPublicKey();

            var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            cipher.Init(true, pubKey);
            return cipher.DoFinal(message);
        }

        public static byte[] Decrypt(byte[] encryptedMessage, AsymmetricKeyParameter privateKey)
        {
            var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            cipher.Init(false, privateKey);
            return cipher.DoFinal(encryptedMessage);
        }

        public static string PackMessageToBeSend(byte[] message, byte[] signedMessage, string fileName, string fileExtension, string boundary)
        {
            var boundaryWithDash = boundary;

            if (!boundaryWithDash.StartsWith("--"))
            {
                boundaryWithDash = "--" + boundary;
            }

            var m = new StringBuilder();

            //m.Append(@"To: someone@somewhere.com
            //        From: another@somewhereelse.com
            //        Subject: Welcome to MIME
            //        Message-ID: <7649a04d-1466-3493-e8a7-7c5084d12285@adroitlogic.com>
            //        Date: Sun, 15 Aug 2021 23:00:30 +0530
            //        MIME-Version: 1.0");

            m.AppendLine($"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=\"sha-256\"; boundary=\"{boundary}\""); //multipart/report; report-type=\"disposition-notification\";
            m.AppendLine($"Subject: Transfer EDI file {fileName}.{fileExtension}");
            m.AppendLine();

            m.AppendLine(boundaryWithDash);
            //m.Append($"Content-Disposition: attachment; filename=\"{fileName}.{fileExtension}\"");
            //m.Append($"Content-Type: application/octet-stream; charset=\"ascii\"; name=\"{fileName}.{fileExtension}\"");
            m.AppendLine("Content-Type: application/octet-stream");
            m.AppendLine("Content-Transfer-Encoding: base64"); // or "binary"?
            m.AppendLine();
            m.AppendLine(Convert.ToBase64String(message));

            m.AppendLine(boundaryWithDash);
            m.AppendLine("Content-Type: application/pkcs7-signature; name=smime.p7s; smime-type=signed-data");
            m.AppendLine("Content-Transfer-Encoding: base64"); // or "binary"?
            m.AppendLine("Content-Disposition: attachment; filename=\"smime.p7s\"");
            m.AppendLine("Content-Description: S/MIME Cryptographic Signature");
            m.AppendLine();
            m.AppendLine(Convert.ToBase64String(signedMessage));

            m.Append(boundaryWithDash);

            return m.ToString();
        }
    }
}
