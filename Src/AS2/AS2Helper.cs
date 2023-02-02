﻿using Org.BouncyCastle.Asn1.Ocsp;
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

            // Sign the encrypted message
            byte[] signedMessage = Sign(encryptedMessage, senderPrivateKey);

            // Verify the signature
            var publicKey = new X509CertificateParser().ReadCertificate(recipientCert.GetRawCertData()).GetPublicKey();
            bool isValidSignature = VerifySignature(encryptedMessage, publicKey);

            //var decrypted = Decrypt(encryptedMessage, );

            Console.WriteLine("Original message: " + message);
            Console.WriteLine();
            Console.WriteLine("Signed message: " + Encoding.UTF8.GetString(signedMessage));
            Console.WriteLine();
            Console.WriteLine("Encrypted message: " + Encoding.UTF8.GetString(encryptedMessage));
            Console.WriteLine();
            Console.WriteLine("Signature validity: " + isValidSignature);

            return signedMessage;
        }

        public static byte[] Encrypt(byte[] data, X509Certificate2 recipientCertificate)
        {
            var certificate = new X509CertificateParser().ReadCertificate(recipientCertificate.GetRawCertData());
            var pubKey = certificate.GetPublicKey();

            var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            cipher.Init(true, pubKey);
            return cipher.DoFinal(data);

            //IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine());
            //cipher.Init(true, pubKey);
            //return cipher.ProcessBlock(data, 0, data.Length);

            //IAsymmetricBlockCipher cipher = new Pkcs1Encoding(new RsaEngine());
            //cipher.Init(true, pubKey);
            //int blockSize = cipher.GetInputBlockSize();
            //int outputSize = cipher.GetOutputBlockSize();
            //List<byte> encryptedData = new List<byte>();
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

        public static bool VerifySignature(byte[] signedData, AsymmetricKeyParameter recipientPublicKey)
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

        public static byte[] Decrypt(byte[] encryptedMessage, AsymmetricKeyParameter privateKey)
        {
            var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            cipher.Init(false, privateKey);
            return cipher.DoFinal(encryptedMessage);

            //// Create the decrypter
            //CmsEnvelopedDataParser decrypter = new CmsEnvelopedDataParser(encryptedMessage);
            //RecipientInformationStore recipients = decrypter.GetRecipientInfos();
            //RecipientInformation recipient = recipients.GetFirstRecipient();
            //byte[] decryptedContent = recipient.GetContent(privateKey);

            //return decryptedContent;
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
