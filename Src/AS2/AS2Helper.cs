using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

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
            var contentInfo = new ContentInfo(message);

            var signedCms = new SignedCms(contentInfo, true);
            var cmsSigner = new CmsSigner(certificate);

            signedCms.ComputeSignature(cmsSigner);
            byte[] signature = signedCms.Encode();

            return signature;
        }

        private static byte[] Encrypt(byte[] message, string recipientCerteficate, string encryptionAlgorithm)
        {
            var certificate = new X509Certificate2(recipientCerteficate);
            var contentInfo = new ContentInfo(message);

            var envelopedCms = new EnvelopedCms(contentInfo, new AlgorithmIdentifier(new System.Security.Cryptography.Oid(encryptionAlgorithm))); // should be 3DES or RC2
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
}
