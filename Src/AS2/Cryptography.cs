using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System.Security.Cryptography.X509Certificates;

namespace AS2
{
    class Cryptography
    {
        public static X509Certificate2 CreateCertificate(string subjectName, string issuer, int ValidMonths, out AsymmetricCipherKeyPair KeyPair, int keyStrength = 2048)
        {
            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            X509V3CertificateGenerator certificateGenerator = new();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(Org.BouncyCastle.Math.BigInteger.One, Org.BouncyCastle.Math.BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(issuer);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddMonths(ValidMonths);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, true, new KeyUsage(KeyUsage.KeyEncipherment));

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;
            KeyPair = subjectKeyPair;

            // Selfsign certificate
            certificateGenerator.SetSignatureAlgorithm("SHA256WithRSA");
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);
            certificate.CheckValidity();
            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());

            return x509;
        }

    }
}
