using System;
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;

#pragma warning disable 0414, CA2213

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Asymmetric
{
    public sealed class RsaCryptoManager : AsymmetricCryptoManager, IDisposable
    {
        private readonly int _memoryConst;
        private readonly RSA _algorithm;

        public RsaCryptoManager()
        {
            // Default memory - TODO Calculate to higher numbers if possible
            _memoryConst = 1024 * 1024 * 4;

            // As the default aes transformation object is AesCng which is FIPS compliant
            IsFipsCompliant = true;

            _algorithm = new RSACng();
        }

        public override byte[] EncryptBytesWithPubKey(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public override byte[] DecryptBytesWithPubKey(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptBytesWithPrivKey(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        public override byte[] DecryptBytesWithPrivKey(byte[] data, byte[] key)
        {
            throw new NotImplementedException();
        }

        [SuppressMessage("Microsoft.Usage", "CA2213:DisposableFieldsShouldBeDisposed", MessageId = nameof(_algorithm), Justification = "Glitched - should not warn")]
        public void Dispose()
        {

            _algorithm?.Dispose();
        }
    }
}