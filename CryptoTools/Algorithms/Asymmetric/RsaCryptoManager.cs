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
            
            IsNISTCompliant = true;

            _algorithm = new RSACng();
        }

        [SuppressMessage("Microsoft.Usage", "CA2213:DisposableFieldsShouldBeDisposed", MessageId = nameof(_algorithm), Justification = "Glitched - should not warn")]
        public void Dispose()
        {

            _algorithm?.Dispose();
        }

        public override byte[] EncryptBytes(byte[] data, byte[] PublicKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] DecryptBytes(byte[] data, byte[] PrivateKey)
        {
            throw new NotImplementedException();
        }
    }
}