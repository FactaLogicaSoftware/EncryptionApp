#pragma warning disable 0414, CA2213

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Asymmetric
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Security.Cryptography;

    public sealed class RsaCryptoManager : AsymmetricCryptoManager, IDisposable
    {
        private readonly RSA _algorithm;

        private readonly int _memoryConst;

        public RsaCryptoManager()
        {
            this._memoryConst = 1024 * 1024 * 4;

            this.IsNistCompliant = true;

            this._algorithm = new RSACng();
        }

        public override byte[] DecryptBytes(byte[] data, byte[] privateKey)
        {
            throw new NotImplementedException();
        }

        [SuppressMessage("Microsoft.Usage", "CA2213:DisposableFieldsShouldBeDisposed", MessageId = nameof(_algorithm), Justification = "Glitched - should not warn")]
        public void Dispose()
        {
            this._algorithm?.Dispose();
        }

        public override byte[] EncryptBytes(byte[] data, byte[] publicKey)
        {
            throw new NotImplementedException();
        }
    }
}