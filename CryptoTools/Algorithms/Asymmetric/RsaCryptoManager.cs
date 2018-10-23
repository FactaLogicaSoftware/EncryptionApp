using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Asymmetric
{
    public sealed class RsaCryptoManager : AsymmetricCryptoManager
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
    }
}
