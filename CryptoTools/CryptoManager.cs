using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTools
{
    public abstract class CryptoManager
    {
        private protected SymmetricAlgorithm SymmetricAlgorithm;

        public abstract byte[] EncryptBytes(byte[] data, byte[] key, byte[] iv);

        public abstract byte[] DecryptBytes(byte[] data, byte[] key, byte[] iv);
    }
}