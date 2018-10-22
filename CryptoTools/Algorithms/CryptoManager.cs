using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools.Algorithms
{
    public abstract class CryptoManager
    {
        private protected SymmetricAlgorithm SymmetricAlgorithm;

        public abstract byte[] EncryptBytes(byte[] data, byte[] key, byte[] iv);

        public abstract byte[] DecryptBytes(byte[] data, byte[] key, byte[] iv);
    }
}