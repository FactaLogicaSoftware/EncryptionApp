using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools
{
    public class WindowsDerivedCryptoManager
    {
        public static byte[] GenerateEntropy()
        {
            var entropy = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(entropy);

            return entropy;
        }

        public static byte[] GenerateEntropy(int length)
        {
            var entropy = new byte[length];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(entropy);

            return entropy;
        }

        public static byte[] EncryptKey(byte[] key)
        {
            return ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
        }

        public static byte[] DecryptKey(byte[] encryptedKey)
        {
            return ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);
        }
    }
}