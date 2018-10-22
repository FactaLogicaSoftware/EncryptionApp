namespace FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric
{
    public interface ISymmetricCryptoManager
    {
        void EncryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv);

        void DecryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv);
    }
}
