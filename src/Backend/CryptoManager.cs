namespace Encryption_App.Backend
{
    internal abstract class CryptoManager
    {
        public abstract byte[] EncryptBytes();
        
        public abstract bool DecryptBytes();
    }
}
