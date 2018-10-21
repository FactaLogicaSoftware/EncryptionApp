namespace CryptoTools
{
    public sealed class Scrypt : KeyDerive
    {
        private readonly (ulong N, uint r, uint p) _tuneFlags;

        public Scrypt(byte[] key, byte[] salt, (ulong N, uint r, uint p) tuneFlags)
        {
            _tuneFlags = tuneFlags;
            Salt = salt;
            Key = key;
        }

        public override void GetBytes(byte[] toFill)
        {
            toFill = Replicon.Cryptography.SCrypt.SCrypt.DeriveKey(Key, Salt, _tuneFlags.N, _tuneFlags.r, _tuneFlags.p, (uint)toFill.Length);
        }

        public override void Reset()
        {
            // doesn't do anything as the Replicon implementation of SCrypt doesn't use an object
        }
    }
}