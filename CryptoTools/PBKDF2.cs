using System;
using System.Security.Cryptography;
using Replicon.Cryptography.SCrypt;

namespace CryptoTools
{
    public sealed class Pbkdf2 : KeyDerive
    {
        private new readonly Rfc2898DeriveBytes _baseObject;
        private readonly ulong _iterations;

        public Pbkdf2(byte[] key, byte[] salt, ulong iterations)
        {
            _iterations = iterations;
            Salt = salt;
            Key = key;
            _baseObject = new Rfc2898DeriveBytes(Key, Salt, checked((int)_iterations)
        }

        public override void GetBytes(byte[] toFill)
        {
            toFill = _baseObject.GetBytes(toFill.Length);
        }

        public override void Reset()
        {
            _baseObject.Reset();
        }
    }
}
