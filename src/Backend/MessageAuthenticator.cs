using System;
using System.IO;
using System.Security.Cryptography;

namespace Encryption_App
{
    class MessageAuthenticator
    {
        public void VerifyHMACFile(byte[] data, byte[] key)
        {
            byte[] hashKey;

            using (var hmac = new HMACSHA384(key))
            {
                if (key.Length > hmac.InputBlockSize)
                {
                    hashKey = hmac.ComputeHash(data);
                }
            }
        }

        public void VerifyHMACFile(byte[] data, byte[] key, Type TypeOfHash)
        {
            HMAC hmac;
            if (TypeOfHash.IsSubclassOf(typeof(HMAC)))
            {
                hmac = (HMAC)Activator.CreateInstance(TypeOfHash);
            }
            else
            {
                throw new ArgumentException("TypeOfHash is not a derivative of \"System.Security.Cryptorgaphy.HMAC\"");
            }
        }
    }
}
