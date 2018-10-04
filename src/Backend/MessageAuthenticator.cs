using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Encryption_App
{
    class MessageAuthenticator
    {
        public byte[] CreateHMAC(byte[] data, byte[] key)
        {
            byte[] hashKey;

            using (var hmac = new HMACSHA384(key))
            {
                hashKey = hmac.ComputeHash(data);
            }

            return hashKey;
        }

        public byte[] CreateHMAC(byte[] data, byte[] key, Type TypeOfHash)
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

            byte[] hashKey;

            using (hmac)
            {
                hashKey = hmac.ComputeHash(data);
            }

            return hashKey;
        }

        public bool VerifyHMAC(byte[] data, byte[] key, byte[] hash)
        {
            byte[] hashKey;

            using (var hmac = new HMACSHA384(key))
            {
                hashKey = hmac.ComputeHash(data);
            }

            if (data.SequenceEqual(hash))
            {
                return true;
            }

            return false;
        }

        public bool VerifyHMAC(byte[] data, byte[] key, byte[] hash, Type TypeOfHash)
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

            byte[] hashKey;

            using (hmac)
            {
                hashKey = hmac.ComputeHash(data);
            }

            if (data.SequenceEqual(hash))
            {
                return true;
            }

            return false;
        }
    }
}
