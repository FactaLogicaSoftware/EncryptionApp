using System;
using System.Security.Cryptography;

namespace PBKDF2Hasher
{
    private static byte[] GenerateSalt()
    {
        var csprng = new RNGCryptoServiceProvider();
        var salt = new byte[32];
        csprng.GetBytes(salt);
        return salt;
    }

    public static (byte[] hash, byte[] salt) pbkdf2hash(string password)
    {

        string password = "passwd";
        byte[] salt = GenerateSalt();//warning shouldnt be random salts - change when you try and decrypt no?
        int iterations = 100000;
        byte[] hashValue;
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations))
        {
            hashValue = pbkdf2.GetBytes(32);
        }
        return (hashValue,salt);
    }
}
