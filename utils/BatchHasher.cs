using System;
using System.Security.Cryptography;

namespace utils
{
    public class BatchHasher
    {

        public static byte[] generateSalt()
        {
            var csprng = new RNGCryptoServiceProvider();
            var salt = new byte[24];
            csprng.GetBytes(salt);
            return salt;
        }

        public static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine(@"Please give a word followed by a salt, seperated by a comma (with no spaces) to be hashed
                E.g beep,gxsnfYvKQIExdD233H8rpkx8MKp8KhdD - not beep, gxsnfYvKQIExdD233H8rpkx8MKp8KhdD");
                return 1;
            }
            byte[] salt = new byte[24];
            var SplitArgs = new string[args.Length][];
            for (int i = 0; i < args.Length; i++)
            {
                SplitArgs[i] = args[i].Split(',');
                if(SplitArgs[i].Length == 1)
                {
                    Console.WriteLine("No salt detected - salt will be generated");
                    salt = generateSalt();
                }
            }

            var hashes = new byte[args.Length][];
            for (int i = 0; i < args.Length; i++)
            {
                byte[] hashValue;
                

                //Generate hash using salt
                using (var pbkdf2 = new Rfc2898DeriveBytes(SplitArgs[i][0], Convert.FromBase64String(SplitArgs[i][1]), 100000))
                {
                    hashValue = pbkdf2.GetBytes(24);
                }
                hashes[i] = hashValue;
            }
            Console.WriteLine("Hashes come first, followed by a hiphen ('-') then the salt: ");
            for (int i = 0; i < args.Length; i++)
            {
                Console.WriteLine(Convert.ToBase64String(hashes[i]) + " - " + SplitArgs[i][1]);
            }

        return 0;
        }
    }
}