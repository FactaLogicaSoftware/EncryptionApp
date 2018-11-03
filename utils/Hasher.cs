using System;
using System.Security.Cryptography;

namespace PBKDF2Hasher
{
    public class Hasher
    {

        public static byte[] GenerateSalt()
        {
            var csprng = new RNGCryptoServiceProvider();
            var salt = new byte[32];
            csprng.GetBytes(salt);
            Console.WriteLine("Salt generated - {0}", Convert.ToBase64String(salt));
            return salt;
        }

        public static int GetIterations()
        {
            Console.WriteLine("Please enter a number of iterations. If no input is given the program will default to 1 million: ");
            
            int iterations;
            
            string input = Console.ReadLine();
            if (input == "")
            {
                Console.WriteLine("Using default iterations");
                return 1000000;
            }
            if (!Int32.TryParse(input, out iterations))
            {
                Console.WriteLine("Please enter a valid number");
                return GetIterations();
            }
            return iterations;
        }

        public static int Main(string[] args)
        {
            if (args.Length > 3 || args.Length == 0) 
            {
                Console.WriteLine("Please give a word to be hashed, and optionally a salt and an iteration number");
                return 1;
            }

            Byte[] salt;
            int iterations;
            
            if (args.Length > 1)
            {
                salt = Convert.FromBase64String(args[1]);
            }
            else
            {
                salt = GenerateSalt();
            }

            if (args.Length == 3)
            {
                iterations = Convert.ToInt32(args[3]);
            }
            else
            {
                iterations = GetIterations();
                
            }
            
            byte[] hashValue;

            //Generate hash using salt
            using (var pbkdf2 = new Rfc2898DeriveBytes(args[0], salt, iterations))
            {
                Console.WriteLine("Hashing...");
                hashValue = pbkdf2.GetBytes(64);
            }

            Console.WriteLine("\nHash: " + Convert.ToBase64String(hashValue) + "\n"  + "Salt: " + Convert.ToBase64String(salt));
            

        return 0;
        }
    }
}
