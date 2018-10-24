using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;

namespace Encryption_App
{
    /// <summary>
    /// The class used to create and transform performance values to
    /// KDF tuning parameters
    /// </summary>
    public sealed class PerformanceDerivative
    {
        private const ulong Pbkdf2Iterations = 1000;

        /// <summary>
        /// The base performance derivative value
        /// </summary>
        public ulong PerformanceDerivativeValue { get; private set; }

        /// <summary>
        /// The desired number of milliseconds
        /// </summary>
        public ulong Milliseconds { get; set; }

        /// <summary>
        /// The default constructor, uses 1000 desired milliseconds
        /// </summary>
        public PerformanceDerivative()
        {
            GeneratePerformanceDerivative();
            Milliseconds = 1000;
        }

        /// <summary>
        /// Manually sets the performance derivative value, uses 1000
        /// desired milliseconds
        /// </summary>
        /// <param name="performanceDerivative"></param>
        public PerformanceDerivative(ulong performanceDerivative)
        {
            PerformanceDerivativeValue = performanceDerivative;
            Milliseconds = 1000;
        }

        /// <summary>
        /// Generates a new performance derivative value based off this PC's
        /// performance
        /// </summary>
        /// <returns>Rhe generated value</returns>
        public ulong GeneratePerformanceDerivative()
        {
            Stopwatch watch = Stopwatch.StartNew();

            var rand = new Random();
            var salt = new byte[256 / 8];
            var buff = new byte[256 / 8];
            rand.NextBytes(salt);

            // TODO manage overflow
            var test = new Pbkdf2KeyDerive("Hello World", salt, checked((int)Pbkdf2Iterations));

            long a = watch.ElapsedMilliseconds;

            buff = test.GetBytes(buff.Length);

            long b = watch.ElapsedMilliseconds - a;

            PerformanceDerivativeValue = (ulong)b;

#if DEBUG
            Console.WriteLine("Initialization time" + Convert.ToString(a));
            Console.WriteLine("Derivation time" + Convert.ToString(b));
#endif

            return PerformanceDerivativeValue;
        }

        /// <summary>
        /// Transforms the current performance derivative value to a number
        /// of iterations for Rfc2898DeriveBytes
        /// </summary>
        /// <param name="milliseconds">The desired number of milliseconds</param>
        /// <returns>The number of iterations to perform to get the
        /// desired time</returns>
        public ulong TransformToRfc2898(ulong milliseconds)
        {
            return milliseconds / PerformanceDerivativeValue * 1250;
        }

#warning "Parameter has no signficance at the moment"
        /// <summary>
        /// Transforms the current performance derivative value to
        /// to a tuple (N, r, p) of SCrypt tuning values
        /// </summary>
        /// <param name="milliseconds">The desired number of milliseconds</param>
        /// <returns>The tuning parameters for SCrypt to get the
        /// desired time</returns>
        public (int N, int r, int p) TransformToScryptTuning(ulong milliseconds)
        {
            // TODO manage overflow
            return (checked((int)Math.Pow(2, 19)), 8, 1);
        }

#warning "Parameter has no signficance at the moment"
        public (int N, int r, int p) TransformToArgon2Tuning(ulong milliseconds)
        {
            return (3, 1024 * 128, 1);
        }
    }
}
