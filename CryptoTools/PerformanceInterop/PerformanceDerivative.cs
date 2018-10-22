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
    /// 
    /// </summary>
    public sealed class PerformanceDerivative
    {
        private const ulong Pbkdf2Iterations = 1000;
        public ulong PerformanceDerivativeValue { get; private set; }
        public ulong Milliseconds { get; set; }

        public PerformanceDerivative()
        {
            GeneratePerformanceDerivative();
            Milliseconds = 1000;
        }

        public PerformanceDerivative(ulong performanceDerivative)
        {
            PerformanceDerivativeValue = performanceDerivative;
            Milliseconds = 1000;
        }

        public ulong GeneratePerformanceDerivative()
        {
            Stopwatch watch = Stopwatch.StartNew();

            // TODO manage overflow
            var test = new Rfc2898DeriveBytes("Hello World", 32, checked((int)Pbkdf2Iterations));

            long a = watch.ElapsedMilliseconds;

            test.GetBytes(64); // we should never need more than 512 bits of a hash

            long b = watch.ElapsedMilliseconds - a;

            PerformanceDerivativeValue = (ulong)b;

#if DEBUG
            Console.WriteLine("Initialization time" + Convert.ToString(a));
            Console.WriteLine("Derivation time" + Convert.ToString(b));
#endif

            return PerformanceDerivativeValue;
        }

        public ulong TransformToRfc2898(ulong milliseconds)
        {
            return milliseconds / PerformanceDerivativeValue;
        }

#warning "Parameter has no signficance at the moment"
        public (int N, int r, int p) TransformToScryptTuning(ulong milliseconds)
        {
            // TODO manage overflow
            return (checked((int)Math.Pow(2, 19)), 8, 1);
        }
    }
}
