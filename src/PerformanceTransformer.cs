using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_App
{
    internal class PerformanceTransformer
    {
        private readonly ulong PBKDF2Iterations;
        private ulong PerformanceDerivative { get; set; }

        public PerformanceTransformer()
        {
#if DEBUG
            Stopwatch watch = Stopwatch.StartNew();
#endif
            PBKDF2Iterations = 1000;

            // TODO manage overflow
            var test = new Rfc2898DeriveBytes("Hello World", 32, checked((int)PBKDF2Iterations));

            long a = watch.ElapsedMilliseconds;

            test.GetBytes(32);

            long b = watch.ElapsedMilliseconds - a;

            PerformanceDerivative = (ulong)b;

#if DEBUG
            Console.WriteLine(Resources.PerformanceTransformer_PerformanceTransformer_Initialization_time__ + Convert.ToString(a));
            Console.WriteLine(Resources.PerformanceTransformer_PerformanceTransformer_Derivation_time__ + Convert.ToString(b));
#endif
        }

        public int TransformToRfc2898(int milliseconds)
        {
            return milliseconds / ((int)PerformanceDerivative / (int)PBKDF2Iterations);
        }

        public (int n, int r, int p) TransformToScryptTuning(int milliseconds)
        {
            // TODO manage overflow
            return (checked((int)Math.Pow(2, 19)), 8, 1);
        }
    }
}
