namespace FactaLogicaSoftware.CryptoTools.PerformanceInterop
{
    using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
    using System;
    using System.Diagnostics;

    /// <summary>
    /// The class used to create and transform performance values to
    /// KDF tuning parameters
    /// </summary>
    public sealed class PerformanceDerivative
    {
        private const int Pbkdf2Iterations = 1000;

        /// <summary>
        /// The default constructor, uses 1000 desired milliseconds
        /// </summary>
        public PerformanceDerivative()
        {
            this.GeneratePerformanceDerivative();
            this.Milliseconds = 2000;
        }

        /// <summary>
        /// Manually sets the performance derivative value, uses 1000
        /// desired milliseconds
        /// </summary>
        /// <param name="performanceDerivative"></param>
        public PerformanceDerivative(ulong performanceDerivative)
        {
            this.PerformanceDerivativeValue = performanceDerivative;
            this.Milliseconds = 2000;
        }

        /// <summary>
        /// The desired number of milliseconds
        /// </summary>
        public ulong Milliseconds { get; set; }

        /// <summary>
        /// The base performance derivative value
        /// </summary>
        public ulong PerformanceDerivativeValue { get; private set; }

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

            var test = new Pbkdf2KeyDerive("Hello World", salt, Pbkdf2Iterations);

            long a = watch.ElapsedMilliseconds;

            test.GetBytes(buff.Length);

            long b = watch.ElapsedMilliseconds - a;

            this.PerformanceDerivativeValue = (ulong)b;

            return this.PerformanceDerivativeValue;
        }

        /// <summary>
        /// Transforms the current performance derivative value to
        /// to a tuple (N, r, p) of argon2 tuning values
        /// </summary>
        /// <param name="milliseconds">The desired number of milliseconds</param>
        /// <returns>The tuning parameters for argon to get the
        /// desired time</returns>
        public (ulong N, uint r, uint p) TransformToArgon2Tuning(ulong milliseconds)
        {
            return (3, 1024 * 128, 1);
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
            return milliseconds / this.PerformanceDerivativeValue * 1250;
        }

        /// <summary>
        /// Transforms the current performance derivative value to
        /// to a tuple (N, r, p) of SCrypt tuning values
        /// </summary>
        /// <param name="milliseconds">The desired number of milliseconds</param>
        /// <returns>The tuning parameters for SCrypt to get the
        /// desired time</returns>
        public (ulong N, uint r, uint p) TransformToScryptTuning(ulong milliseconds)
        {
            return (checked((ulong)Math.Pow(2, 19)), 8U, 1U);
        }
    }
}