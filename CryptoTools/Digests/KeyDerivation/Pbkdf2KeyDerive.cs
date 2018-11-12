namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    using FactaLogicaSoftware.CryptoTools.PerformanceInterop;
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Security.Cryptography;
    using System.Text;

    /// <inheritdoc cref="KeyDerive" />
    /// <summary>
    /// </summary>
    public sealed class Pbkdf2KeyDerive : KeyDerive, IDisposable
    {
        private readonly Rfc2898DeriveBytes _baseObject;

        /// <summary>
        /// Creates an instance of an object used to hash
        /// </summary>
        /// <param name="password">The bytes of the password to hash</param>
        /// <param name="salt">The salt used to hash</param>
        /// <param name="iterations">The number of iterations to use on the
        /// underlying Rfc2898DeriveBytes objects</param>
        public Pbkdf2KeyDerive(byte[] password, byte[] salt, int iterations)
        {
            this.PerformanceValues = iterations;
            this.Salt = salt;
            this.Password = password;
            this._baseObject = new Rfc2898DeriveBytes(this.Password, this.Salt, (int)this.PerformanceValues);
        }

        /// <summary>
        /// Creates an instance of an object used to hash
        /// </summary>
        /// <param name="password">The string of the password to hash</param>
        /// <param name="salt">The salt used to hash</param>
        /// <param name="iterations">The number of iterations to use on the
        /// underlying Rfc2898DeriveBytes objects</param>
        public Pbkdf2KeyDerive(string password, byte[] salt, int iterations)
        {
            this.PerformanceValues = iterations;
            this.Salt = salt;
            this.Password = Encoding.UTF8.GetBytes(password);
            this._baseObject = new Rfc2898DeriveBytes(this.Password, this.Salt, (int)this.PerformanceValues);
        }

        /// <inheritdoc />
        /// <summary>
        /// The password, stored encrypted
        /// </summary>
        public override byte[] Password
        {
            get => ProtectedData.Unprotect(this.BackEncryptedArray, null, DataProtectionScope.CurrentUser);
            private protected set
            {
                this.BackEncryptedArray = ProtectedData.Protect(value, null, DataProtectionScope.CurrentUser);
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// The performance values for this pbkdf2 function
        /// </summary>
        public override dynamic PerformanceValues { get; private protected set; }

        /// <inheritdoc />
        [SuppressMessage("Microsoft.Usage", "CA2213:DisposableFieldsShouldBeDisposed", MessageId = nameof(_baseObject), Justification = "Glitched - should not warn")]
        public void Dispose()
        {
            this._baseObject?.Dispose();
        }

        /// <inheritdoc />
        /// <summary>
        /// Fills an array with hashed bytes
        /// </summary>
        public override byte[] GetBytes(int size)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException(nameof(size));

            return this._baseObject.GetBytes(size);
        }

        /// <inheritdoc />
        public override void Reset()
        {
            this._baseObject.Reset();
        }

        /// <summary>
        /// </summary>
        /// <param name="performanceDerivative"></param>
        /// <param name="milliseconds">The desired number of milliseconds</param>
        public static int TransformPerformance(PerformanceDerivative performanceDerivative, ulong milliseconds)
        {
            return checked((int)performanceDerivative.TransformToRfc2898(milliseconds));
        }
    }
}