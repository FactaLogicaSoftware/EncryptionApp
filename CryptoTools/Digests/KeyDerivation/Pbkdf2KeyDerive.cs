using System.Security.Cryptography;
using System.Text;
using Encryption_App;
using FactaLogicaSoftware.CryptoTools.Exceptions;

namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class Pbkdf2KeyDerive : KeyDerive
    {
        private readonly Rfc2898DeriveBytes _baseObject;

        private int iterations;

        /// <inheritdoc />
        /// <summary>
        /// The performance values for this pbkdf2 function
        /// </summary>
        public override object PerformanceValues
        {
            get => iterations;
            private protected set => iterations = (int)value;
        }

        private byte[] backPassword;

        /// <inheritdoc />
        /// <summary>
        /// The password, stored encrypted
        /// </summary>
        public override byte[] Password
        {
            get => ProtectedData.Unprotect(BackEncryptedArray, null, DataProtectionScope.CurrentUser);
            private protected set
            {
                BackEncryptedArray = ProtectedData.Protect(value, null, DataProtectionScope.CurrentUser);
                Usable = PerformanceValues != null;
            }
        }

        /// <summary>
        /// Default constructor that isn't valid for derivation
        /// </summary>
        public Pbkdf2KeyDerive()
        {
            Usable = false;
        }

        /// <summary>
        /// Creates an instance of an object used to hash
        /// </summary>
        /// <param name="password">The bytes of the password to hash</param>
        /// <param name="salt">The salt used to hash</param>
        /// <param name="iterations">The number of iterations to use on the
        /// underlying Rfc2898DeriveBytes objects</param>
        public Pbkdf2KeyDerive(byte[] password, byte[] salt, int iterations)
        {
            PerformanceValues = iterations;
            Salt = salt;
            Password = password;
            _baseObject = new Rfc2898DeriveBytes(Password, Salt, (int)PerformanceValues);
            Usable = true;
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
            PerformanceValues = iterations;
            Salt = salt;
            Password = Encoding.UTF8.GetBytes(password);
            _baseObject = new Rfc2898DeriveBytes(Password, Salt, (int)PerformanceValues);
            Usable = true;
        }

        /// <inheritdoc />
        /// <summary>
        /// </summary>
        /// <param name="toFill"></param>
        public override void GetBytes(byte[] toFill)
        {
            if (!Usable)
            {
                throw new InvalidCryptographicOperationException("Password not set");
            }

            toFill = _baseObject.GetBytes(toFill.Length);
        }

        /// <inheritdoc />
        /// <summary>
        /// </summary>
        public override void Reset()
        {
            _baseObject.Reset();
        }

        /// <inheritdoc />
        /// <summary>
        /// </summary>
        /// <param name="performanceDerivative"></param>
        public override void TransformPerformance(PerformanceDerivative performanceDerivative)
        {
            PerformanceValues = checked((int)performanceDerivative.TransformToRfc2898(performanceDerivative.Milliseconds));
        }
    }
}
