using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Encryption_App;

namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    /// <inheritdoc />
    /// <summary>
    /// </summary>
    public sealed class SCryptKeyDerive : KeyDerive
    {
        private uint _read;
        private (ulong N, uint r, uint p) _tuneFlags;

        public override object PerformanceValues
        {
            get => _tuneFlags;
            private protected set
            {
                var newCastTuple = (ValueTuple<int, int, int>) value;
                _tuneFlags = ((ulong)newCastTuple.Item1, (uint)newCastTuple.Item2, (uint)newCastTuple.Item3);
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// </summary>
        public override byte[] Password
        {
            get => ProtectedData.Unprotect(BackEncryptedArray, null, DataProtectionScope.CurrentUser);

            private protected set
            {
                BackEncryptedArray = ProtectedData.Protect(value, null, DataProtectionScope.CurrentUser);

                if ((_tuneFlags.N & (_tuneFlags.N - 1)) == 0 && _tuneFlags.r > 0 && _tuneFlags.p > 0)
                {
                    Usable = true;
                }
            }
        }

        /// <summary>
        /// Default constructor that isn't valid for derivation
        /// </summary>
        public SCryptKeyDerive()
        {
            Usable = false;
        }

        /// <summary>
        /// Creates an instance of an object used to hash
        /// </summary>
        /// <param name="password">The bytes of the password to hash</param>
        /// <param name="salt">The salt used to hash
        /// underlying Rfc2898DeriveBytes objects</param>
        /// <param name="tuneFlags">The tuple containing the SCrypt tuning
        /// parameters (N, r, and p)</param>
        public SCryptKeyDerive(byte[] password, byte[] salt, (ulong N, uint r, uint p) tuneFlags)
        {
            _tuneFlags = tuneFlags;
            Salt = salt;
            Password = password;
            _read = 0;
            Usable = true;
        }

        /// <summary>
        /// Creates an instance of an object used to hash
        /// </summary>
        /// <param name="password">The string of the password to hash</param>
        /// <param name="salt">The salt used to hash
        /// underlying Rfc2898DeriveBytes objects</param>
        /// <param name="tuneFlags">The tuple containing the SCrypt tuning
        /// parameters (N, r, and p)</param>
        public SCryptKeyDerive(string password, byte[] salt, (ulong N, uint r, uint p) tuneFlags)
        {
            _tuneFlags = tuneFlags;
            Salt = salt;
            Password = Encoding.UTF8.GetBytes(password);
            _read = 0;
            Usable = true;
        }

        /// <inheritdoc />
        /// <summary>
        /// </summary>
        /// <param name="toFill"></param>
        public override void GetBytes(byte[] toFill)
        {
            // TODO manage checked overflows
            toFill = Replicon.Cryptography.SCrypt.SCrypt.DeriveKey(Password, Salt, _tuneFlags.N, _tuneFlags.r, _tuneFlags.p, (uint)toFill.Length + _read).Skip(checked((int)_read)).ToArray();
        }

        /// <inheritdoc />
        /// <summary>
        /// </summary>
        public override void Reset()
        {
            _read = 0;
        }

        /// <inheritdoc />
        /// <summary>
        /// </summary>
        /// <param name="performanceDerivative"></param>
        public override void TransformPerformance(PerformanceDerivative performanceDerivative)
        {
            PerformanceValues = performanceDerivative.TransformToScryptTuning(performanceDerivative.Milliseconds);
        }
    }
}