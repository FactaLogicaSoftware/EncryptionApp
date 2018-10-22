using System.Security.Cryptography;
using System.Text;
using Encryption_App;

namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    public sealed class Pbkdf2KeyDerive : KeyDerive
    {
        private readonly Rfc2898DeriveBytes _baseObject;

        private int iterations;
        public override object PerformanceValues
        {
            get => iterations;
            private protected set => iterations = (int)value;
        }

        private byte[] backPassword;
        public override byte[] Password
        {
            get => backPassword;

            private protected set
            {
                backPassword = value;
                if ((int)PerformanceValues > 0)
                {
                    Usable = true;
                }
            }
        }

        public Pbkdf2KeyDerive()
        {
            Usable = false;
        }

        public Pbkdf2KeyDerive(byte[] key, byte[] salt, int iterations)
        {
            PerformanceValues = iterations;
            Salt = salt;
            Password = key;
            _baseObject = new Rfc2898DeriveBytes(Password, Salt, (int)PerformanceValues);
            Usable = true;
        }

        public Pbkdf2KeyDerive(string password, byte[] salt, int iterations)
        {
            PerformanceValues = iterations;
            Salt = salt;
            Password = Encoding.UTF8.GetBytes(password);
            _baseObject = new Rfc2898DeriveBytes(Password, Salt, (int)PerformanceValues);
            Usable = true;
        }

        public override void GetBytes(byte[] toFill)
        {
            toFill = _baseObject.GetBytes(toFill.Length);
        }

        public override void Reset()
        {
            _baseObject.Reset();
        }

        public override void TransformPerformance(PerformanceDerivative performanceDerivative)
        {
            PerformanceValues = checked((int)performanceDerivative.TransformToRfc2898(performanceDerivative.Milliseconds));
        }
    }
}
