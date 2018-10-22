using System.Runtime.CompilerServices;
using Encryption_App;

namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    public abstract class KeyDerive
    {
        public byte[] Salt { get; private protected set; }
        private protected bool Usable;
        public abstract object PerformanceValues { get; private protected set; }
        public abstract byte[] Password { get; private protected set; }

        public abstract void GetBytes(byte[] toFill);

        public abstract void Reset();

        public abstract void TransformPerformance(PerformanceDerivative performanceDerivative);
    }
}
