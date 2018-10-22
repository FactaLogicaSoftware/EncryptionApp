using System;
using System.Linq;
using Encryption_App;

namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    public sealed class SCryptKeyDerive : KeyDerive
    {
        private readonly (ulong N, uint r, uint p) _tuneFlags;
        private uint _read;
        private (int N, int r, int p) backTuple;
        public override object PerformanceValues
        {
            get => backTuple;
            private protected set => backTuple = (ValueTuple<int, int, int>)value;
        }

        private byte[] backPassword;
        public override byte[] Password
        {
            get => backPassword;

            private protected set
            {
                backPassword = value;
                if ((backTuple.N & (backTuple.N - 1)) == 0 && backTuple.r > 0 && backTuple.p > 0)
                {
                    Usable = true;
                }
            }
        }

        public SCryptKeyDerive()
        {
            Usable = false;
        }

        public SCryptKeyDerive(byte[] password, byte[] salt, (ulong N, uint r, uint p) tuneFlags)
        {
            _tuneFlags = tuneFlags;
            Salt = salt;
            Password = password;
            _read = 0;
            Usable = true;
        }

        public override void GetBytes(byte[] toFill)
        {
            // TODO manage checked overflows
            toFill = Replicon.Cryptography.SCrypt.SCrypt.DeriveKey(Password, Salt, _tuneFlags.N, _tuneFlags.r, _tuneFlags.p, (uint)toFill.Length + _read).Skip(checked((int)_read)).ToArray();
        }

        public override void Reset()
        {
            _read = 0;
        }

        public override void TransformPerformance(PerformanceDerivative performanceDerivative)
        {
            PerformanceValues = performanceDerivative.TransformToScryptTuning(performanceDerivative.Milliseconds);
        }
    }
}