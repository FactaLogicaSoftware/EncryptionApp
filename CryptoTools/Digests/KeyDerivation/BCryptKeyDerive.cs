using FactaLogicaSoftware.CryptoTools.PerformanceInterop;
using System;

#pragma warning disable 0414
#pragma warning disable 1591

namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    // TODO implement this, the BCrypt library i found doesn't have wide enough methods for this wrapper
    [Obsolete("Not implemented yet")]
    public sealed class BCryptKeyDerive : KeyDerive
    {
        private uint _cost;
        private uint _read;

        public BCryptKeyDerive(byte[] key, byte[] salt, uint cost)
        {
            Password = key;
            Salt = salt;
            _cost = cost;
            _read = 0;
        }

        public override object PerformanceValues { get; private protected set; }
        public override byte[] Password { get; private protected set; }

        public override byte[] GetBytes(int size)
        {
            throw new NotImplementedException();
        }

        public override void Reset()
        {
            throw new NotImplementedException();
        }

        public static dynamic TransformPerformance(PerformanceDerivative performanceDerivative, ulong milliseconds)
        {
            throw new NotImplementedException();
        }
    }
}