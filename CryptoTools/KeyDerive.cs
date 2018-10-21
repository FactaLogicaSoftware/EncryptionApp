using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTools
{
    public abstract class KeyDerive
    {
        private protected byte[] Salt;
        private protected byte[] Key;
        private protected object _baseObject;


        public abstract void GetBytes(byte[] toFill);

        public abstract void Reset();
    }
}
