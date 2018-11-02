using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;

namespace FactaLogicaSoftware.CryptoTools.Events
{
    public class MemoryChunkValueChangedEventArgs : EventArgs
    {
        /// <inheritdoc />
        public MemoryChunkValueChangedEventArgs(int newValue, SymmetricCryptoManager sender)
        {
            NewValue = newValue;
            Sender = sender;
        }

        public int NewValue;
        public SymmetricCryptoManager Sender;
    }
}
