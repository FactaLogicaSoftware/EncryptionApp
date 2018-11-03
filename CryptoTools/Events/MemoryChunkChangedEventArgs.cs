namespace FactaLogicaSoftware.CryptoTools.Events
{
    using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
    using System;

    public class MemoryChunkValueChangedEventArgs : EventArgs
    {
        public int NewValue;

        public SymmetricCryptoManager Sender;

        /// <inheritdoc />
        public MemoryChunkValueChangedEventArgs(int newValue, SymmetricCryptoManager sender)
        {
            this.NewValue = newValue;
            this.Sender = sender;
        }
    }
}