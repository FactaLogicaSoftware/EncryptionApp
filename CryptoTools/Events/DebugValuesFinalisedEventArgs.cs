namespace FactaLogicaSoftware.CryptoTools.Events
{
    using System;

    public class DebugValuesFinalisedEventArgs : EventArgs
    {
        public readonly string[] FinalisedStrings;

        public DebugValuesFinalisedEventArgs(string[] values)
        {
            this.FinalisedStrings = values;
        }
    }
}