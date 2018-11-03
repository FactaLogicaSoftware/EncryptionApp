namespace Encryption_App.ManagedSlaves
{
    internal abstract class ManagedSlave
    {
        protected dynamic Owner;

        protected ManagedSlave(dynamic owner)
        {
            this.Owner = owner;
        }
    }
}
