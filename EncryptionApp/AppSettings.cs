namespace Encryption_App
{
    internal class AppSettings
    {
        public AppSettings()
        {
            MinPasswordLength = 8;
        }

        public int MinPasswordLength { get; set; }
    }
}