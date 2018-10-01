using System;
using System.Security.Cryptography;

public class Class1
{
	public Class1()
	{
	}

    public static void main()
    {
        var rng = new RNGCryptoServiceProvider();
        byte[] salt = new byte[16];
        salt = rng.GetBytes(salt);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var hasher = new Rfc2898DeriveBytes("HelloWorld12345", salt, 10000);
        watch.Stop();
        var elapsedMs = watch.ElapsedMilliseconds;
        Console.WriteLine(elapsedMs);

    }
}
