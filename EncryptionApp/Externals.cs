using System;
using System.Runtime.InteropServices;

namespace Encryption_App
{
    internal static class Externals
    {
        /// <summary>
        /// A kernel32 function that destroys all values in a block of memory
        /// </summary>
        /// <param name="destination">The pointer to the start of the block to be zeroed</param>
        /// <param name="length">The destination pointer + number of bytes to zero</param>
        /// <returns></returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, EntryPoint = "RtlSecureZeroMemory")]
        public static extern void SecureZeroMemory(IntPtr destination, IntPtr length);

        /// <summary>
        /// A kernel32 function that destroys all values in a block of memory
        /// </summary>
        /// <param name="destination">The pointer to the start of the block to be zeroed</param>
        /// <param name="length">Number of bytes to zero</param>
        /// <returns></returns>
        [DllImport("kernel32.dll", EntryPoint = "RtlZeroMemory")]
        public static extern void ZeroMemory(IntPtr destination, int length);
    }
}