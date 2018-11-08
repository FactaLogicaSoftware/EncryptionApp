using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_App
{
    internal static class Externals
    {
        #region EXTERNAL_DECLERATIONS


        /// <summary>
        /// A kernel32 function that destroys all values in a block of memory
        /// </summary>
        /// <param name="destination">The pointer to the start of the block to be zeroed</param>
        /// <param name="length">The number of bytes to zero</param>
        /// <returns></returns>
        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        // ReSharper disable once UnusedMember.Local
        public static extern bool ZeroMemory(IntPtr destination, int length); // Function is called at runtime through a dynamic type; ignore warning

        #endregion
    }
}
