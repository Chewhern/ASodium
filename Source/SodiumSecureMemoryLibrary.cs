using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumSecureMemoryLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_memzero(IntPtr Destination, int Length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_mlock(IntPtr Destination, int Length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_munlock(IntPtr Destination, int Length);
    }
}
