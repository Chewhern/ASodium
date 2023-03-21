using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumSecureMemoryLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_memzero(IntPtr Destination, long Length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_mlock(IntPtr Destination, long Length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_munlock(IntPtr Destination, long Length);
    }
}
