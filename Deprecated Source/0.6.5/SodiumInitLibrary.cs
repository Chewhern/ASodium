using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumInitLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_init();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_version_string();


    }
}
