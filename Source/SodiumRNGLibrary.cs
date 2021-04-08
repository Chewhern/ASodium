using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumRNGLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int randombytes_seedbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint randombytes_random();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void randombytes_buf(Byte[] buffer, int size);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void randombytes_buf_deterministic(Byte[] buffer, ulong size, Byte[] Seeds);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint randombytes_uniform(uint upperBound);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_increment(Byte[] buffer, long length);
    }
}
