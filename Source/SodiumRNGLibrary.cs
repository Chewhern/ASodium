using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumRNGLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //randombytes_seedbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int randombytes_seedbytes();

        //randombytes_random
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint randombytes_random();

        //randombytes_buf
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void randombytes_buf(Byte[] buffer, int size);

        //randombytes_buf_deterministic
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void randombytes_buf_deterministic(Byte[] buffer, ulong size, Byte[] Seeds);

        //randombytes_uniform
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint randombytes_uniform(uint upperBound);

        //sodium_increment
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_increment(Byte[] buffer, long length);
    }
}
