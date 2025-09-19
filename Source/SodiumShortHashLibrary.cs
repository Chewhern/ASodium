using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumShortHashLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_siphashx24_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash(Byte[] ComputedHash,Byte[] Message,long MessageLength,Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash(Byte[] ComputedHash, Byte[] Message, long MessageLength, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_siphashx24(Byte[] ComputedHash, Byte[] Message, long MessageLength, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_siphashx24(Byte[] ComputedHash, Byte[] Message, long MessageLength, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_shorthash_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_shorthash_keygen(IntPtr Key);
    }
}
