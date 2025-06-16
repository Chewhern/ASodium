using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumHMACSHA512Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512(Byte[] ComputedMAC, Byte[] Message, long MessageLength, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_verify(Byte[] ComputedMAC, Byte[] Message, long MessageLength, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_auth_hmacsha512_keygen(Byte[] Key);
    }
}
