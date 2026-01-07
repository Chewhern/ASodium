using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumHMACSHA256Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256(Byte[] ComputedMAC,Byte[] Message,long MessageLength,Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256(Byte[] ComputedMAC, Byte[] Message, long MessageLength, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_verify(Byte[] ComputedMAC, Byte[] Message, long MessageLength, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_verify(Byte[] ComputedMAC, Byte[] Message, long MessageLength, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_auth_hmacsha256_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_auth_hmacsha256_keygen(IntPtr Key);
    }
}
