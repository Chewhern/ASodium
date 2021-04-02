using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumHMACSHA512256Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_auth_hmacsha512256_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512256_bytes();

        //crypto_auth_hmacsha512256_keybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512256_keybytes();

        //crypto_auth_hmacsha512256
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512256(Byte[] ComputedMAC, Byte[] Message, long MessageLength, Byte[] Key);

        //crypto_auth_hmacsha512256_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512256_verify(Byte[] ComputedMAC, Byte[] Message, long MessageLength, Byte[] Key);

        //crypto_auth_hmacsha512256_keygen
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_auth_hmacsha512256_keygen(Byte[] Key);
    }
}
