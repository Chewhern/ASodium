using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumHMACSHA256Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_auth_hmacsha256_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_bytes();

        //crypto_auth_hmacsha256_keybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_keybytes();

        //crypto_auth_hmacsha256
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256(Byte[] ComputedMAC,Byte[] Message,long MessageLength,Byte[] Key);

        //crypto_auth_hmacsha256_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha256_verify(Byte[] ComputedMAC, Byte[] Message, long MessageLength, Byte[] Key);

        //crypto_auth_hmacsha256_keygen
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_auth_hmacsha256_keygen(Byte[] Key);
    }
}
