using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumHMACSHA512Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_auth_hmacsha512_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_bytes();

        //crypto_auth_hmacsha512_keybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_keybytes();

        //crypto_auth_hmacsha512
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512(Byte[] ComputedMAC, Byte[] Message, long MessageLength, Byte[] Key);

        //crypto_auth_hmacsha512_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_hmacsha512_verify(Byte[] ComputedMAC, Byte[] Message, long MessageLength, Byte[] Key);

        //crypto_auth_hmacsha512_keygen
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_auth_hmacsha512_keygen(Byte[] Key);
    }
}
