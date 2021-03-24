using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumSecretKeyAuthLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_auth
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth(Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Key);

        //crypto_auth_keybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_keybytes();

        //crypto_auth_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_bytes();

        //crypto_auth_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_auth_verify(Byte[] Signature, Byte[] Message, long MessageLength, Byte[] Key);

        //crypto_auth_keygen
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_auth_keygen(Byte[] Key);
    }
}
