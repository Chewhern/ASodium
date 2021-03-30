using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumShortHashLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_shorthash_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_bytes();

        //crypto_shorthash_keybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_keybytes();

        //crypto_shorthash_siphashx24_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_siphashx24_bytes();

        //crypto_shorthash
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash(Byte[] ComputedHash,Byte[] Message,long MessageLength,Byte[] Key);

        //crypto_shorthash_siphashx24
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_shorthash_siphashx24(Byte[] ComputedHash, Byte[] Message, long MessageLength, Byte[] Key);

        //crypto_shorthash_keygen
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_shorthash_keygen(Byte[] Key);
    }
}
