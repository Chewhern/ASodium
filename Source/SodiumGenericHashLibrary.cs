using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumGenericHashLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_generichash_bytes_min
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_bytes_min();

        //crypto_generichash_bytes_max
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_bytes_max();

        //crypto_generichash_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_bytes();

        //crypto_generichash_keybytes_min
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_keybytes_min();

        //crypto_generichash_keybytes_max
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_keybytes_max();

        //crypto_generichash_keybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_keybytes();

        //crypto_generichash_statebytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_statebytes();

        //crypto_generichash
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash(Byte[] ComputedHash,int ComputedHashLength,Byte[] Message,long MessageLength,Byte[] Key,int KeyLength);

        //crypto_generichash_init
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_init(Byte[] State,Byte[] Key,int KeyLength,Byte OutLength);

        //crypto_generichash_update
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_update(Byte[] State, Byte[] Message, long MessageLength);

        //crypto_generichash_final
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_generichash_final(Byte[] State, Byte[] ComputedHash, int ComputedHashLength);

        //crypto_generichash_keygen
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_generichash_keygen(Byte[] Key);
    }
}
