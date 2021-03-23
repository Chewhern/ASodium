using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumSecretBoxLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_secretbox_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_easy(Byte[] buffer, Byte[] message, long messageLength, Byte[] nonce, Byte[] key);

        //crypto_secretbox_open_easy
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_easy(Byte[] buffer, Byte[] cipherText, long cipherTextLength, Byte[] nonce, Byte[] key);

        //crypto_secretbox_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_detached(Byte[] cipher, Byte[] mac, Byte[] message, long messageLength, Byte[] nonce, Byte[] key);

        //crypto_secretbox_open_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_detached(Byte[] buffer, Byte[] cipherText, Byte[] mac, long cipherTextLength, Byte[] nonce, Byte[] key);

        //crypto_secretbox_open_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_secretbox_keygen(Byte[] KeyByte);
    }
}
