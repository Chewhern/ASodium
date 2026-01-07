using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumSecretBoxLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_easy(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_easy(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_easy(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_easy(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_detached(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_detached(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_detached(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_open_detached(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_secretbox_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_secretbox_keygen(IntPtr Key);
    }
}
