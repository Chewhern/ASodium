using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumSecretBoxXChaCha20Poly1305Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_noncebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_macbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_easy(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_easy(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_open_easy(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_open_easy(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_detached(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_detached(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_open_detached(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretbox_xchacha20poly1305_open_detached(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, IntPtr Key);
    }
}
