using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumSecretAeadXChaCha20Poly1305IETFLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_npubbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_nsecbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_abytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_aead_xchacha20poly1305_ietf_messagebytes_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_encrypt(Byte[] CipherText, long CipherTextLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_encrypt(Byte[] CipherText, long CipherTextLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_decrypt(Byte[] Message, long MessageLength, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_decrypt(Byte[] Message, long MessageLength, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(Byte[] CipherText, Byte[] MAC, long MACLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(Byte[] CipherText, Byte[] MAC, long MACLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_decrypt_detached(Byte[] Message, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength, Byte[] MAC, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_xchacha20poly1305_ietf_decrypt_detached(Byte[] Message, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength, Byte[] MAC, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_aead_xchacha20poly1305_ietf_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_aead_xchacha20poly1305_ietf_keygen(IntPtr Key);
    }
}
