using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumSecretAeadChaCha20Poly1305Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_aead_chacha20poly1305_keybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_keybytes();

        //crypto_aead_chacha20poly1305_npubbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_npubbytes();

        //crypto_aead_chacha20poly1305_nsecbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_nsecbytes();

        //crypto_aead_chacha20poly1305_abytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_abytes();

        //crypto_aead_chacha20poly1305_messagebytes_max
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_aead_chacha20poly1305_messagebytes_max();

        //crypto_aead_chacha20poly1305_encrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_encrypt(Byte[] CipherText,long CipherTextLength,Byte[] Message,long MessageLength,Byte[] AdditionalData,long AdditionalDataLength,Byte[] NonceSecurity,Byte[] NoncePublic,Byte[] Key);

        //crypto_aead_chacha20poly1305_decrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_decrypt(Byte[] Message,long MessageLength,Byte[] NonceSecurity,Byte[] CipherText,long CipherTextLength,Byte[] AdditionalData,long AdditionalDataLength,Byte[] NoncePublic,Byte[] Key);

        //crypto_aead_chacha20poly1305_encrypt_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_encrypt_detached(Byte[] CipherText, Byte[] MAC, long MACLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, Byte[] Key);

        //crypto_aead_chacha20poly1305_decrypt_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_chacha20poly1305_decrypt_detached(Byte[] Message, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength,Byte[] MAC, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, Byte[] Key);

        //crypto_aead_chacha20poly1305_keygen
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_aead_chacha20poly1305_keygen(Byte[] Key);
    }
}
