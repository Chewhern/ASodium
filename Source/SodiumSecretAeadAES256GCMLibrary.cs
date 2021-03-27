using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumSecretAeadAES256GCMLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_aead_aes256gcm_is_available
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_is_available();

        //crypto_aead_aes256gcm_encrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_encrypt(Byte[] CipherText, long CipherTextLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, Byte[] Key);

        //crypto_aead_aes256gcm_decrypt
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_decrypt(Byte[] Message, long MessageLength, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, Byte[] Key);

        //crypto_aead_aes256gcm_encrypt_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_encrypt_detached(Byte[] CipherText, Byte[] MAC, long MACLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, Byte[] Key);

        //crypto_aead_aes256gcm_decrypt_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_decrypt_detached(Byte[] Message, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength, Byte[] MAC, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, Byte[] Key);

        //crypto_aead_aes256gcm_keygen
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_aead_aes256gcm_keygen(Byte[] Key);

        //crypto_aead_aes256gcm_beforenm
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_beforenm(Byte[] State,Byte[] Key);

        //crypto_aead_aes256gcm_encrypt_afternm
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_encrypt_afternm(Byte[] CipherText, long CipherTextLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, Byte[] State);

        //crypto_aead_aes256gcm_decrypt_afternm
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_decrypt_afternm(Byte[] Message, long MessageLength, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, Byte[] State);

        //crypto_aead_aes256gcm_encrypt_detached_afternm
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_encrypt_detached_afternm(Byte[] CipherText, Byte[] MAC, long MACLength, Byte[] Message, long MessageLength, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NonceSecurity, Byte[] NoncePublic, Byte[] State);

        //crypto_aead_aes256gcm_decrypt_detached_afternm
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_decrypt_detached_afternm(Byte[] Message, Byte[] NonceSecurity, Byte[] CipherText, long CipherTextLength, Byte[] MAC, Byte[] AdditionalData, long AdditionalDataLength, Byte[] NoncePublic, Byte[] State);

        //crypto_aead_aes256gcm_keybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_keybytes();

        //crypto_aead_aes256gcm_nsecbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_nsecbytes();

        //crypto_aead_aes256gcm_npubbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_npubbytes();

        //crypto_aead_aes256gcm_abytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_abytes();

        //crypto_aead_aes256gcm_statebytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_aead_aes256gcm_statebytes();

        //crypto_aead_aes256gcm_messagebytes_max
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_aead_aes256gcm_messagebytes_max();
    }
}
