using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumSealedPublicKeyBoxXChaCha20Poly1305Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_seal(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] OtherUserPublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_seal_open(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] CurrentUserPublicKey, Byte[] CurrentUserSecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_seal_open(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] CurrentUserPublicKey, IntPtr CurrentUserSecretKey);

    }
}
