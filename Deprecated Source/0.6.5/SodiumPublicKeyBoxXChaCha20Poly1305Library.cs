using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumPublicKeyBoxXChaCha20Poly1305Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_seedbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_publickeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_secretkeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_beforenmbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_noncebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_macbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_box_curve25519xchacha20poly1305_messagebytes_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_keypair(Byte[] PublicKey, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_keypair(IntPtr PublicKey, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_seed_keypair(Byte[] PublicKey, Byte[] SecretKey, Byte[] Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_seed_keypair(IntPtr PublicKey, IntPtr SecretKey, IntPtr Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_easy(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_easy(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] OtherUserPublicKey, IntPtr CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_open_easy(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_open_easy(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, Byte[] OtherUserPublicKey, IntPtr CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_detached(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_detached(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] OtherUserPublicKey, IntPtr CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_open_detached(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_open_detached(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, Byte[] OtherUserPublicKey, IntPtr CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_beforenm(Byte[] SharedSecret, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_beforenm(IntPtr SharedSecret, Byte[] OtherUserPublicKey, IntPtr CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_easy_afternm(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_easy_afternm(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_open_easy_afternm(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, Byte[] SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_open_easy_afternm(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, IntPtr SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_detached_afternm(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_detached_afternm(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_open_detached_afternm(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, Byte[] SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_curve25519xchacha20poly1305_open_detached_afternm(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, IntPtr SharedSecret);
    }
}
