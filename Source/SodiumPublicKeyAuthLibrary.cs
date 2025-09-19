using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumPublicKeyAuthLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_keypair(Byte[] PublicKey,Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_keypair(IntPtr PublicKey, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_seed_keypair(Byte[] PublicKey, Byte[] SecretKey,Byte[] Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_seed_keypair(IntPtr PublicKey, IntPtr SecretKey, IntPtr Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign(Byte[] SignatureMessage, long SignatureMessageLength, Byte[] Message,long MessageLength,Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign(Byte[] SignatureMessage, long SignatureMessageLength, Byte[] Message, long MessageLength, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_open(Byte[] Message, long MessageLength, Byte[] SignatureMessage, long SignatureMessageLength, Byte[] PublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_detached(Byte[] Signature, long SignatureLength, Byte[] Message, long MessageLength, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_detached(Byte[] Signature, long SignatureLength, Byte[] Message, long MessageLength, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_verify_detached(Byte[] Signature, Byte[] Message, long MessageLength, Byte[] PublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_init(Byte[] State);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_update(Byte[] State,Byte[] Message,long MessageLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_final_create(Byte[] State,Byte[] Signature,long SignatureLength,Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_final_create(Byte[] State, Byte[] Signature, long SignatureLength, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_final_verify(Byte[] State, Byte[] Signature, Byte[] PublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_seed(Byte[] Seed,Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_seed(IntPtr Seed, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_pk(Byte[] PublicKey, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_pk(Byte[] PublicKey, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_statebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_seedbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_publickeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_secretkeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_sign_primitive();
    }
}
