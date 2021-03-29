using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumPublicKeyAuthLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_sign_keypair
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_keypair(Byte[] PublicKey,Byte[] SecretKey);

        //crypto_sign_seed_keypair
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_seed_keypair(Byte[] PublicKey, Byte[] SecretKey,Byte[] Seed);

        //crypto_sign
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign(Byte[] SignatureMessage, long SignatureMessageLength, Byte[] Message,long MessageLength,Byte[] SecretKey);

        //crypto_sign_open
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_open(Byte[] Message, long MessageLength, Byte[] SignatureMessage, long SignatureMessageLength, Byte[] PublicKey);

        //crypto_sign_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_detached(Byte[] Signature, long SignatureLength, Byte[] Message, long MessageLength, Byte[] SecretKey);

        //crypto_sign_verify_detached
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_verify_detached(Byte[] Signature, Byte[] Message, long MessageLength, Byte[] PublicKey);

        //crypto_sign_init
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_init(Byte[] State);

        //crypto_sign_update
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_update(Byte[] State,Byte[] Message,long MessageLength);

        //crypto_sign_final_create
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_final_create(Byte[] State,Byte[] Signature,long SignatureLength,Byte[] SecretKey);

        //crypto_sign_final_verify
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_final_verify(Byte[] State, Byte[] Signature, Byte[] PublicKey);

        //crypto_sign_ed25519_sk_to_seed
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_seed(Byte[] Seed,Byte[] SecretKey);

        //crypto_sign_ed25519_sk_to_pk
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_ed25519_sk_to_pk(Byte[] PublicKey, Byte[] SecretKey);

        //crypto_sign_statebytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_statebytes();

        //crypto_sign_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_bytes();

        //crypto_sign_seedbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_seedbytes();

        //crypto_sign_publickeybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_publickeybytes();

        //crypto_sign_secretkeybytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_sign_secretkeybytes();

        //crypto_sign_primitive
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_sign_primitive();
    }
}
