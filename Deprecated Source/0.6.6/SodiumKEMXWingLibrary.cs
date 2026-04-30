using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public static partial class SodiumKEMXWingLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_publickeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_secretkeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_ciphertextbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_sharedsecretbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_seedbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_seed_keypair(Byte[] PublicKey, Byte[] SecretKey, Byte[] Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_seed_keypair(IntPtr PublicKey, IntPtr SecretKey, IntPtr Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_keypair(Byte[] PublicKey, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_keypair(IntPtr PublicKey, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_enc(Byte[] CipherText, Byte[] SharedSecret, Byte[] PublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_enc(Byte[] CipherText, IntPtr SharedSecret, Byte[] PublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_enc_deterministic(Byte[] CipherText, Byte[] SharedSecret, Byte[] PublicKey, Byte[] Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_enc_deterministic(Byte[] CipherText, IntPtr SharedSecret, Byte[] PublicKey, IntPtr Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_dec(Byte[] SharedSecret, Byte[] CipherText, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_xwing_dec(IntPtr SharedSecret, Byte[] CipherText, IntPtr SecretKey);
    }
}
