using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public static partial class SodiumKEMLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_publickeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_secretkeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_ciphertextbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_sharedsecretbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_seedbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte[] crypto_kem_primitive();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_seed_keypair(Byte[] PublicKey, Byte[] SecretKey, Byte[] Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_seed_keypair(IntPtr PublicKey, IntPtr SecretKey, IntPtr Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_keypair(Byte[] PublicKey, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_keypair(IntPtr PublicKey, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_enc(Byte[] CipherText, Byte[] SharedSecret, Byte[] PublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_enc(Byte[] CipherText, IntPtr SharedSecret, Byte[] PublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_dec(Byte[] SharedSecret, Byte[] CipherText, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kem_dec(IntPtr SharedSecret, Byte[] CipherText, IntPtr SecretKey);
    }
}
