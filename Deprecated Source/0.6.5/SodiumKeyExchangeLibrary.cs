using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumKeyExchangeLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_publickeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_secretkeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_seedbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_sessionkeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_keypair(Byte[] PublicKey, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_keypair(IntPtr PublicKey, IntPtr SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_seed_keypair(Byte[] PublicKey, Byte[] SecretKey, Byte[] Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_seed_keypair(IntPtr PublicKey, IntPtr SecretKey, IntPtr Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_client_session_keys(Byte[] ReadSharedSecret, Byte[] TransferSharedSecret, Byte[] ClientPK, Byte[] ClientSK, Byte[] ServerPK);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_client_session_keys(IntPtr ReadSharedSecret, IntPtr TransferSharedSecret, Byte[] ClientPK, IntPtr ClientSK, Byte[] ServerPK);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_server_session_keys(Byte[] ReadSharedSecret, Byte[] TransferSharedSecret, Byte[] ServerPK, Byte[] ServerSK, Byte[] ClientPK);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_kx_server_session_keys(IntPtr ReadSharedSecret, IntPtr TransferSharedSecret, Byte[] ServerPK, IntPtr ServerSK, Byte[] ClientPK);
    }
}
