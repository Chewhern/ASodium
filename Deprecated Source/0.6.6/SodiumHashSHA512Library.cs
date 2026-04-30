using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumHashSHA512Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_bytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_statebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512(Byte[] ComputedHash, Byte[] Message, long MessageLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_init(Byte[] State);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_update(Byte[] State, Byte[] Message, long MessageLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_final(Byte[] State, Byte[] ComputedHash);
    }
}
