using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumHashSHA512Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_hash_sha512_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_bytes();

        //crypto_hash_sha512_statebytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_statebytes();

        //crypto_hash_sha512
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512(Byte[] ComputedHash, Byte[] Message, long MessageLength);

        //crypto_hash_sha512_init
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_init(Byte[] State);

        //crypto_hash_sha512_update
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_update(Byte[] State, Byte[] Message, long MessageLength);

        //crypto_hash_sha512_final
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_hash_sha512_final(Byte[] State, Byte[] ComputedHash);
    }
}
