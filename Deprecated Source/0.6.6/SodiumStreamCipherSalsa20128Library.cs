using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumStreamCipherSalsa20128Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_stream_salsa2012_xor(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_stream_salsa2012_xor(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa208_xor(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa208_xor(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr Key);
    }
}
