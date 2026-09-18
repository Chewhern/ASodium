using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumStreamCipherSalsa20Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa20_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa20_noncebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa20_xor(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa20_xor(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa20_xor_ic(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, ulong IC, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa20_xor_ic(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, ulong IC, IntPtr Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_stream_salsa20_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_stream_salsa20_keygen(IntPtr Key);
    }
}
