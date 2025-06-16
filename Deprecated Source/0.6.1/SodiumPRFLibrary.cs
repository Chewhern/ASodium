using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumPRFLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_core_hchacha20(Byte[] ExtendedNonce, Byte[] Nonce, Byte[] Key, Byte[] Constant);
        //Constant = null or 16 bytes

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa20(Byte[] Out, long OutLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa2012(Byte[] Out, long OutLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_salsa208(Byte[] Out, long OutLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_chacha20(Byte[] Out, long OutLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_xchacha20(Byte[] Out, long OutLength, Byte[] Nonce, Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_stream_xsalsa20(Byte[] Out, long OutLength, Byte[] Nonce, Byte[] Key);

    }
}
