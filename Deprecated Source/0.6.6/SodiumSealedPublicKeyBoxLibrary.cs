using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumSealedPublicKeyBoxLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seal(Byte[] CipherText,Byte[] Message,long MessageLength,Byte[] OtherUserPublicKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seal_open(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] CurrentUserPublicKey,Byte[] CurrentUserSecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seal_open(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] CurrentUserPublicKey, IntPtr CurrentUserSecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_sealbytes();
    }
}
