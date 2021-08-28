using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumSecretStreamLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretstream_xchacha20poly1305_statebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretstream_xchacha20poly1305_abytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretstream_xchacha20poly1305_headerbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretstream_xchacha20poly1305_keybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_secretstream_xchacha20poly1305_messagebytes_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_secretstream_xchacha20poly1305_tag_message();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_secretstream_xchacha20poly1305_tag_push();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_secretstream_xchacha20poly1305_tag_rekey();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_secretstream_xchacha20poly1305_tag_final();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_secretstream_xchacha20poly1305_keygen(Byte[] Key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretstream_xchacha20poly1305_init_push(Byte[] StateByte,Byte[] HeaderByte,Byte[] KeyByte);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretstream_xchacha20poly1305_push(Byte[] StateByte, Byte[] CipherText, long CipherTextLength,Byte[] Message,long MessageLength,Byte[] AdditionalData,long AdditionalDataLength,Byte Tag);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretstream_xchacha20poly1305_init_pull (Byte[] StateByte, Byte[] HeaderByte, Byte[] KeyByte);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_secretstream_xchacha20poly1305_pull(Byte[] StateByte, Byte[] MessageByte, long MessageLength, Byte Tag, Byte[] CipherText, long CipherTextLength,Byte[] AdditionalData, long AdditionalDataLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void crypto_secretstream_xchacha20poly1305_rekey(Byte[] StateByte);
    }
}
