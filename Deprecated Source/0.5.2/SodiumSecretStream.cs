﻿using System;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretStream
    {
        public static int GetABytesLength() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_abytes();
        }

        public static int GetKeyLength() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_keybytes();
        }

        public static Byte GetTagMessageByte() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_tag_message();
        }

        public static Byte GetTagPushByte() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_tag_push();
        }

        public static Byte GetTagRekeyByte() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_tag_rekey();
        }

        public static Byte GetTagFinalByte() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_tag_final();
        }

        public static Byte[] KeyGen() 
        {
            Byte[] Key = new Byte[GetKeyLength()];

            SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_keygen(Key);

            return Key;
        }

        public static long GetMessageBytesMaxLength() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_messagebytes_max();
        }

        public static int GetStateBytesLength() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_statebytes();
        }

        public static int GetHeaderBytesLength() 
        {
            return SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_headerbytes();
        }

        public static SecretStreamInitPushBox SecretStreamInitPush(Byte[] KeyByte) 
        {
            SecretStreamInitPushBox MySecretStreamInitPushBox = new SecretStreamInitPushBox();
            Byte[] StateByte = new Byte[GetStateBytesLength()];
            Byte[] HeaderByte = new Byte[GetHeaderBytesLength()];
            int result = SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_init_push(StateByte, HeaderByte, KeyByte);
            MySecretStreamInitPushBox.HeaderByte = HeaderByte;
            MySecretStreamInitPushBox.StateByte = StateByte;
            if (result != 0) 
            {
                throw new Exception("Error: Failed to create SecretStreamInitPushBox");
            }
            return MySecretStreamInitPushBox;
        }

        public static SecretStreamPushBox SecretStreamPush(Byte[] StateByte, Byte[] Message,Byte[] AdditionalData, long AdditionalDataLength, Byte Tag) 
        {
            SecretStreamPushBox MySecretStreamPushBox = new SecretStreamPushBox();
            Byte[] NewStateByte = StateByte;
            Byte[] NewMessageByte = Message;
            Byte[] NewAdditionalData = AdditionalData;
            long MessageLength = NewMessageByte.LongLength;
            long CipheredTextLength=0;
            Byte[] CipheredText = new Byte[MessageLength+GetABytesLength()];

            long MaxMessageLength = GetMessageBytesMaxLength();


            if (MessageLength > MaxMessageLength) 
            {
                throw new ArgumentException("Error: Message length should not be more than " + MaxMessageLength.ToString() + " Bytes");
            }

            int result = SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_push(NewStateByte,CipheredText,CipheredTextLength,NewMessageByte,MessageLength,NewAdditionalData,AdditionalDataLength,Tag);

            if (result != 0) 
            {
                throw new Exception("Error: Failed to create SecretStreamPushBox");
            }

            CipheredTextLength = CipheredText.LongLength;

            MySecretStreamPushBox.AdditionalData = NewAdditionalData;
            MySecretStreamPushBox.CipherText = CipheredText;
            MySecretStreamPushBox.CipherTextLength = CipheredTextLength;
            MySecretStreamPushBox.MessageByte = NewMessageByte;
            MySecretStreamPushBox.StateByte = NewStateByte;

            return MySecretStreamPushBox;
        }

        public static Byte[] SecretStreamInitPull(Byte[] HeaderByte,Byte[] KeyByte)
        {
            Byte[] StateByte = new Byte[GetStateBytesLength()];
            int result = SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_init_pull(StateByte, HeaderByte, KeyByte);
            if (result == -1) 
            {
                throw new ArgumentException("Error: HeaderByte is invalid...");
            }

            return StateByte;
        }

        public static SecretStreamPullBox SecretStreamPull(Byte[] StateByte, Byte TagByte, Byte[] CipheredText, Byte[] AdditionalData,long AdditionalDataLength)
        {
            SecretStreamPullBox MySecretStreamPullBox = new SecretStreamPullBox();
            Byte[] NewStateByte = StateByte;
            Byte[] NewMessageByte = new Byte[CipheredText.LongLength-GetABytesLength()];
            long MessageLength = 0;
            Byte NewTagByte = TagByte;
            Byte[] NewCipheredText = CipheredText;
            long CipherTextLength = NewCipheredText.LongLength;
            Byte[] NewAdditionalData = AdditionalData;
            int result = SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_pull(NewStateByte,NewMessageByte,MessageLength,NewTagByte,NewCipheredText,CipherTextLength,NewAdditionalData,AdditionalDataLength);
            if (result == -1) 
            {
                throw new CryptographicException("Error: Cipher text is invalid...");
            }
            MessageLength = NewMessageByte.LongLength;
            MySecretStreamPullBox.AdditionalData = NewAdditionalData;
            MySecretStreamPullBox.CipherText = NewCipheredText;
            MySecretStreamPullBox.MessageByte = NewMessageByte;
            MySecretStreamPullBox.MessageLength = MessageLength;
            MySecretStreamPullBox.StateByte = NewStateByte;
            MySecretStreamPullBox.TagByte = NewTagByte;
            return MySecretStreamPullBox;
        }

        public static Byte[] SecretStreamReKey(Byte[] StateByte) 
        {
            Byte[] NewStateByte = StateByte;
            SodiumSecretStreamLibrary.crypto_secretstream_xchacha20poly1305_rekey(NewStateByte);
            return NewStateByte;
        }
    }
}
