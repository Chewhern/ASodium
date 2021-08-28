using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumSecretKeyAuth
    {

        public static int GetMACLength()
        {
            return SodiumSecretKeyAuthLibrary.crypto_auth_bytes();
        }

        public static int GetKeyLength() 
        {
            return SodiumSecretKeyAuthLibrary.crypto_auth_keybytes();
        }

        public static Byte[] GenKey() 
        {
            Byte[] Key = new Byte[GetKeyLength()];
            
            SodiumSecretKeyAuthLibrary.crypto_auth_keygen(Key);

            return Key;
        }

        public static Byte[] Sign(Byte[] message, Byte[] Key,Boolean ClearKey=false)
        {
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be "+Key.Length+" in length");

            Byte[] MAC = new Byte[GetMACLength()];
            SodiumSecretKeyAuthLibrary.crypto_auth(MAC, message, message.Length, Key);

            if (ClearKey == true)
            {
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
            }

            return MAC;
        }

        public static void Verify(Byte[] Message, Byte[] MAC, Byte[] Key, Boolean ClearKey = false)
        {
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + Key.Length + " in length");

            if (MAC == null || MAC.Length != GetMACLength())
                throw new ArgumentException("Error: MAC must be " + MAC.Length + " in length");

            var ret = SodiumSecretKeyAuthLibrary.crypto_auth_verify(MAC, Message, Message.Length, Key);

            if (ret == -1)
            {
                throw new CryptographicException("Error: MAC does not match with Message...");
            }

            if (ClearKey == true)
            {
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
            }
        }

        public static Boolean VerifyMAC(Byte[] Message, Byte[] MAC, Byte[] Key, Boolean ClearKey = false)
        {
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + Key.Length + " in length");

            if (MAC == null || MAC.Length != GetMACLength())
                throw new ArgumentException("Error: MAC must be " + MAC.Length + " in length");

            var ret = SodiumSecretKeyAuthLibrary.crypto_auth_verify(MAC, Message, Message.Length, Key);

            if (ClearKey == true)
            {
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
            }

            return ret == -1;
        }
    }
}
