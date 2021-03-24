using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Sodium
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

        public static Byte[] Sign(Byte[] message, Byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be "+key.Length+" in length");

            Byte[] MAC = new Byte[GetMACLength()];
            SodiumSecretKeyAuthLibrary.crypto_auth(MAC, message, message.Length, key);

            return MAC;
        }

        public static void Verify(Byte[] Message, Byte[] MAC, Byte[] Key)
        {
            //validate the length of the key
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + Key.Length + " in length");

            //validate the length of the MAC
            if (MAC == null || MAC.Length != GetMACLength())
                throw new ArgumentException("Error: MAC must be " + MAC.Length + " in length");

            var ret = SodiumSecretKeyAuthLibrary.crypto_auth_verify(MAC, Message, Message.Length, Key);

            if (ret == -1) 
            {
                throw new CryptographicException("Error: MAC does not match with Message...");
            }
        }

        public static Boolean VerifyMAC(Byte[] Message, Byte[] MAC, Byte[] Key)
        {
            //validate the length of the key
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + Key.Length + " in length");

            //validate the length of the MAC
            if (MAC == null || MAC.Length != GetMACLength())
                throw new ArgumentException("Error: MAC must be " + MAC.Length + " in length");

            var ret = SodiumSecretKeyAuthLibrary.crypto_auth_verify(MAC, Message, Message.Length, Key);

            return ret == -1;
        }
    }
}
