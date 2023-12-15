using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumPublicKeyBox
    {
        public static int GetSeedBytesLength() 
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_seedbytes();
        }

        public static int GetPublicKeyBytesLength() 
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_publickeybytes();
        }

        public static int GetSecretKeyBytesLength() 
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_secretkeybytes();
        }

        public static int GetBeforeNMBytesLength() 
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_beforenmbytes();
        }

        public static int GetNonceBytesLength() 
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_noncebytes();
        }

        public static int GetBoxZeroBytesLength() 
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_boxzerobytes();
        }

        public static int GetMACBytesLength() 
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_macbytes();
        }

        public static long GetMaxMessageBytesLength() 
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_messagebytes_max();
        }

        public static KeyPair GenerateKeyPair() 
        {
            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            SodiumPublicKeyBoxLibrary.crypto_box_keypair(PublicKey, SecretKey);


            KeyPair MyKeyPair;
            Boolean IsZero1 = true;
            Boolean IsZero2 = true;
            IntPtr PublicKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero1, GetPublicKeyBytesLength());
            IntPtr SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, GetSecretKeyBytesLength());
            if (IsZero1 == false && IsZero2 == false)
            {
                Marshal.Copy(PublicKey, 0, PublicKeyIntPtr, PublicKey.Length);
                Marshal.Copy(SecretKey, 0, SecretKeyIntPtr, SecretKey.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PublicKeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                MyKeyPair = new KeyPair(SecretKeyIntPtr, SecretKey.Length, PublicKeyIntPtr, PublicKey.Length);
            }
            else
            {
                MyKeyPair = new KeyPair(IntPtr.Zero, 0, IntPtr.Zero, 0);
            }

            SodiumSecureMemory.SecureClearBytes(SecretKey);
            SodiumSecureMemory.SecureClearBytes(PublicKey);

            SecretKeyIntPtr = IntPtr.Zero;
            PublicKeyIntPtr = IntPtr.Zero;

            return MyKeyPair;
        }

        public static RevampedKeyPair GenerateRevampedKeyPair() 
        {
            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            SodiumPublicKeyBoxLibrary.crypto_box_keypair(PublicKey, SecretKey);

            RevampedKeyPair MyKeyPair = new RevampedKeyPair(PublicKey, SecretKey);

            return MyKeyPair;
        }

        public static KeyPair GenerateSeededKeyPair(Byte[] Seed)
        {
            if (Seed == null)
            {
                throw new ArgumentException("Error:Seed must not be null");
            }
            if (Seed.Length != GetSeedBytesLength())
            {
                throw new ArgumentException("Error:Seed length must be " + GetSeedBytesLength() + " bytes");
            }

            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            SodiumPublicKeyBoxLibrary.crypto_box_seed_keypair(PublicKey, SecretKey,Seed);

            KeyPair MyKeyPair;
            Boolean IsZero1 = true;
            Boolean IsZero2 = true;
            IntPtr PublicKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero1, GetPublicKeyBytesLength());
            IntPtr SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, GetSecretKeyBytesLength());
            if (IsZero1 == false && IsZero2 == false)
            {
                Marshal.Copy(PublicKey, 0, PublicKeyIntPtr, PublicKey.Length);
                Marshal.Copy(SecretKey, 0, SecretKeyIntPtr, SecretKey.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PublicKeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                MyKeyPair = new KeyPair(SecretKeyIntPtr, SecretKey.Length, PublicKeyIntPtr, PublicKey.Length);
            }
            else
            {
                MyKeyPair = new KeyPair(IntPtr.Zero, 0, IntPtr.Zero, 0);
            }

            SodiumSecureMemory.SecureClearBytes(SecretKey);
            SodiumSecureMemory.SecureClearBytes(PublicKey);

            SecretKeyIntPtr = IntPtr.Zero;
            PublicKeyIntPtr = IntPtr.Zero;

            return MyKeyPair;
        }

        public static RevampedKeyPair GenerateSeededRevampedKeyPair(Byte[] Seed)
        {
            if (Seed == null)
            {
                throw new ArgumentException("Error:Seed must not be null");
            }
            if (Seed.Length != GetSeedBytesLength())
            {
                throw new ArgumentException("Error:Seed length must be " + GetSeedBytesLength() + " bytes");
            }

            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            SodiumPublicKeyBoxLibrary.crypto_box_seed_keypair(PublicKey, SecretKey,Seed);

            RevampedKeyPair MyKeyPair = new RevampedKeyPair(PublicKey, SecretKey);

            return MyKeyPair;
        }

        public static Byte[] GenerateNonce() 
        {
            return SodiumRNG.GetRandomBytes(GetNonceBytesLength());
        }

        public static Byte[] GeneratePublicKey(Byte[] SecretKey,Boolean ClearKey = false) 
        {
            Byte[] PublicKey = SodiumScalarMult.Base(SecretKey, ClearKey);

            return PublicKey;
        }

        public static Byte[] GenerateSharedSecret(Byte[] CurrentUserSecretKey,Byte[] OtherUserPublicKey,Boolean ClearKey = false) 
        {
            Byte[] SharedSecret = SodiumScalarMult.Mult(CurrentUserSecretKey, OtherUserPublicKey, ClearKey);

            return SharedSecret;
        }

        public static IntPtr GenerateSharedSecretIntPtr(Byte[] CurrentUserSecretKey,Byte[] OtherUserPublicKey,Boolean ClearKey = false) 
        {
            IntPtr SharedSecret = SodiumScalarMult.MultIntPtr(CurrentUserSecretKey, OtherUserPublicKey, ClearKey);

            return SharedSecret;
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, Byte[] CurrentUserSecretKey, Byte[] OtherUserPublicKey,Boolean ClearKey=false) 
        {
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != GetSecretKeyBytesLength())
                throw new ArgumentException("Error: Secret key must be "+GetSecretKeyBytesLength()+" bytes in length");

            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != GetPublicKeyBytesLength())
                throw new ArgumentException("Error: Public key must be " + GetPublicKeyBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            Byte[] CipherText = new Byte[Message.Length + GetMACBytesLength()];
            int ret = SodiumPublicKeyBoxLibrary.crypto_box_easy(CipherText, Message, Message.Length, Nonce, OtherUserPublicKey, CurrentUserSecretKey);


            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserSecretKey);
                SodiumSecureMemory.SecureClearBytes(OtherUserPublicKey);
            }

            if (ret != 0)
                throw new CryptographicException("Failed to create PublicKeyBox");

            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, Byte[] CurrentUserSecretKey, Byte[] OtherUserPublicKey,Boolean ClearKey=false)
        {
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != GetSecretKeyBytesLength())
                throw new ArgumentException("Error: Secret key must be " + GetSecretKeyBytesLength() + " bytes in length");

            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != GetPublicKeyBytesLength())
                throw new ArgumentException("Error: Public key must be " + GetPublicKeyBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (CipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < GetMACBytesLength() - 1; i++)
                {
                    if (CipherText[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }

                //if the leading MAC_BYTES are null, trim it off before going on.
                if (trim)
                {
                    var temp = new Byte[CipherText.Length - GetMACBytesLength()];
                    Array.Copy(CipherText, GetMACBytesLength(), temp, 0, CipherText.Length - GetMACBytesLength());

                    CipherText = temp;
                }
            }

            Byte[] Message = new Byte[CipherText.Length - GetMACBytesLength()];
            int ret = SodiumPublicKeyBoxLibrary.crypto_box_open_easy(Message, CipherText, CipherText.Length, Nonce, OtherUserPublicKey, CurrentUserSecretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to open PublicKeyBox");

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserSecretKey);
                SodiumSecureMemory.SecureClearBytes(OtherUserPublicKey);
            }

            return Message;
        }

        public static DetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, Byte[] CurrentUserSecretKey, Byte[] OtherUserPublicKey, Boolean ClearKey = false)
        {
            DetachedBox MyDetachedBox = new DetachedBox();

            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != GetSecretKeyBytesLength())
                throw new ArgumentException("Error: Secret key must be " + GetSecretKeyBytesLength() + " bytes in length");

            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != GetPublicKeyBytesLength())
                throw new ArgumentException("Error: Public key must be " + GetPublicKeyBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new byte[GetMACBytesLength()];

            int ret = SodiumPublicKeyBoxLibrary.crypto_box_detached(CipherText, MAC, Message, Message.Length, Nonce, OtherUserPublicKey,CurrentUserSecretKey);


            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserSecretKey);
                SodiumSecureMemory.SecureClearBytes(OtherUserPublicKey);
            }

            if (ret != 0)
                throw new CryptographicException("Failed to create public detached Box");

            MyDetachedBox = new DetachedBox(CipherText, MAC);

            return MyDetachedBox;
        }

        public static byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, Byte[] CurrentUserSecretKey, Byte[] OtherUserPublicKey,Boolean ClearKey=false)
        {
            if (CurrentUserSecretKey == null || CurrentUserSecretKey.Length != GetSecretKeyBytesLength())
                throw new ArgumentException("Error: Secret key must be " + GetSecretKeyBytesLength() + " bytes in length");

            if (OtherUserPublicKey == null || OtherUserPublicKey.Length != GetPublicKeyBytesLength())
                throw new ArgumentException("Error: Public key must be " + GetPublicKeyBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            if (MAC == null || MAC.Length != GetMACBytesLength())
                throw new ArgumentException("Error: MAC must be "+GetMACBytesLength()+" bytes in length");

            Byte[] Message = new Byte[CipherText.Length];
            int ret = SodiumPublicKeyBoxLibrary.crypto_box_open_detached(Message, CipherText, MAC, CipherText.Length, Nonce, OtherUserPublicKey,CurrentUserSecretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to open public detached Box");

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(CurrentUserSecretKey);
                SodiumSecureMemory.SecureClearBytes(OtherUserPublicKey);
            }

            return Message;
        }
    }
}
