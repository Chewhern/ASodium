﻿using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumPublicKeyAuth
    {
        public static int GetSeedBytesLength()
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_seedbytes();
        }

        public static int GetPublicKeyBytesLength()
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_publickeybytes();
        }

        public static int GetSecretKeyBytesLength()
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_secretkeybytes();
        }

        public static int GetSignatureBytesLength()
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_bytes();
        }

        public static Byte GetPrimitiveByte() 
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_primitive();
        }

        public static KeyPair GenerateKeyPair()
        {
            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            SodiumPublicKeyAuthLibrary.crypto_sign_keypair(PublicKey, SecretKey);


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

            SodiumPublicKeyAuthLibrary.crypto_sign_keypair(PublicKey, SecretKey);

            RevampedKeyPair MyKeyPair = new RevampedKeyPair(PublicKey, SecretKey);

            return MyKeyPair;
        }

        public static Byte[] Sign(Byte[] Message,Byte[] SecretKey, Boolean ClearKey = false) 
        {
            if (Message == null) 
            {
                throw new ArgumentException("Error: Message cannot be null");
            }
            if (SecretKey == null) 
            {
                throw new ArgumentException("Error: Secret Key cannot be null");
            }
            else 
            {
                if (SecretKey.Length != GetSecretKeyBytesLength()) 
                {
                    throw new ArgumentException("Error: Secret Key length must be " + GetSecretKeyBytesLength() + " bytes in length");
                }
            }

            Byte[] SignatureMessage = new Byte[GetSignatureBytesLength()+Message.LongLength];
            long SignatureMessageLength = 0;

            int Result = SodiumPublicKeyAuthLibrary.crypto_sign(SignatureMessage, SignatureMessageLength, Message, Message.LongLength, SecretKey);

            if (Result != 0) 
            {
                throw new CryptographicException("Error: Failed to sign message");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }

            return SignatureMessage;
        }

        public static Byte[] Verify(Byte[] SignatureMessage,Byte[] PublicKey) 
        {
            if (SignatureMessage == null)
            {
                throw new ArgumentException("Error: Signature message cannot be null");
            }
            else
            {
                if (SignatureMessage.LongLength-GetSignatureBytesLength()==0)
                {
                    throw new ArgumentException("Error: Signature message is not properly signed..");
                }
            }
            if (PublicKey == null)
            {
                throw new ArgumentException("Error: Public key cannot be null");
            }
            else
            {
                if (PublicKey.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public Key length must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] Message = new Byte[SignatureMessage.LongLength - GetSignatureBytesLength()];
            long MessageLength = 0;

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_open(Message, MessageLength, SignatureMessage, SignatureMessage.LongLength, PublicKey);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to verify signature on the SignatureMessage");
            }
            return Message;
        }

        public static Byte[] SignDetached(Byte[] Message, Byte[] SecretKey, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message cannot be null");
            }
            if (SecretKey == null)
            {
                throw new ArgumentException("Error: Secret Key cannot be null");
            }
            else
            {
                if (SecretKey.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Secret Key length must be " + GetSecretKeyBytesLength() + " bytes in length");
                }
            }

            Byte[] Signature = new Byte[GetSignatureBytesLength()];
            long SignatureLength = 0;

            int Result = SodiumPublicKeyAuthLibrary.crypto_sign_detached(Signature, SignatureLength, Message, Message.LongLength, SecretKey);

            if (Result != 0)
            {
                throw new CryptographicException("Error: Failed to sign message and create signature");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }

            return Signature;
        }

        public static Boolean VerifyDetached(Byte[] Signature, Byte[] Message, Byte[] PublicKey)
        {
            if (Signature == null)
            {
                throw new ArgumentException("Error: Signature cannot be null");
            }
            else
            {
                if (Signature.LongLength !=GetSignatureBytesLength())
                {
                    throw new ArgumentException("Error: Signature length must have "+GetSignatureBytesLength()+" bytes in length");
                }
            }

            if (Message == null)
            {
                throw new ArgumentException("Error: Message cannot be null");
            }

            if (PublicKey == null)
            {
                throw new ArgumentException("Error: Public key cannot be null");
            }
            else
            {
                if (PublicKey.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public Key length must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_verify_detached(Signature,Message,Message.LongLength,PublicKey);

            if (result != 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public static Byte[] GeneratePublicKey(Byte[] SecretKey,Boolean ClearKey=false) 
        {
            if (SecretKey == null)
            {
                throw new ArgumentException("Error: Secret Key cannot be null");
            }
            else
            {
                if (SecretKey.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Secret Key length must be " + GetSecretKeyBytesLength() + " bytes in length");
                }
            }

            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_ed25519_sk_to_pk(PublicKey, SecretKey);

            if(result != 0) 
            {
                throw new CryptographicException("Error: Failed to generate public key");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }

            return PublicKey;
        }

        public static Byte[] ExtractSeed(Byte[] SecretKey,Boolean ClearKey=false) 
        {
            if (SecretKey == null)
            {
                throw new ArgumentException("Error: Secret Key cannot be null");
            }
            else
            {
                if (SecretKey.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Secret Key length must be " + GetSecretKeyBytesLength() + " bytes in length");
                }
            }

            Byte[] Seed = new Byte[GetSeedBytesLength()];

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_ed25519_sk_to_seed(Seed, SecretKey);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to extract seeds");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }

            return Seed;
        }

        public static IntPtr ExtractSeedIntPtr(Byte[] SecretKey, Boolean ClearKey = false) 
        {
            if (SecretKey == null)
            {
                throw new ArgumentException("Error: Secret Key cannot be null");
            }
            else
            {
                if (SecretKey.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Secret Key length must be " + GetSecretKeyBytesLength() + " bytes in length");
                }
            }

            Byte[] Seed = new Byte[GetSeedBytesLength()];

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_ed25519_sk_to_seed(Seed, SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to extract seeds");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }

            Boolean IsZero = true;
            IntPtr SeedIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Seed.Length);
            if (IsZero == false) 
            {
                Marshal.Copy(Seed, 0, SeedIntPtr, Seed.Length);

                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SeedIntPtr);

                SodiumSecureMemory.SecureClearBytes(Seed);

                return SeedIntPtr;
            }
            else 
            {
                SodiumSecureMemory.SecureClearBytes(Seed);

                return IntPtr.Zero;
            }
        }

        public static PublicKeyAuthSealBox SealedSign(Byte[] Message) 
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message cannot be null");
            }

            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            SodiumPublicKeyAuthLibrary.crypto_sign_keypair(PublicKey, SecretKey);

            Byte[] SignatureMessage = new Byte[Message.LongLength + GetSignatureBytesLength()];
            long SignatureMessageLength = 0;

            int result = SodiumPublicKeyAuthLibrary.crypto_sign(SignatureMessage, SignatureMessageLength, Message, Message.LongLength, SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to sign message");
            }

            SodiumSecureMemory.SecureClearBytes(SecretKey);

            PublicKeyAuthSealBox MySealBox = new PublicKeyAuthSealBox();
            MySealBox.SignatureMessage = SignatureMessage;
            MySealBox.PublicKey = PublicKey;

            return MySealBox;
        }

        public static PublicKeyAuthDetachedSealBox SealedSignDetached(Byte[] Message)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message cannot be null");
            }

            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            SodiumPublicKeyAuthLibrary.crypto_sign_keypair(PublicKey, SecretKey);

            Byte[] Signature = new Byte[GetSignatureBytesLength()];
            long SignatureLength = 0;

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_detached(Signature,SignatureLength,Message,Message.LongLength,SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to sign message");
            }

            SodiumSecureMemory.SecureClearBytes(SecretKey);

            PublicKeyAuthDetachedSealBox MySealBox = new PublicKeyAuthDetachedSealBox();

            MySealBox.PublicKey = PublicKey;
            MySealBox.Signature = Signature;

            return MySealBox;
        }
    }
}
