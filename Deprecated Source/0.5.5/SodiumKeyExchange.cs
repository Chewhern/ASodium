﻿using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumKeyExchange
    {
        public static int GetPublicKeyBytesLength() 
        {
            return SodiumKeyExchangeLibrary.crypto_kx_publickeybytes();
        }

        public static int GetSecretKeyBytesLength() 
        {
            return SodiumKeyExchangeLibrary.crypto_kx_secretkeybytes();
        }

        public static int GetSeedBytesLength() 
        {
            return SodiumKeyExchangeLibrary.crypto_kx_seedbytes();
        }

        public static int GetSessionKeyBytesLength() 
        {
            return SodiumKeyExchangeLibrary.crypto_kx_sessionkeybytes();
        }

        public static RevampedKeyPair GenerateRevampedKeyPair() 
        {
            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            int result = SodiumKeyExchangeLibrary.crypto_kx_keypair(PublicKey, SecretKey);

            RevampedKeyPair MyKeyPair = new RevampedKeyPair(PublicKey, SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create Key Exchange Revamped Key Pair");
            }

            return MyKeyPair;
        }

        public static KeyPair GenerateKeyPair()
        {
            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            int result = SodiumKeyExchangeLibrary.crypto_kx_keypair(PublicKey, SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create Key Exchange Revamped Key Pair");
            }

            Boolean IsZero = true;
            IntPtr PublicKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, PublicKey.Length);
            Boolean IsZero2 = true;
            IntPtr SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, SecretKey.Length);

            if(IsZero==false && IsZero2 == false) 
            {
                Marshal.Copy(PublicKey, 0, PublicKeyIntPtr, GetPublicKeyBytesLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PublicKeyIntPtr);
                Marshal.Copy(SecretKey, 0, SecretKeyIntPtr, GetSecretKeyBytesLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                SodiumSecureMemory.SecureClearBytes(PublicKey);
                SodiumSecureMemory.SecureClearBytes(SecretKey);
                return new KeyPair(SecretKeyIntPtr, GetSecretKeyBytesLength(), PublicKeyIntPtr, GetPublicKeyBytesLength());
            }
            else 
            {
                SodiumSecureMemory.SecureClearBytes(PublicKey);
                SodiumSecureMemory.SecureClearBytes(SecretKey);
                return new KeyPair(IntPtr.Zero, 0, IntPtr.Zero, 0);
            }
        }

        public static SodiumKeyExchangeSharedSecretBox CalculateClientSharedSecret(Byte[] ClientPK,Byte[] ClientSK, Byte[] ServerPK) 
        {
            if (ClientPK == null) 
            {
                throw new ArgumentException("Error: Client PK must not be null");
            }
            else 
            {
                if (ClientPK.Length != GetPublicKeyBytesLength()) 
                {
                    throw new ArgumentException("Error: Client PK length must exactly be " + GetPublicKeyBytesLength() + " bytes");
                }
            }
            if (ClientSK == null)
            {
                throw new ArgumentException("Error: Client SK must not be null");
            }
            else
            {
                if (ClientSK.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Client SK length must exactly be " + GetSecretKeyBytesLength() + " bytes");
                }
            }
            if (ServerPK == null)
            {
                throw new ArgumentException("Error: Server PK must not be null");
            }
            else
            {
                if (ServerPK.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Server PK length must exactly be " + GetPublicKeyBytesLength() + " bytes");
                }
            }

            Byte[] ReadSharedSecret = new Byte[GetSessionKeyBytesLength()];
            Byte[] TransferSharedSecret = new Byte[GetSessionKeyBytesLength()];

            int result = SodiumKeyExchangeLibrary.crypto_kx_client_session_keys(ReadSharedSecret, TransferSharedSecret, ClientPK, ClientSK, ServerPK);

            if (result != 0) 
            {
                throw new CryptographicException("Failed to calculate key exchange's shared secret");
            }

            SodiumKeyExchangeSharedSecretBox MySharedSecretBox = new SodiumKeyExchangeSharedSecretBox();

            MySharedSecretBox.ReadSharedSecret = ReadSharedSecret;
            MySharedSecretBox.TransferSharedSecret = TransferSharedSecret;

            return MySharedSecretBox;
        }

        public static SodiumKeyExchangeSharedSecretBox CalculateServerSharedSecret(Byte[] ServerPK,Byte[] ServerSK,Byte[] ClientPK)
        {
            if (ServerPK == null)
            {
                throw new ArgumentException("Error: Server PK must not be null");
            }
            else
            {
                if (ServerPK.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Server PK length must exactly be " + GetPublicKeyBytesLength() + " bytes");
                }
            }
            if (ServerSK == null)
            {
                throw new ArgumentException("Error: Server SK must not be null");
            }
            else
            {
                if (ServerSK.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Server SK length must exactly be " + GetSecretKeyBytesLength() + " bytes");
                }
            }
            if (ClientPK == null)
            {
                throw new ArgumentException("Error: Client PK must not be null");
            }
            else
            {
                if (ClientPK.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Client PK length must exactly be " + GetPublicKeyBytesLength() + " bytes");
                }
            }

            Byte[] ReadSharedSecret = new Byte[GetSessionKeyBytesLength()];
            Byte[] TransferSharedSecret = new Byte[GetSessionKeyBytesLength()];

            int result = SodiumKeyExchangeLibrary.crypto_kx_server_session_keys(ReadSharedSecret, TransferSharedSecret,ServerPK,ServerSK,ClientPK);

            if (result != 0)
            {
                throw new CryptographicException("Failed to calculate key exchange's shared secret");
            }

            SodiumKeyExchangeSharedSecretBox MySharedSecretBox = new SodiumKeyExchangeSharedSecretBox();

            MySharedSecretBox.ReadSharedSecret = ReadSharedSecret;
            MySharedSecretBox.TransferSharedSecret = TransferSharedSecret;

            return MySharedSecretBox;
        }

        public static SodiumKeyExchangeSharedSecretIntPtrBox CalculateClientSharedSecretIntPtr(Byte[] ClientPK, Byte[] ClientSK, Byte[] ServerPK)
        {
            if (ClientPK == null)
            {
                throw new ArgumentException("Error: Client PK must not be null");
            }
            else
            {
                if (ClientPK.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Client PK length must exactly be " + GetPublicKeyBytesLength() + " bytes");
                }
            }
            if (ClientSK == null)
            {
                throw new ArgumentException("Error: Client SK must not be null");
            }
            else
            {
                if (ClientSK.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Client SK length must exactly be " + GetSecretKeyBytesLength() + " bytes");
                }
            }
            if (ServerPK == null)
            {
                throw new ArgumentException("Error: Server PK must not be null");
            }
            else
            {
                if (ServerPK.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Server PK length must exactly be " + GetPublicKeyBytesLength() + " bytes");
                }
            }

            Byte[] ReadSharedSecret = new Byte[GetSessionKeyBytesLength()];
            Byte[] TransferSharedSecret = new Byte[GetSessionKeyBytesLength()];

            int result = SodiumKeyExchangeLibrary.crypto_kx_client_session_keys(ReadSharedSecret, TransferSharedSecret, ClientPK, ClientSK, ServerPK);

            if (result != 0)
            {
                throw new CryptographicException("Failed to calculate key exchange's shared secret");
            }

            SodiumKeyExchangeSharedSecretIntPtrBox MySharedSecretBox = new SodiumKeyExchangeSharedSecretIntPtrBox();

            Boolean IsZero = true;
            IntPtr ReadSharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, ReadSharedSecret.Length);
            Boolean IsZero2 = true;
            IntPtr TransferSharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, TransferSharedSecret.Length);

            if(IsZero==false && IsZero2 == false) 
            {
                Marshal.Copy(ReadSharedSecret, 0, ReadSharedSecretIntPtr, ReadSharedSecret.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ReadSharedSecretIntPtr);
                Marshal.Copy(TransferSharedSecret, 0, TransferSharedSecretIntPtr, TransferSharedSecret.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(TransferSharedSecretIntPtr);
            }
            else 
            {
                MySharedSecretBox.ReadSharedSecret = IntPtr.Zero;
                MySharedSecretBox.ReadSharedSecretLength = 0;
                MySharedSecretBox.TransferSharedSecret = IntPtr.Zero;
                MySharedSecretBox.TransferSharedSecretLength = 0;
            }

            SodiumSecureMemory.SecureClearBytes(ReadSharedSecret);
            SodiumSecureMemory.SecureClearBytes(TransferSharedSecret);

            return MySharedSecretBox;
        }

        public static SodiumKeyExchangeSharedSecretIntPtrBox CalculateServerSharedSecretIntPtr(Byte[] ServerPK, Byte[] ServerSK, Byte[] ClientPK)
        {
            if (ServerPK == null)
            {
                throw new ArgumentException("Error: Server PK must not be null");
            }
            else
            {
                if (ServerPK.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Server PK length must exactly be " + GetPublicKeyBytesLength() + " bytes");
                }
            }
            if (ServerSK == null)
            {
                throw new ArgumentException("Error: Server SK must not be null");
            }
            else
            {
                if (ServerSK.Length != GetSecretKeyBytesLength())
                {
                    throw new ArgumentException("Error: Server SK length must exactly be " + GetSecretKeyBytesLength() + " bytes");
                }
            }
            if (ClientPK == null)
            {
                throw new ArgumentException("Error: Client PK must not be null");
            }
            else
            {
                if (ClientPK.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Client PK length must exactly be " + GetPublicKeyBytesLength() + " bytes");
                }
            }

            Byte[] ReadSharedSecret = new Byte[GetSessionKeyBytesLength()];
            Byte[] TransferSharedSecret = new Byte[GetSessionKeyBytesLength()];

            int result = SodiumKeyExchangeLibrary.crypto_kx_server_session_keys(ReadSharedSecret, TransferSharedSecret, ServerPK, ServerSK, ClientPK);

            if (result != 0)
            {
                throw new CryptographicException("Failed to calculate key exchange's shared secret");
            }


            SodiumKeyExchangeSharedSecretIntPtrBox MySharedSecretBox = new SodiumKeyExchangeSharedSecretIntPtrBox();

            Boolean IsZero = true;
            IntPtr ReadSharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, ReadSharedSecret.Length);
            Boolean IsZero2 = true;
            IntPtr TransferSharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, TransferSharedSecret.Length);

            if (IsZero == false && IsZero2 == false)
            {
                Marshal.Copy(ReadSharedSecret, 0, ReadSharedSecretIntPtr, ReadSharedSecret.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ReadSharedSecretIntPtr);
                Marshal.Copy(TransferSharedSecret, 0, TransferSharedSecretIntPtr, TransferSharedSecret.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(TransferSharedSecretIntPtr);
            }
            else
            {
                MySharedSecretBox.ReadSharedSecret = IntPtr.Zero;
                MySharedSecretBox.ReadSharedSecretLength = 0;
                MySharedSecretBox.TransferSharedSecret = IntPtr.Zero;
                MySharedSecretBox.TransferSharedSecretLength = 0;
            }

            SodiumSecureMemory.SecureClearBytes(ReadSharedSecret);
            SodiumSecureMemory.SecureClearBytes(TransferSharedSecret);

            return MySharedSecretBox;
        }
    }
}
