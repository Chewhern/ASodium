using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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
            Boolean IsZero = true;
            IntPtr PublicKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetPublicKeyBytesLength());
            Boolean IsZero2 = true;
            IntPtr SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, GetSecretKeyBytesLength());

            if(IsZero==false && IsZero2 == false) 
            {
                int result = SodiumKeyExchangeLibrary.crypto_kx_keypair(PublicKeyIntPtr, SecretKeyIntPtr);

                if (result != 0)
                {
                    throw new CryptographicException("Error: Failed to create Key Exchange Key Pair");
                }

                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);

                return new KeyPair(SecretKeyIntPtr, GetSecretKeyBytesLength(), PublicKeyIntPtr, GetPublicKeyBytesLength());
            }
            else 
            {
                return new KeyPair(IntPtr.Zero, 0, IntPtr.Zero, 0);
            }
        }

        public static RevampedKeyPair GenerateSeededRevampedKeyPair(Byte[] Seed, Boolean ClearKey = false)
        {
            if (Seed == null) 
            {
                throw new ArgumentException("Error: Seed must not be null");
            }
            else 
            {
                if(Seed.Length != GetSeedBytesLength()) 
                {
                    throw new ArgumentException("Error: Seed must exactly be " + GetSeedBytesLength() + " in bytes");
                }
            }
            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            Byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            int result = SodiumKeyExchangeLibrary.crypto_kx_seed_keypair(PublicKey, SecretKey,Seed);

            RevampedKeyPair MyKeyPair = new RevampedKeyPair(PublicKey, SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create Key Exchange Revamped Key Pair");
            }

            if (ClearKey) 
            {
                SodiumSecureMemory.SecureClearBytes(Seed);
            }

            return MyKeyPair;
        }

        public static KeyPair GenerateSeededKeyPair(IntPtr SeedIntPtr, Boolean ClearKey = false)
        {
            if(SeedIntPtr == IntPtr.Zero) 
            {
                throw new ArgumentException("Error: Seed must not empty");
            }

            Boolean IsZero = true;
            IntPtr PublicKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetPublicKeyBytesLength());
            Boolean IsZero2 = true;
            IntPtr SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, GetSecretKeyBytesLength());

            if (IsZero == false && IsZero2 == false)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SeedIntPtr);
                int result = SodiumKeyExchangeLibrary.crypto_kx_seed_keypair(PublicKeyIntPtr, SecretKeyIntPtr,SeedIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SeedIntPtr);

                if (result != 0)
                {
                    throw new CryptographicException("Error: Failed to create Key Exchange Key Pair");
                }

                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);

                if (ClearKey)
                {
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SeedIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_Free(SeedIntPtr);
                }
                return new KeyPair(SecretKeyIntPtr, GetSecretKeyBytesLength(), PublicKeyIntPtr, GetPublicKeyBytesLength());
            }
            else
            {
                if (ClearKey)
                {
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SeedIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_Free(SeedIntPtr);
                }
                return new KeyPair(IntPtr.Zero, 0, IntPtr.Zero, 0);
            }
        }

        public static SodiumKeyExchangeSharedSecretBox CalculateClientSharedSecret(Byte[] ClientPK,Byte[] ClientSK, Byte[] ServerPK, Boolean ClearKey = false) 
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

            if (ClearKey) 
            {
                SodiumSecureMemory.SecureClearBytes(ClientSK);
            }

            return MySharedSecretBox;
        }

        public static SodiumKeyExchangeSharedSecretBox CalculateServerSharedSecret(Byte[] ServerPK,Byte[] ServerSK,Byte[] ClientPK, Boolean ClearKey = false)
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

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(ServerSK);
            }

            return MySharedSecretBox;
        }

        public static SodiumKeyExchangeSharedSecretIntPtrBox CalculateClientSharedSecret(Byte[] ClientPK, IntPtr ClientSK, Byte[] ServerPK, Boolean ClearKey=false)
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
            if (ClientSK == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Client SK must not be null");
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

            SodiumKeyExchangeSharedSecretIntPtrBox MySharedSecretBox = new SodiumKeyExchangeSharedSecretIntPtrBox();

            Boolean IsZero = true;
            IntPtr ReadSharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetSessionKeyBytesLength());
            Boolean IsZero2 = true;
            IntPtr TransferSharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, GetSessionKeyBytesLength());

            if(IsZero==false && IsZero2 == false) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(ClientSK);
                int result = SodiumKeyExchangeLibrary.crypto_kx_client_session_keys(ReadSharedSecretIntPtr, TransferSharedSecretIntPtr, ClientPK, ClientSK, ServerPK);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ClientSK);

                if (result != 0)
                {
                    throw new CryptographicException("Failed to calculate key exchange's shared secret");
                }

                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ReadSharedSecretIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(TransferSharedSecretIntPtr);

                MySharedSecretBox.ReadSharedSecret = ReadSharedSecretIntPtr;
                MySharedSecretBox.ReadSharedSecretLength = GetSessionKeyBytesLength();
                MySharedSecretBox.TransferSharedSecret = TransferSharedSecretIntPtr;
                MySharedSecretBox.ReadSharedSecretLength = GetSessionKeyBytesLength();
            }
            else 
            {
                MySharedSecretBox.ReadSharedSecret = IntPtr.Zero;
                MySharedSecretBox.ReadSharedSecretLength = 0;
                MySharedSecretBox.TransferSharedSecret = IntPtr.Zero;
                MySharedSecretBox.TransferSharedSecretLength = 0;
            }

            if (ClearKey) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(ClientSK);
                SodiumGuardedHeapAllocation.Sodium_Free(ClientSK);
            }

            return MySharedSecretBox;
        }

        public static SodiumKeyExchangeSharedSecretIntPtrBox CalculateServerSharedSecret(Byte[] ServerPK, IntPtr ServerSK, Byte[] ClientPK, Boolean ClearKey=false)
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
            if (ServerSK == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Server SK must not be null");
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

            SodiumKeyExchangeSharedSecretIntPtrBox MySharedSecretBox = new SodiumKeyExchangeSharedSecretIntPtrBox();

            Boolean IsZero = true;
            IntPtr ReadSharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetSessionKeyBytesLength());
            Boolean IsZero2 = true;
            IntPtr TransferSharedSecretIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, GetSessionKeyBytesLength());

            if (IsZero == false && IsZero2 == false)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(ServerSK);
                int result = SodiumKeyExchangeLibrary.crypto_kx_server_session_keys(ReadSharedSecretIntPtr, TransferSharedSecretIntPtr, ServerPK, ServerSK, ClientPK);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ServerSK);

                if (result != 0)
                {
                    throw new CryptographicException("Failed to calculate key exchange's shared secret");
                }

                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ReadSharedSecretIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(TransferSharedSecretIntPtr);

                MySharedSecretBox.ReadSharedSecret = ReadSharedSecretIntPtr;
                MySharedSecretBox.ReadSharedSecretLength = GetSessionKeyBytesLength();
                MySharedSecretBox.TransferSharedSecret = TransferSharedSecretIntPtr;
                MySharedSecretBox.ReadSharedSecretLength = GetSessionKeyBytesLength();
            }
            else
            {
                MySharedSecretBox.ReadSharedSecret = IntPtr.Zero;
                MySharedSecretBox.ReadSharedSecretLength = 0;
                MySharedSecretBox.TransferSharedSecret = IntPtr.Zero;
                MySharedSecretBox.TransferSharedSecretLength = 0;
            }

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(ServerSK);
                SodiumGuardedHeapAllocation.Sodium_Free(ServerSK);
            }

            return MySharedSecretBox;
        }
    }
}
