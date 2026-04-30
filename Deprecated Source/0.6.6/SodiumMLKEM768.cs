using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public static class SodiumMLKEM768
    {
        public static int GetPublicKeyBytesLength()
        {
            return SodiumMLKEM768Library.crypto_kem_mlkem768_publickeybytes();
        }

        public static int GetPrivateKeyBytesLength()
        {
            return SodiumMLKEM768Library.crypto_kem_mlkem768_secretkeybytes();
        }

        public static int GetCipherTextBytesLength()
        {
            return SodiumMLKEM768Library.crypto_kem_mlkem768_ciphertextbytes();
        }

        public static int GetSharedSecretBytesLength()
        {
            return SodiumMLKEM768Library.crypto_kem_mlkem768_sharedsecretbytes();
        }

        public static int GetSeedBytesLength()
        {
            return SodiumMLKEM768Library.crypto_kem_mlkem768_seedbytes();
        }

        public static RevampedKeyPair GenerateSeededRevampedKeyPair(Byte[] Seed, Boolean ClearKey = false)
        {
            if (Seed == null)
            {
                throw new ArgumentException("Error: Seed must not be null/empty");
            }
            else
            {
                if (Seed.Length != GetSeedBytesLength())
                {
                    throw new ArgumentException("Error: Seed length must be " + GetSeedBytesLength() + " bytes");
                }
            }
            Byte[] PrivateKey = new Byte[GetPrivateKeyBytesLength()];
            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];

            SodiumMLKEM768Library.crypto_kem_mlkem768_seed_keypair(PublicKey, PrivateKey, Seed);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Seed);
            }

            return new RevampedKeyPair(PublicKey, PrivateKey, true);
        }

        public static KeyPair GenerateSeededKeyPair(IntPtr Seed, Boolean ClearKey = false)
        {
            if (Seed == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Seed must not be null/empty");
            }

            Boolean IsZero = false;
            Boolean IsZero2 = false;
            IntPtr PrivateKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetPrivateKeyBytesLength());
            IntPtr PublicKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetPublicKeyBytesLength());
            KeyPair MyKeyPair;
            if (IsZero == true && IsZero2 == true)
            {
                MyKeyPair = new KeyPair();
            }
            else
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Seed);
                SodiumMLKEM768Library.crypto_kem_mlkem768_seed_keypair(PublicKey, PrivateKey, Seed);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PublicKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PrivateKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Seed);
                MyKeyPair = new KeyPair(PrivateKey, GetPrivateKeyBytesLength(), PublicKey, GetPublicKeyBytesLength());
            }
            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Seed);
                SodiumGuardedHeapAllocation.Sodium_Free(Seed);
            }

            return MyKeyPair;
        }

        public static RevampedKeyPair GenerateRevampedKeyPair()
        {
            Byte[] PrivateKey = new Byte[GetPrivateKeyBytesLength()];
            Byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];

            SodiumMLKEM768Library.crypto_kem_mlkem768_keypair(PublicKey, PrivateKey);

            return new RevampedKeyPair(PublicKey, PrivateKey, true);
        }

        public static KeyPair GenerateKeyPair()
        {
            Boolean IsZero = false;
            Boolean IsZero2 = false;
            IntPtr PrivateKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetPrivateKeyBytesLength());
            IntPtr PublicKey = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetPublicKeyBytesLength());
            KeyPair MyKeyPair;
            if (IsZero == true && IsZero2 == true)
            {
                MyKeyPair = new KeyPair();
            }
            else
            {
                SodiumMLKEM768Library.crypto_kem_mlkem768_keypair(PublicKey, PrivateKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PublicKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PrivateKey);
                MyKeyPair = new KeyPair(PrivateKey, GetPrivateKeyBytesLength(), PublicKey, GetPublicKeyBytesLength());
            }

            return MyKeyPair;
        }

        public static EncapsulatedSharedSecretBox EncapsulateSecretKeyBytes(Byte[] PublicKey, Byte[] Seed, Boolean ClearKey = false)
        {
            EncapsulatedSharedSecretBox MyESSBox = new EncapsulatedSharedSecretBox();
            if (PublicKey == null)
            {
                throw new ArgumentException("Error: Public Key must not be null/empty");
            }
            else
            {
                if (PublicKey.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public Key length must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            if (Seed == null)
            {
                throw new ArgumentException("Error: Seed must not be null/empty");
            }
            else
            {
                if (Seed.Length != 32)
                {
                    throw new ArgumentException("Error: Seed must be 32 bytes in length");
                }
            }
            Byte[] SharedSecret = new Byte[GetSharedSecretBytesLength()];
            Byte[] CipherText = new Byte[GetCipherTextBytesLength()];

            int result = SodiumMLKEM768Library.crypto_kem_mlkem768_enc_deterministic(CipherText, SharedSecret, PublicKey, Seed);

            if (result == -1)
            {
                throw new Exception("Error: Unable to encapsulate properly..");
            }

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(Seed);
            }

            MyESSBox.SharedSecretBytes = SharedSecret;
            MyESSBox.CipherTextBytes = CipherText;

            return MyESSBox;
        }

        public static EncapsulatedSharedSecretBox EncapsulateSecretKeyBytes(Byte[] PublicKey, IntPtr Seed, Boolean ClearKey = false)
        {
            EncapsulatedSharedSecretBox MyESSBox = new EncapsulatedSharedSecretBox();
            if (PublicKey == null)
            {
                throw new ArgumentException("Error: Public Key must not be null/empty");
            }
            else
            {
                if (PublicKey.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public Key length must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            if (Seed == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Seed must not be null/empty");
            }
            Boolean IsZero = false;
            IntPtr SharedSecret = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetSharedSecretBytesLength());
            Byte[] CipherText = new Byte[GetCipherTextBytesLength()];

            if (IsZero == false)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Seed);
                int result = SodiumMLKEM768Library.crypto_kem_mlkem768_enc_deterministic(CipherText, SharedSecret, PublicKey, Seed);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Seed);

                if (result == -1)
                {
                    throw new Exception("Error: Unable to encapsulate properly..");
                }

                if (ClearKey)
                {
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Seed);
                    SodiumGuardedHeapAllocation.Sodium_Free(Seed);
                }
            }

            MyESSBox.SharedSecretIntPtr = SharedSecret;
            MyESSBox.CipherTextBytes = CipherText;

            return MyESSBox;
        }

        public static EncapsulatedSharedSecretBox EncapsulateSecretKeyBytes(Byte[] PublicKey)
        {
            EncapsulatedSharedSecretBox MyESSBox = new EncapsulatedSharedSecretBox();
            if (PublicKey == null)
            {
                throw new ArgumentException("Error: Public Key must not be null/empty");
            }
            else
            {
                if (PublicKey.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public Key length must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] SharedSecret = new Byte[GetSharedSecretBytesLength()];
            Byte[] CipherText = new Byte[GetCipherTextBytesLength()];

            int result = SodiumMLKEM768Library.crypto_kem_mlkem768_enc(CipherText, SharedSecret, PublicKey);

            if (result == -1)
            {
                throw new Exception("Error: Unable to encapsulate properly..");
            }

            MyESSBox.SharedSecretBytes = SharedSecret;
            MyESSBox.CipherTextBytes = CipherText;

            return MyESSBox;
        }

        public static EncapsulatedSharedSecretBox EncapsulateSecretKeyIntPtr(Byte[] PublicKey)
        {
            EncapsulatedSharedSecretBox MyESSBox = new EncapsulatedSharedSecretBox();
            if (PublicKey == null)
            {
                throw new ArgumentException("Error: Public Key must not be null/empty");
            }
            else
            {
                if (PublicKey.Length != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public Key length must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }

            Boolean IsZero = false;
            IntPtr SharedSecret = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetSharedSecretBytesLength());
            Byte[] CipherText = new Byte[GetCipherTextBytesLength()];

            if (IsZero == false)
            {
                int result = SodiumMLKEM768Library.crypto_kem_mlkem768_enc(CipherText, SharedSecret, PublicKey);

                if (result == -1)
                {
                    throw new Exception("Error: Unable to encapsulate properly..");
                }

                MyESSBox.SharedSecretIntPtr = SharedSecret;
                MyESSBox.CipherTextBytes = CipherText;
            }
            else
            {
                MyESSBox.SharedSecretIntPtr = IntPtr.Zero;
            }

            return MyESSBox;
        }

        public static Byte[] DecapsulateSharedSecret(Byte[] CipherText, Byte[] PrivateKey, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: Cipher Text must not be null/empty");
            }
            else
            {
                if (CipherText.Length != GetCipherTextBytesLength())
                {
                    throw new ArgumentException("Error: Cipher Text must be " + GetCipherTextBytesLength() + " bytes in length");
                }
            }
            if (PrivateKey == null)
            {
                throw new ArgumentException("Error: Private Key must not be null/empty");
            }
            else
            {
                if (PrivateKey.Length != GetPrivateKeyBytesLength())
                {
                    throw new ArgumentException("Error: Private Key must be " + GetPrivateKeyBytesLength() + " bytes in length");
                }
            }
            Byte[] SharedSecret = new Byte[GetSharedSecretBytesLength()];

            int result = SodiumMLKEM768Library.crypto_kem_mlkem768_dec(SharedSecret, CipherText, PrivateKey);

            if (result == -1)
            {
                throw new Exception("Error: Unable to decapsulate the shared secret from cipher text");
            }

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(PrivateKey);
            }

            return SharedSecret;
        }

        public static IntPtr DecapsulateSharedSecret(Byte[] CipherText, IntPtr PrivateKey, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: Cipher Text must not be null/empty");
            }
            else
            {
                if (CipherText.Length != GetCipherTextBytesLength())
                {
                    throw new ArgumentException("Error: Cipher Text must be " + GetCipherTextBytesLength() + " bytes in length");
                }
            }
            if (PrivateKey == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Private Key must not be null/empty");
            }

            Boolean IsZero = false;
            IntPtr SharedSecret = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetSharedSecretBytesLength());

            if (IsZero == false)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(PrivateKey);
                int result = SodiumMLKEM768Library.crypto_kem_mlkem768_dec(SharedSecret, CipherText, PrivateKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PrivateKey);

                if (result == -1)
                {
                    throw new Exception("Error: Unable to decapsulate the shared secret from cipher text");
                }

                if (ClearKey)
                {
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(PrivateKey);
                    SodiumGuardedHeapAllocation.Sodium_Free(PrivateKey);
                }
            }
            else
            {
                SharedSecret = IntPtr.Zero;
            }

            return SharedSecret;
        }
    }
}
