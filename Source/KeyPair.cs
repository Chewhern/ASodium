using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public class KeyPair
    {
        private IntPtr PrivateKey;
        private int PrivateKeyLength;
        private IntPtr PublicKey;
        private int PublicKeyLength;
        private Boolean HadCleared = false;


        //Assume that the IntPtr comes from GuardedHeapAllocation with NoAccess 
        public KeyPair(IntPtr PrivateKey, int PrivateKeyLength, IntPtr PublicKey, int PublicKeyLength)
        {
            this.PrivateKey = PrivateKey;
            this.PrivateKeyLength = PrivateKeyLength;
            this.PublicKey = PublicKey;
            this.PublicKeyLength = PublicKeyLength;
        }

        public KeyPair()
        {
            this.PrivateKey = IntPtr.Zero;
            this.PrivateKeyLength = 0;
            this.PublicKey = IntPtr.Zero;
            this.PublicKeyLength = 0;
        }

        public IntPtr GetPrivateKey()
        {
            if (CheckIsInvalid()) 
            {
                throw new CryptographicException("Error: This is not an initialized keypair instance.. Aborting private key pointer export/use..");
            }
            return this.PrivateKey;
        }

        public int GetPrivateKeyLength()
        {
            if (CheckIsInvalid())
            {
                throw new CryptographicException("Error: This is not an initialized keypair instance.. Aborting private key length retrieval..");
            }
            return this.PrivateKeyLength;
        }

        public Byte[] GetPublicKey()
        {
            if (CheckIsInvalid()) 
            {
                throw new CryptographicException("Error: This is not an initialized keypair instance.. Aborting public key managed bytes export..");
            }
            Byte[] PublicKey = new Byte[this.PublicKeyLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(this.PublicKey);
            Marshal.Copy(this.PublicKey, PublicKey, 0, this.PublicKeyLength);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(this.PublicKey);

            return PublicKey;
        }

        public int GetPublicKeyLength()
        {
            if (CheckIsInvalid()) 
            {
                throw new CryptographicException("Error: This is not an initialized keypair instance.. Aborting public key length retrieval..");
            }
            return this.PublicKeyLength;
        }

        public void Clear()
        {
            if (CheckIsInvalid()==false && HadCleared==false) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(PrivateKey);
                SodiumGuardedHeapAllocation.Sodium_Free(PrivateKey);
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(PublicKey);
                SodiumGuardedHeapAllocation.Sodium_Free(PublicKey);
                PrivateKey = IntPtr.Zero;
                PublicKey = IntPtr.Zero;
                PrivateKeyLength = 0;
                PublicKeyLength = 0;
                HadCleared = true;
            }
            else 
            {
                throw new CryptographicException("Error: This keypair instance had been cleared. Not allowed to be cleared again");
            }
        }

        public Boolean CheckIsInvalid() 
        {
            return (this.PrivateKey == IntPtr.Zero ||
            this.PrivateKeyLength == 0 ||
            this.PublicKey == IntPtr.Zero ||
            this.PublicKeyLength == 0);
        }
    }
}
