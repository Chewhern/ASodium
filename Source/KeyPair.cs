using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public class KeyPair
    {
        private readonly IntPtr PrivateKey;
        private readonly int PrivateKeyLength;
        private readonly IntPtr PublicKey;
        private readonly int PublicKeyLength;


        //Assume that the IntPtr comes from GuardedHeapAllocation with NoAccess 
        public KeyPair(IntPtr PrivateKey,int PrivateKeyLength, IntPtr PublicKey, int PublicKeyLength) 
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
            IntPtr ReadOnlyPrivateKey = IntPtr.Zero;
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(this.PrivateKey);
            ReadOnlyPrivateKey = this.PrivateKey;

            return ReadOnlyPrivateKey;
        }

        public void ProtectPrivateKey() 
        {
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(this.PrivateKey);
        }

        public int GetPrivateKeyLength() 
        {
            return this.PrivateKeyLength;
        }

        public Byte[] GetPublicKey() 
        {
            Byte[] PublicKey = new Byte[this.PublicKeyLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(this.PublicKey);
            Marshal.Copy(this.PublicKey, PublicKey, 0, this.PublicKeyLength);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(this.PublicKey);

            return PublicKey;
        }

        public int GetPublicKeyLength() 
        {
            return this.PublicKeyLength;
        }

        public void Clear() 
        {
            SodiumGuardedHeapAllocation.Sodium_Free(PrivateKey);
            SodiumGuardedHeapAllocation.Sodium_Free(PublicKey);
            new KeyPair();
        }
    }
}
