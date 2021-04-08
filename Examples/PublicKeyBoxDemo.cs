using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using ASodium;

namespace LibSodiumBinding
{
    public partial class PublicKeyBoxDemo : Form
    {
        public PublicKeyBoxDemo()
        {
            InitializeComponent();
        }

        private void KeyPairGenBTN_Click(object sender, EventArgs e)
        {
            KeyPair MyKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            IntPtr PrivateKeyIntPtr = MyKeyPair.GetPrivateKey();
            Byte[] PrivateKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            Marshal.Copy(PrivateKeyIntPtr, PrivateKey, 0, 32);
            MyKeyPair.ProtectPrivateKey();
            MyKeyPair.Clear();
            RevampedKeyPair MyRevampedKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            MyRevampedKeyPair.Clear();
        }

        private void ReadMeBTN_Click(object sender, EventArgs e)
        {
            MessageBox.Show("KeyPair is the new KeyPair type while RevampedKeyPair is the old KeyPair type with certain adjustments");
            MessageBox.Show("Revamped Key Pair acts as the same as Sodium.Core KeyPair with a little adjustment on changing Dispose to Clear");
            MessageBox.Show("Revamped Key Pair now uses SodiumSecureMemory to clear the Public Key and Private Key that stores in Key Pair");
            MessageBox.Show("KeyPair uses SodiumGuardedHeapAllocation to store Public and Private Key in Sodium Allocated IntPtr");
            MessageBox.Show("Unlike Revamped Key Pair, Key Pair uses no memory protection('ProtectedMemory.Protect') instead both public and private key IntPtr are returned as NoAccess IntPtr");
            MessageBox.Show("To read the private key from Key Pair due to it's in IntPtr format, one must know how to use Marshal to read the private key");
            MessageBox.Show("Once private key was read, you can protect it once again through (ProtectPrivateKey) function which makes the IntPtr of Private Key NoAccess again.");
            MessageBox.Show("KeyPair have a slight chance in returning IntPtr with address IntPtr.Zero which is null address in C#, make sure that both your private and public key length was not in 0");
            MessageBox.Show("KeyPair needs to have further testing..");
        }

        private void CreateBTN_Click(object sender, EventArgs e)
        {
            //RevampedKeyPair
            RevampedKeyPair AliceKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Nonce = SodiumPublicKeyBox.GenerateNonce();
            Byte[] CipherText = SodiumPublicKeyBox.Create(RandomMessage, Nonce, AliceKeyPair.PrivateKey, BobKeyPair.PublicKey);
            AliceKeyPair.Clear();
            BobKeyPair.Clear();
            //KeyPair
            KeyPair AliceNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            KeyPair BobNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            IntPtr AliceSecretKeyIntPtr = AliceNewKeyPair.GetPrivateKey();
            Byte[] AliceSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            IntPtr BobSecretKeyIntPtr = BobNewKeyPair.GetPrivateKey();
            Byte[] BobSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            Marshal.Copy(AliceSecretKeyIntPtr, AliceSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Marshal.Copy(BobSecretKeyIntPtr, BobSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            CipherText = SodiumPublicKeyBox.Create(RandomMessage, Nonce, AliceSecretKey, BobNewKeyPair.GetPublicKey());
            AliceNewKeyPair.ProtectPrivateKey();
            BobNewKeyPair.ProtectPrivateKey();
            AliceNewKeyPair.Clear();
            BobNewKeyPair.Clear();
        }

        private void OpenBTN_Click(object sender, EventArgs e)
        {
            //RevampedKeyPair
            RevampedKeyPair AliceKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Nonce = SodiumPublicKeyBox.GenerateNonce();
            Byte[] CipherText = SodiumPublicKeyBox.Create(RandomMessage, Nonce, AliceKeyPair.PrivateKey, BobKeyPair.PublicKey);
            Byte[] PlainText = SodiumPublicKeyBox.Open(CipherText, Nonce, BobKeyPair.PrivateKey, AliceKeyPair.PublicKey);
            AliceKeyPair.Clear();
            BobKeyPair.Clear();
            //KeyPair
            KeyPair AliceNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            KeyPair BobNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            IntPtr AliceSecretKeyIntPtr = AliceNewKeyPair.GetPrivateKey();
            Byte[] AliceSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            IntPtr BobSecretKeyIntPtr = BobNewKeyPair.GetPrivateKey();
            Byte[] BobSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            Marshal.Copy(AliceSecretKeyIntPtr, AliceSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Marshal.Copy(BobSecretKeyIntPtr, BobSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            CipherText = SodiumPublicKeyBox.Create(RandomMessage, Nonce, AliceSecretKey, BobNewKeyPair.GetPublicKey());
            PlainText = SodiumPublicKeyBox.Open(CipherText, Nonce, BobSecretKey, AliceNewKeyPair.GetPublicKey());
            AliceNewKeyPair.ProtectPrivateKey();
            BobNewKeyPair.ProtectPrivateKey();
            AliceNewKeyPair.Clear();
            BobNewKeyPair.Clear();
        }

        private void CreateDetachedBoxBTN_Click(object sender, EventArgs e)
        {
            //RevampedKeyPair
            RevampedKeyPair AliceKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Nonce = SodiumPublicKeyBox.GenerateNonce();
            PublicKeyBoxDetachedBox MyDetachedBox = SodiumPublicKeyBox.CreateDetached(RandomMessage, Nonce, AliceKeyPair.PrivateKey, BobKeyPair.PublicKey);
            AliceKeyPair.Clear();
            BobKeyPair.Clear();
            //KeyPair
            KeyPair AliceNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            KeyPair BobNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            IntPtr AliceSecretKeyIntPtr = AliceNewKeyPair.GetPrivateKey();
            Byte[] AliceSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            IntPtr BobSecretKeyIntPtr = BobNewKeyPair.GetPrivateKey();
            Byte[] BobSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            Marshal.Copy(AliceSecretKeyIntPtr, AliceSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Marshal.Copy(BobSecretKeyIntPtr, BobSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            MyDetachedBox = SodiumPublicKeyBox.CreateDetached(RandomMessage, Nonce, AliceSecretKey, BobNewKeyPair.GetPublicKey());
            AliceNewKeyPair.ProtectPrivateKey();
            BobNewKeyPair.ProtectPrivateKey();
            AliceNewKeyPair.Clear();
            BobNewKeyPair.Clear();
        }

        private void OpenDetachedBoxBTN_Click(object sender, EventArgs e)
        {
            //==RevampedKeyPair==
            RevampedKeyPair AliceKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Nonce = SodiumPublicKeyBox.GenerateNonce();
            PublicKeyBoxDetachedBox MyDetachedBox = SodiumPublicKeyBox.CreateDetached(RandomMessage, Nonce, AliceKeyPair.PrivateKey, BobKeyPair.PublicKey);
            Byte[] PlainText = SodiumPublicKeyBox.OpenDetached(MyDetachedBox.CipherText,MyDetachedBox.MAC, Nonce, BobKeyPair.PrivateKey, AliceKeyPair.PublicKey);
            AliceKeyPair.Clear();
            BobKeyPair.Clear();
            //==KeyPair==
            KeyPair AliceNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            KeyPair BobNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            IntPtr AliceSecretKeyIntPtr = AliceNewKeyPair.GetPrivateKey();
            Byte[] AliceSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            IntPtr BobSecretKeyIntPtr = BobNewKeyPair.GetPrivateKey();
            Byte[] BobSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            Marshal.Copy(AliceSecretKeyIntPtr, AliceSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Marshal.Copy(BobSecretKeyIntPtr, BobSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            MyDetachedBox = SodiumPublicKeyBox.CreateDetached(RandomMessage, Nonce, AliceSecretKey, BobNewKeyPair.GetPublicKey());
            PlainText = SodiumPublicKeyBox.OpenDetached(MyDetachedBox.CipherText, MyDetachedBox.MAC, Nonce, BobSecretKey, AliceNewKeyPair.GetPublicKey());
            AliceNewKeyPair.ProtectPrivateKey();
            BobNewKeyPair.ProtectPrivateKey();
            AliceNewKeyPair.Clear();
            BobNewKeyPair.Clear();
        }

        private void CreatePCIBTN_Click(object sender, EventArgs e)
        {
            //==RevampedKeyPair==
            RevampedKeyPair AliceKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Nonce = SodiumPublicKeyBox.GenerateNonce();
            Byte[] SharedSecret1 = SodiumPublicKeyBoxPCI.CalculateSharedSecret(BobKeyPair.PublicKey,AliceKeyPair.PrivateKey);
            Byte[] SharedSecret2 = SodiumPublicKeyBoxPCI.CalculateSharedSecret(AliceKeyPair.PublicKey, BobKeyPair.PrivateKey);
            Byte[] AliceCipherText = SodiumPublicKeyBoxPCI.Create(RandomMessage, Nonce, SharedSecret1);
            Byte[] BobReceivedPlainText = SodiumPublicKeyBoxPCI.Open(AliceCipherText, Nonce, SharedSecret2);
            AliceKeyPair.Clear();
            BobKeyPair.Clear();
            //==KeyPair==
            KeyPair AliceNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            KeyPair BobNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            IntPtr AliceSecretKeyIntPtr = AliceNewKeyPair.GetPrivateKey();
            Byte[] AliceSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            IntPtr BobSecretKeyIntPtr = BobNewKeyPair.GetPrivateKey();
            Byte[] BobSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            Marshal.Copy(AliceSecretKeyIntPtr, AliceSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Marshal.Copy(BobSecretKeyIntPtr, BobSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Byte[] SharedSecretAlice = SodiumPublicKeyBoxPCI.CalculateSharedSecret(BobNewKeyPair.GetPublicKey(), AliceSecretKey);
            Byte[] SharedSecretBob = SodiumPublicKeyBoxPCI.CalculateSharedSecret(AliceNewKeyPair.GetPublicKey(), BobSecretKey);
            AliceCipherText = SodiumPublicKeyBoxPCI.Create(RandomMessage, Nonce, SharedSecretAlice);
            BobReceivedPlainText = SodiumPublicKeyBoxPCI.Open(AliceCipherText, Nonce, SharedSecretBob);
            AliceNewKeyPair.ProtectPrivateKey();
            BobNewKeyPair.ProtectPrivateKey();
            AliceNewKeyPair.Clear();
            BobNewKeyPair.Clear();
        }

        private void CreateDetachedPCIBTN_Click(object sender, EventArgs e)
        {
            //==RevampedKeyPair==
            RevampedKeyPair AliceKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] Nonce = SodiumPublicKeyBox.GenerateNonce();
            Byte[] SharedSecret1 = SodiumPublicKeyBoxPCI.CalculateSharedSecret(BobKeyPair.PublicKey, AliceKeyPair.PrivateKey);
            Byte[] SharedSecret2 = SodiumPublicKeyBoxPCI.CalculateSharedSecret(AliceKeyPair.PublicKey, BobKeyPair.PrivateKey);
            PublicKeyBoxDetachedBox MyDetachedBox = SodiumPublicKeyBoxPCI.CreateDetached(RandomMessage, Nonce, SharedSecret1);
            Byte[] BobReceivedPlainText = SodiumPublicKeyBoxPCI.OpenDetached(MyDetachedBox.CipherText, MyDetachedBox.MAC, Nonce, SharedSecret2);
            AliceKeyPair.Clear();
            BobKeyPair.Clear();
            //==KeyPair==
            KeyPair AliceNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            KeyPair BobNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            IntPtr AliceSecretKeyIntPtr = AliceNewKeyPair.GetPrivateKey();
            Byte[] AliceSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            IntPtr BobSecretKeyIntPtr = BobNewKeyPair.GetPrivateKey();
            Byte[] BobSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            Marshal.Copy(AliceSecretKeyIntPtr, AliceSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Marshal.Copy(BobSecretKeyIntPtr, BobSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Byte[] SharedSecretAlice = SodiumPublicKeyBoxPCI.CalculateSharedSecret(BobNewKeyPair.GetPublicKey(), AliceSecretKey);
            Byte[] SharedSecretBob = SodiumPublicKeyBoxPCI.CalculateSharedSecret(AliceNewKeyPair.GetPublicKey(), BobSecretKey);
            MyDetachedBox = SodiumPublicKeyBoxPCI.CreateDetached(RandomMessage, Nonce, SharedSecretAlice);
            BobReceivedPlainText = SodiumPublicKeyBoxPCI.OpenDetached(MyDetachedBox.CipherText, MyDetachedBox.MAC, Nonce, SharedSecretBob);
            AliceNewKeyPair.ProtectPrivateKey();
            BobNewKeyPair.ProtectPrivateKey();
            AliceNewKeyPair.Clear();
            BobNewKeyPair.Clear();
        }

        private void GenerateSharedSecretBTN_Click(object sender, EventArgs e)
        {
            //==RevampedKeyPair==
            RevampedKeyPair AliceKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] SharedSecret1 = SodiumPublicKeyBoxPCI.CalculateSharedSecret(BobKeyPair.PublicKey, AliceKeyPair.PrivateKey);
            Byte[] SharedSecret2 = SodiumPublicKeyBoxPCI.CalculateSharedSecret(AliceKeyPair.PublicKey, BobKeyPair.PrivateKey);
            AliceKeyPair.Clear();
            BobKeyPair.Clear();
            //==KeyPair==
            KeyPair AliceNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            KeyPair BobNewKeyPair = SodiumPublicKeyBox.GenerateKeyPair();
            IntPtr AliceSecretKeyIntPtr = AliceNewKeyPair.GetPrivateKey();
            Byte[] AliceSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            IntPtr BobSecretKeyIntPtr = BobNewKeyPair.GetPrivateKey();
            Byte[] BobSecretKey = new Byte[SodiumPublicKeyBox.GetSecretKeyBytesLength()];
            Marshal.Copy(AliceSecretKeyIntPtr, AliceSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Marshal.Copy(BobSecretKeyIntPtr, BobSecretKey, 0, SodiumPublicKeyBox.GetSecretKeyBytesLength());
            Byte[] SharedSecretAlice = SodiumPublicKeyBoxPCI.CalculateSharedSecret(BobNewKeyPair.GetPublicKey(), AliceSecretKey);
            Byte[] SharedSecretBob = SodiumPublicKeyBoxPCI.CalculateSharedSecret(AliceNewKeyPair.GetPublicKey(), BobSecretKey);
            AliceNewKeyPair.ProtectPrivateKey();
            BobNewKeyPair.ProtectPrivateKey();
            AliceNewKeyPair.Clear();
            BobNewKeyPair.Clear();
            //Shared Secret can be return as 2 data type either in Byte[] or in No Access Protected IntPtr
        }
    }
}
