using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using ASodium;
using System.Runtime.InteropServices;

namespace LibSodiumBinding
{
    public partial class PublicKeyAuthDemo : Form
    {
        public PublicKeyAuthDemo()
        {
            InitializeComponent();
        }

        private void SignOpenBTN_Click(object sender, EventArgs e)
        {
            //Revamped KeyPair
            RevampedKeyPair MyKeyPair = SodiumPublicKeyAuth.GenerateRevampedKeyPair();
            Byte[] Message = SodiumRNG.GetRandomBytes(128);
            Byte[] SignatureMessage = SodiumPublicKeyAuth.Sign(Message, MyKeyPair.PrivateKey);
            Byte[] VerifiedMessage = SodiumPublicKeyAuth.Verify(SignatureMessage, MyKeyPair.PublicKey);
            KeyPair MyNewKeyPair = SodiumPublicKeyAuth.GenerateKeyPair();
            IntPtr SecretKeyIntPtr = MyNewKeyPair.GetPrivateKey();
            Byte[] SecretKey = new Byte[SodiumPublicKeyAuth.GetSecretKeyBytesLength()];
            Marshal.Copy(SecretKeyIntPtr, SecretKey, 0, SodiumPublicKeyAuth.GetSecretKeyBytesLength());
            MyNewKeyPair.ProtectPrivateKey();
            SignatureMessage = SodiumPublicKeyAuth.Sign(Message, SecretKey);
            VerifiedMessage = SodiumPublicKeyAuth.Verify(SignatureMessage, MyNewKeyPair.GetPublicKey());
        }

        private void SignVerifyDetachedBTN_Click(object sender, EventArgs e)
        {
            //Revamped KeyPair
            RevampedKeyPair MyKeyPair = SodiumPublicKeyAuth.GenerateRevampedKeyPair();
            Byte[] Message = SodiumRNG.GetRandomBytes(128);
            Byte[] Signature = SodiumPublicKeyAuth.SignDetached(Message, MyKeyPair.PrivateKey);
            Boolean Verified = SodiumPublicKeyAuth.VerifyDetached(Signature,Message , MyKeyPair.PublicKey);
            if (Verified) 
            {
                MessageBox.Show("Signature and Message Matched");
            }
            KeyPair MyNewKeyPair = SodiumPublicKeyAuth.GenerateKeyPair();
            IntPtr SecretKeyIntPtr = MyNewKeyPair.GetPrivateKey();
            Byte[] SecretKey = new Byte[SodiumPublicKeyAuth.GetSecretKeyBytesLength()];
            Marshal.Copy(SecretKeyIntPtr, SecretKey, 0, SodiumPublicKeyAuth.GetSecretKeyBytesLength());
            MyNewKeyPair.ProtectPrivateKey();
            Signature = SodiumPublicKeyAuth.SignDetached(Message, SecretKey);
            Verified = SodiumPublicKeyAuth.VerifyDetached(Signature, Message, MyNewKeyPair.GetPublicKey());
            if (Verified)
            {
                MessageBox.Show("Signature and Message Matched");
            }
        }

        private void SignVerifyMPMBTN_Click(object sender, EventArgs e)
        {
            Byte[] Message1 = SodiumRNG.GetRandomBytes(128);
            Byte[] Message2 = SodiumRNG.GetRandomBytes(128);
            Byte[] Message3 = SodiumRNG.GetRandomBytes(128);
            Byte[] StateByte = SodiumPublicKeyAuthMPM.InitializeState();
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message1);
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message2);
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message3);
            //Revamped KeyPair
            RevampedKeyPair MyKeyPair = SodiumPublicKeyAuth.GenerateRevampedKeyPair();
            Byte[] Signature = SodiumPublicKeyAuthMPM.SignFinalState(StateByte, MyKeyPair.PrivateKey);
            StateByte = SodiumPublicKeyAuthMPM.InitializeState();
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message1);
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message2);
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message3);
            Boolean Verified = SodiumPublicKeyAuthMPM.VerifySignedFinalState(StateByte, Signature, MyKeyPair.PublicKey);
            KeyPair MyNewKeyPair = SodiumPublicKeyAuth.GenerateKeyPair();
            IntPtr SecretKeyIntPtr = MyNewKeyPair.GetPrivateKey();
            Byte[] SecretKey = new Byte[SodiumPublicKeyAuth.GetSecretKeyBytesLength()];
            Marshal.Copy(SecretKeyIntPtr, SecretKey, 0, SodiumPublicKeyAuth.GetSecretKeyBytesLength());
            MyNewKeyPair.ProtectPrivateKey();
            StateByte = SodiumPublicKeyAuthMPM.InitializeState();
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message1);
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message2);
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message3);
            Signature = SodiumPublicKeyAuthMPM.SignFinalState(StateByte, SecretKey);
            StateByte = SodiumPublicKeyAuthMPM.InitializeState();
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message1);
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message2);
            StateByte = SodiumPublicKeyAuthMPM.UpdateState(StateByte, Message3);
            Verified = SodiumPublicKeyAuthMPM.VerifySignedFinalState(StateByte, Signature, MyNewKeyPair.GetPublicKey());
        }

        private void GetSeedsFromSKBTN_Click(object sender, EventArgs e)
        {
            RevampedKeyPair MyKeyPair = SodiumPublicKeyAuth.GenerateRevampedKeyPair();
            Byte[] Seed = SodiumPublicKeyAuth.ExtractSeed(MyKeyPair.PrivateKey);
        }

        private void GetPKFromSKBTN_Click(object sender, EventArgs e)
        {
            RevampedKeyPair MyKeyPair = SodiumPublicKeyAuth.GenerateRevampedKeyPair();
            Byte[] PublicKey = SodiumPublicKeyAuth.GeneratePublicKey(MyKeyPair.PrivateKey);
            //This can be used not only for recovering lost public key
            //It can also be used in creating your own keypair
        }

        private void SealedSignMessageBTN_Click(object sender, EventArgs e)
        {
            Byte[] Message = SodiumRNG.GetRandomBytes(128);
            PublicKeyAuthSealBox MyPublicKeyAuthSealBox = SodiumPublicKeyAuth.SealedSign(Message);
            PublicKeyAuthDetachedSealBox MyPublicKeyAuthDetachedSealBox = SodiumPublicKeyAuth.SealedSignDetached(Message);
            Byte[] VerifiedMessage = SodiumPublicKeyAuth.Verify(MyPublicKeyAuthSealBox.SignatureMessage, MyPublicKeyAuthSealBox.PublicKey);
            Boolean Verified = SodiumPublicKeyAuth.VerifyDetached(MyPublicKeyAuthDetachedSealBox.Signature, Message, MyPublicKeyAuthDetachedSealBox.PublicKey);
        }
    }
}
