using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Sodium;

namespace LibSodiumBinding
{
    public partial class XChaCha20Poly1305IETFDemo : Form
    {
        public XChaCha20Poly1305IETFDemo()
        {
            InitializeComponent();
        }

        private void KeyGenBTN_Click(object sender, EventArgs e)
        {
            Byte[] Key = SodiumSecretAeadXChaCha20Poly1305IETF.GenerateKey();
        }

        private void NoncePublicGenBTN_Click(object sender, EventArgs e)
        {
            Byte[] NoncePublic = SodiumSecretAeadXChaCha20Poly1305IETF.GeneratePublicNonce();
        }

        private void EncryptBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomData = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumSecretAeadXChaCha20Poly1305IETF.GenerateKey();
            Byte[] NoncePublic = SodiumSecretAeadXChaCha20Poly1305IETF.GeneratePublicNonce();
            Byte[] EncryptedData = SodiumSecretAeadXChaCha20Poly1305IETF.Encrypt(RandomData, NoncePublic, Key);
        }

        private void DecryptBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomData = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumSecretAeadXChaCha20Poly1305IETF.GenerateKey();
            Byte[] NoncePublic = SodiumSecretAeadXChaCha20Poly1305IETF.GeneratePublicNonce();
            Byte[] EncryptedData = SodiumSecretAeadXChaCha20Poly1305IETF.Encrypt(RandomData, NoncePublic, Key);
            Byte[] DecryptedData = SodiumSecretAeadXChaCha20Poly1305IETF.Decrypt(EncryptedData, NoncePublic, Key);
        }

        private void CreateDetachedBoxBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomData = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumSecretAeadXChaCha20Poly1305IETF.GenerateKey();
            Byte[] NoncePublic = SodiumSecretAeadXChaCha20Poly1305IETF.GeneratePublicNonce();
            ChaCha20Poly1305DetachedBox MyDetachedBox = SodiumSecretAeadXChaCha20Poly1305IETF.CreateDetachedBox(RandomData, NoncePublic, Key);
        }

        private void OpenDetachedBoxBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomData = SodiumRNG.GetRandomBytes(128);
            Byte[] Key = SodiumSecretAeadXChaCha20Poly1305IETF.GenerateKey();
            Byte[] NoncePublic = SodiumSecretAeadXChaCha20Poly1305IETF.GeneratePublicNonce();
            Byte[] DecryptedText1 = new Byte[] { };
            Byte[] DecryptedText2 = new Byte[] { };
            ChaCha20Poly1305DetachedBox MyDetachedBox = SodiumSecretAeadXChaCha20Poly1305IETF.CreateDetachedBox(RandomData, NoncePublic, Key);
            DecryptedText1 = SodiumSecretAeadXChaCha20Poly1305IETF.OpenDetachedBox(MyDetachedBox, NoncePublic, Key);
            DecryptedText2 = SodiumSecretAeadXChaCha20Poly1305IETF.OpenDetachedBox(MyDetachedBox.CipherText, MyDetachedBox.MAC, NoncePublic, Key);
        }
    }
}
