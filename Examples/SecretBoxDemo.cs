using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using ASodium;

namespace LibSodiumBinding
{
    public partial class SecretBoxDemo : Form
    {
        public SecretBoxDemo()
        {
            InitializeComponent();
        }

        private void KeyGenBTN_Click(object sender, EventArgs e)
        {
            Byte[] SecretBoxKey = SodiumSecretBox.GenerateKey();
            MessageBox.Show(new System.Numerics.BigInteger(SecretBoxKey).ToString());
        }

        private void NonceGenBTN_Click(object sender, EventArgs e)
        {
            Byte[] Nonce = SodiumSecretBox.GenerateNonce();
            MessageBox.Show(new System.Numerics.BigInteger(Nonce).ToString());
        }

        private void SeededKeyGenBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            Byte[] SeededSecretBoxKey = SodiumSecretBox.GenerateSeededKey(RandomByte);
            MessageBox.Show(new System.Numerics.BigInteger(SeededSecretBoxKey).ToString());
        }

        private void SeededNonceBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            Byte[] Nonce = SodiumSecretBox.GenerateSeededNonce(RandomByte);
            MessageBox.Show(new System.Numerics.BigInteger(Nonce).ToString());
        }

        private void SecretBoxCreateOpenBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] CipherText = new Byte[] { };
            Byte[] OriginalText = new Byte[] { };
            Byte[] StreamCipherKey = new Byte[] { };
            Byte[] Nonce = new Byte[] { };
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            StreamCipherKey = SodiumSecretBox.GenerateKey();
            Nonce = SodiumSecretBox.GenerateNonce();
            CipherText = SodiumSecretBox.Create(RandomByte, Nonce, StreamCipherKey);
            OriginalText = SodiumSecretBox.Open(CipherText, Nonce, StreamCipherKey);
            MessageBox.Show(OriginalText.SequenceEqual(RandomByte).ToString());
        }

        private void DetachedBoxCreateOpenBTN_Click(object sender, EventArgs e)
        {
            DetachedBox MyDetachedBox = new DetachedBox();
            Byte[] RandomByte = new Byte[32];
            Byte[] CipherText = new Byte[] { };
            Byte[] OriginalText = new Byte[] { };
            Byte[] OriginalText2 = new Byte[] { };
            Byte[] StreamCipherKey = new Byte[] { };
            Byte[] Nonce = new Byte[] { };
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            StreamCipherKey = SodiumSecretBox.GenerateKey();
            Nonce = SodiumSecretBox.GenerateNonce();
            MyDetachedBox = SodiumSecretBox.CreateDetached(RandomByte, Nonce, StreamCipherKey);
            OriginalText=SodiumSecretBox.OpenDetached(MyDetachedBox,Nonce,StreamCipherKey);
            OriginalText2 = SodiumSecretBox.OpenDetached(MyDetachedBox.CipherText, MyDetachedBox.Mac, Nonce, StreamCipherKey);
            MessageBox.Show(RandomByte.SequenceEqual(OriginalText).ToString());
            MessageBox.Show(RandomByte.SequenceEqual(OriginalText2).ToString());
        }
    }
}
