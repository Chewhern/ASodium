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

namespace LibSodiumBinding
{
    public partial class SealedPublicKeyBoxDemo : Form
    {
        public SealedPublicKeyBoxDemo()
        {
            InitializeComponent();
        }

        private void CreateBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] CipherText = SodiumSealedPublicKeyBox.Create(RandomMessage, BobKeyPair.PublicKey);
        }

        private void OpenBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            RevampedKeyPair BobKeyPair = SodiumPublicKeyBox.GenerateRevampedKeyPair();
            Byte[] CipherText = SodiumSealedPublicKeyBox.Create(RandomMessage, BobKeyPair.PublicKey);
            Byte[] PlainText = SodiumSealedPublicKeyBox.Open(CipherText, BobKeyPair.PublicKey, BobKeyPair.PrivateKey);
        }
    }
}
