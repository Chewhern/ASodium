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

namespace LibSodiumBinding
{
    public partial class SecretKeyAuthDemo : Form
    {
        public SecretKeyAuthDemo()
        {
            InitializeComponent();
        }

        private void KeyGenBTN_Click(object sender, EventArgs e)
        {
            Byte[] SecretKeyAuthKey = Sodium.SodiumSecretKeyAuth.GenKey();
            MessageBox.Show(new System.Numerics.BigInteger(SecretKeyAuthKey).ToString());
        }

        private void SignVerifyBTN_Click(object sender, EventArgs e)
        {
            Byte[] SecretKeyAuthKey = Sodium.SodiumSecretKeyAuth.GenKey();
            Byte[] RandomMessage = new Byte[128];
            Byte[] MessageMAC = new Byte[] { };
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomMessage);
            MessageMAC = Sodium.SodiumSecretKeyAuth.Sign(RandomMessage, SecretKeyAuthKey);
            try 
            {
                Sodium.SodiumSecretKeyAuth.Verify(RandomMessage, MessageMAC, SecretKeyAuthKey);
            }
            catch 
            {
                MessageBox.Show("MAC does not match with original message");
            }
            //There're 2 versions of verify methods, the 2nd method will be returning boolean...
        }

        private void GetKeyLengthBTN_Click(object sender, EventArgs e)
        {
            int KeyLength = Sodium.SodiumSecretKeyAuth.GetKeyLength();
            MessageBox.Show(KeyLength.ToString());
        }

        private void GetMACLengthBTN_Click(object sender, EventArgs e)
        {
            int MACLength = Sodium.SodiumSecretKeyAuth.GetMACLength();
            MessageBox.Show(MACLength.ToString());
        }
    }
}
