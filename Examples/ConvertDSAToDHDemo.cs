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
    public partial class ConvertDSAToDHDemo : Form
    {
        public ConvertDSAToDHDemo()
        {
            InitializeComponent();
        }

        private void ConvertDSASKToDHSKBTN_Click(object sender, EventArgs e)
        {
            RevampedKeyPair MyKeyPair = SodiumPublicKeyAuth.GenerateRevampedKeyPair();
            Byte[] X25519SK = SodiumConvertDSAToDH.ConvertDSASKToDHSK(MyKeyPair.PrivateKey);
        }

        private void ConvertDSAPKToDHPKBTN_Click(object sender, EventArgs e)
        {
            RevampedKeyPair MyKeyPair = SodiumPublicKeyAuth.GenerateRevampedKeyPair();
            Byte[] X25519PK = SodiumConvertDSAToDH.ConvertDSAPKToDHPK(MyKeyPair.PublicKey);
        }
    }
}
