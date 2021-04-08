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
    public partial class KeyExchangeDemo : Form
    {
        public KeyExchangeDemo()
        {
            InitializeComponent();
        }

        private void CalculateSharedSecretBTN_Click(object sender, EventArgs e)
        {
            RevampedKeyPair ClientKeyPair = SodiumKeyExchange.GenerateRevampedKeyPair();
            RevampedKeyPair ServerKeyPair = SodiumKeyExchange.GenerateRevampedKeyPair();
            SodiumKeyExchangeSharedSecretBox ClientSharedSecretBox = SodiumKeyExchange.CalculateClientSharedSecret(ClientKeyPair.PublicKey, ClientKeyPair.PrivateKey, ServerKeyPair.PublicKey);
            SodiumKeyExchangeSharedSecretBox ServerSharedSecretBox = SodiumKeyExchange.CalculateServerSharedSecret(ServerKeyPair.PublicKey, ServerKeyPair.PrivateKey, ClientKeyPair.PublicKey);
        }
    }
}
