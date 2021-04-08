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
    public partial class SHA256Demo : Form
    {
        public SHA256Demo()
        {
            InitializeComponent();
        }

        private void ComputeHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] ComputedHash = SodiumHashSHA256.ComputeHash(RandomMessage);
        }

        private void ComputeMPMBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomMessage1 = SodiumRNG.GetRandomBytes(128);
            Byte[] RandomMessage2 = SodiumRNG.GetRandomBytes(128);
            Byte[] RandomMessage3 = SodiumRNG.GetRandomBytes(128);
            Byte[] State = SodiumHashSHA256.InitializeState();
            State = SodiumHashSHA256.UpdateState(State, RandomMessage1);
            State = SodiumHashSHA256.UpdateState(State, RandomMessage2);
            State = SodiumHashSHA256.UpdateState(State, RandomMessage3);
            Byte[] ComputedHash = SodiumHashSHA256.ComputeHashForFinalizedState(State);
        }
    }
}
