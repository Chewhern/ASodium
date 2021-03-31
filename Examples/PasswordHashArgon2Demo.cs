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
    public partial class PasswordHashArgon2Demo : Form
    {
        public PasswordHashArgon2Demo()
        {
            InitializeComponent();
        }

        private void PBKDFBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPasswords = SodiumRNG.GetRandomBytes(128);
            Byte[] Salt = SodiumPasswordHashArgon2.GenerateSalt();
            Byte[] DerivedKey = SodiumPasswordHashArgon2.Argon2PBKDF(32, RandomPasswords, Salt,SodiumPasswordHashArgon2.Strength.SENSITIVE);
            MessageBox.Show(new System.Numerics.BigInteger(DerivedKey).ToString());
        }

        private void CustomPBKDFBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPasswords = SodiumRNG.GetRandomBytes(128);
            Byte[] Salt = SodiumPasswordHashArgon2.GenerateSalt();
            Byte[] DerivedKey = SodiumPasswordHashArgon2.Argon2PBKDFCustom(32, RandomPasswords, Salt, 5, 1610612736);
            MessageBox.Show(new System.Numerics.BigInteger(DerivedKey).ToString());
            //refer to libsodium documentation to decide your own parameters for opslimit and memlimit
        }

        private void PasswordHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPasswords = SodiumRNG.GetRandomBytes(128);
            Byte[] Salt = SodiumPasswordHashArgon2.GenerateSalt();
            String HashedPasswordWithParam = SodiumPasswordHashArgon2.Argon2HashPassword(RandomPasswords);
            MessageBox.Show(HashedPasswordWithParam);
        }

        private void CustomPasswordHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPasswords = SodiumRNG.GetRandomBytes(128);
            Byte[] Salt = SodiumPasswordHashArgon2.GenerateSalt();
            String HashedPasswordWithParam = SodiumPasswordHashArgon2.Argon2CustomParamHashPassword(RandomPasswords,5, 1610612736);
            MessageBox.Show(HashedPasswordWithParam);
        }

        private void PasswordNeedsRehashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPasswords = SodiumRNG.GetRandomBytes(128);
            Byte[] Salt = SodiumPasswordHashArgon2.GenerateSalt();
            String HashedPasswordWithParam = SodiumPasswordHashArgon2.Argon2HashPassword(RandomPasswords);
            int Status = SodiumPasswordHashArgon2.PasswordNeedsRehash(HashedPasswordWithParam, SodiumPasswordHashArgon2.Strength.MODERATE);
            MessageBox.Show(Status.ToString());
            //Refer to libsodium for documentation
        }
    }
}
