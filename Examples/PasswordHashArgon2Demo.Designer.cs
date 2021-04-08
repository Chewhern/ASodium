namespace LibSodiumBinding
{
    partial class PasswordHashArgon2Demo
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.PBKDFBTN = new System.Windows.Forms.Button();
            this.CustomPBKDFBTN = new System.Windows.Forms.Button();
            this.PasswordHashBTN = new System.Windows.Forms.Button();
            this.CustomPasswordHashBTN = new System.Windows.Forms.Button();
            this.PasswordNeedsRehashBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // PBKDFBTN
            // 
            this.PBKDFBTN.Location = new System.Drawing.Point(13, 13);
            this.PBKDFBTN.Name = "PBKDFBTN";
            this.PBKDFBTN.Size = new System.Drawing.Size(176, 67);
            this.PBKDFBTN.TabIndex = 0;
            this.PBKDFBTN.Text = "PBKDF";
            this.PBKDFBTN.UseVisualStyleBackColor = true;
            this.PBKDFBTN.Click += new System.EventHandler(this.PBKDFBTN_Click);
            // 
            // CustomPBKDFBTN
            // 
            this.CustomPBKDFBTN.Location = new System.Drawing.Point(13, 107);
            this.CustomPBKDFBTN.Name = "CustomPBKDFBTN";
            this.CustomPBKDFBTN.Size = new System.Drawing.Size(176, 67);
            this.CustomPBKDFBTN.TabIndex = 1;
            this.CustomPBKDFBTN.Text = "Custom PBKDF";
            this.CustomPBKDFBTN.UseVisualStyleBackColor = true;
            this.CustomPBKDFBTN.Click += new System.EventHandler(this.CustomPBKDFBTN_Click);
            // 
            // PasswordHashBTN
            // 
            this.PasswordHashBTN.Location = new System.Drawing.Point(228, 13);
            this.PasswordHashBTN.Name = "PasswordHashBTN";
            this.PasswordHashBTN.Size = new System.Drawing.Size(176, 67);
            this.PasswordHashBTN.TabIndex = 2;
            this.PasswordHashBTN.Text = "Hash Passwords";
            this.PasswordHashBTN.UseVisualStyleBackColor = true;
            this.PasswordHashBTN.Click += new System.EventHandler(this.PasswordHashBTN_Click);
            // 
            // CustomPasswordHashBTN
            // 
            this.CustomPasswordHashBTN.Location = new System.Drawing.Point(228, 107);
            this.CustomPasswordHashBTN.Name = "CustomPasswordHashBTN";
            this.CustomPasswordHashBTN.Size = new System.Drawing.Size(176, 67);
            this.CustomPasswordHashBTN.TabIndex = 3;
            this.CustomPasswordHashBTN.Text = "Custom Hash PW";
            this.CustomPasswordHashBTN.UseVisualStyleBackColor = true;
            this.CustomPasswordHashBTN.Click += new System.EventHandler(this.CustomPasswordHashBTN_Click);
            // 
            // PasswordNeedsRehashBTN
            // 
            this.PasswordNeedsRehashBTN.Location = new System.Drawing.Point(441, 13);
            this.PasswordNeedsRehashBTN.Name = "PasswordNeedsRehashBTN";
            this.PasswordNeedsRehashBTN.Size = new System.Drawing.Size(176, 67);
            this.PasswordNeedsRehashBTN.TabIndex = 4;
            this.PasswordNeedsRehashBTN.Text = "PW Needs Rehash?";
            this.PasswordNeedsRehashBTN.UseVisualStyleBackColor = true;
            this.PasswordNeedsRehashBTN.Click += new System.EventHandler(this.PasswordNeedsRehashBTN_Click);
            // 
            // PasswordHashArgon2Demo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.PasswordNeedsRehashBTN);
            this.Controls.Add(this.CustomPasswordHashBTN);
            this.Controls.Add(this.PasswordHashBTN);
            this.Controls.Add(this.CustomPBKDFBTN);
            this.Controls.Add(this.PBKDFBTN);
            this.Name = "PasswordHashArgon2Demo";
            this.Text = "PasswordHashArgon2Demo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button PBKDFBTN;
        private System.Windows.Forms.Button CustomPBKDFBTN;
        private System.Windows.Forms.Button PasswordHashBTN;
        private System.Windows.Forms.Button CustomPasswordHashBTN;
        private System.Windows.Forms.Button PasswordNeedsRehashBTN;
    }
}