namespace LibSodiumBinding
{
    partial class SecretKeyAuthDemo
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
            this.KeyGenBTN = new System.Windows.Forms.Button();
            this.SignVerifyBTN = new System.Windows.Forms.Button();
            this.GetKeyLengthBTN = new System.Windows.Forms.Button();
            this.GetMACLengthBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // KeyGenBTN
            // 
            this.KeyGenBTN.Location = new System.Drawing.Point(13, 13);
            this.KeyGenBTN.Name = "KeyGenBTN";
            this.KeyGenBTN.Size = new System.Drawing.Size(190, 59);
            this.KeyGenBTN.TabIndex = 0;
            this.KeyGenBTN.Text = "Generate Key";
            this.KeyGenBTN.UseVisualStyleBackColor = true;
            this.KeyGenBTN.Click += new System.EventHandler(this.KeyGenBTN_Click);
            // 
            // SignVerifyBTN
            // 
            this.SignVerifyBTN.Location = new System.Drawing.Point(13, 93);
            this.SignVerifyBTN.Name = "SignVerifyBTN";
            this.SignVerifyBTN.Size = new System.Drawing.Size(190, 59);
            this.SignVerifyBTN.TabIndex = 1;
            this.SignVerifyBTN.Text = "Sign/Verify Message";
            this.SignVerifyBTN.UseVisualStyleBackColor = true;
            this.SignVerifyBTN.Click += new System.EventHandler(this.SignVerifyBTN_Click);
            // 
            // GetKeyLengthBTN
            // 
            this.GetKeyLengthBTN.Location = new System.Drawing.Point(226, 13);
            this.GetKeyLengthBTN.Name = "GetKeyLengthBTN";
            this.GetKeyLengthBTN.Size = new System.Drawing.Size(190, 59);
            this.GetKeyLengthBTN.TabIndex = 2;
            this.GetKeyLengthBTN.Text = "Get Key Length";
            this.GetKeyLengthBTN.UseVisualStyleBackColor = true;
            this.GetKeyLengthBTN.Click += new System.EventHandler(this.GetKeyLengthBTN_Click);
            // 
            // GetMACLengthBTN
            // 
            this.GetMACLengthBTN.Location = new System.Drawing.Point(226, 93);
            this.GetMACLengthBTN.Name = "GetMACLengthBTN";
            this.GetMACLengthBTN.Size = new System.Drawing.Size(190, 59);
            this.GetMACLengthBTN.TabIndex = 3;
            this.GetMACLengthBTN.Text = "Get MAC Length";
            this.GetMACLengthBTN.UseVisualStyleBackColor = true;
            this.GetMACLengthBTN.Click += new System.EventHandler(this.GetMACLengthBTN_Click);
            // 
            // SecretKeyAuthDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.GetMACLengthBTN);
            this.Controls.Add(this.GetKeyLengthBTN);
            this.Controls.Add(this.SignVerifyBTN);
            this.Controls.Add(this.KeyGenBTN);
            this.Name = "SecretKeyAuthDemo";
            this.Text = "SecretKeyAuthDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button KeyGenBTN;
        private System.Windows.Forms.Button SignVerifyBTN;
        private System.Windows.Forms.Button GetKeyLengthBTN;
        private System.Windows.Forms.Button GetMACLengthBTN;
    }
}