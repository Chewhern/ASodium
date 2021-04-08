namespace LibSodiumBinding
{
    partial class ChaCha20Poly1305IETFDemo
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
            this.OpenDetachedBoxBTN = new System.Windows.Forms.Button();
            this.CreateDetachedBoxBTN = new System.Windows.Forms.Button();
            this.DecryptBTN = new System.Windows.Forms.Button();
            this.EncryptBTN = new System.Windows.Forms.Button();
            this.NoncePublicGenBTN = new System.Windows.Forms.Button();
            this.KeyGenBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // OpenDetachedBoxBTN
            // 
            this.OpenDetachedBoxBTN.Location = new System.Drawing.Point(444, 105);
            this.OpenDetachedBoxBTN.Name = "OpenDetachedBoxBTN";
            this.OpenDetachedBoxBTN.Size = new System.Drawing.Size(191, 64);
            this.OpenDetachedBoxBTN.TabIndex = 11;
            this.OpenDetachedBoxBTN.Text = "Open Detached Box";
            this.OpenDetachedBoxBTN.UseVisualStyleBackColor = true;
            this.OpenDetachedBoxBTN.Click += new System.EventHandler(this.OpenDetachedBoxBTN_Click);
            // 
            // CreateDetachedBoxBTN
            // 
            this.CreateDetachedBoxBTN.Location = new System.Drawing.Point(444, 12);
            this.CreateDetachedBoxBTN.Name = "CreateDetachedBoxBTN";
            this.CreateDetachedBoxBTN.Size = new System.Drawing.Size(191, 64);
            this.CreateDetachedBoxBTN.TabIndex = 10;
            this.CreateDetachedBoxBTN.Text = "Create Detached Box";
            this.CreateDetachedBoxBTN.UseVisualStyleBackColor = true;
            this.CreateDetachedBoxBTN.Click += new System.EventHandler(this.CreateDetachedBoxBTN_Click);
            // 
            // DecryptBTN
            // 
            this.DecryptBTN.Location = new System.Drawing.Point(230, 105);
            this.DecryptBTN.Name = "DecryptBTN";
            this.DecryptBTN.Size = new System.Drawing.Size(191, 64);
            this.DecryptBTN.TabIndex = 9;
            this.DecryptBTN.Text = "Decrypt";
            this.DecryptBTN.UseVisualStyleBackColor = true;
            this.DecryptBTN.Click += new System.EventHandler(this.DecryptBTN_Click);
            // 
            // EncryptBTN
            // 
            this.EncryptBTN.Location = new System.Drawing.Point(230, 12);
            this.EncryptBTN.Name = "EncryptBTN";
            this.EncryptBTN.Size = new System.Drawing.Size(191, 64);
            this.EncryptBTN.TabIndex = 8;
            this.EncryptBTN.Text = "Encrypt";
            this.EncryptBTN.UseVisualStyleBackColor = true;
            this.EncryptBTN.Click += new System.EventHandler(this.EncryptBTN_Click);
            // 
            // NoncePublicGenBTN
            // 
            this.NoncePublicGenBTN.Location = new System.Drawing.Point(12, 105);
            this.NoncePublicGenBTN.Name = "NoncePublicGenBTN";
            this.NoncePublicGenBTN.Size = new System.Drawing.Size(191, 64);
            this.NoncePublicGenBTN.TabIndex = 7;
            this.NoncePublicGenBTN.Text = "Generate Pub Nonce";
            this.NoncePublicGenBTN.UseVisualStyleBackColor = true;
            this.NoncePublicGenBTN.Click += new System.EventHandler(this.NoncePublicGenBTN_Click);
            // 
            // KeyGenBTN
            // 
            this.KeyGenBTN.Location = new System.Drawing.Point(12, 12);
            this.KeyGenBTN.Name = "KeyGenBTN";
            this.KeyGenBTN.Size = new System.Drawing.Size(191, 64);
            this.KeyGenBTN.TabIndex = 6;
            this.KeyGenBTN.Text = "Generate Key";
            this.KeyGenBTN.UseVisualStyleBackColor = true;
            this.KeyGenBTN.Click += new System.EventHandler(this.KeyGenBTN_Click);
            // 
            // ChaCha20Poly1305IETFDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.OpenDetachedBoxBTN);
            this.Controls.Add(this.CreateDetachedBoxBTN);
            this.Controls.Add(this.DecryptBTN);
            this.Controls.Add(this.EncryptBTN);
            this.Controls.Add(this.NoncePublicGenBTN);
            this.Controls.Add(this.KeyGenBTN);
            this.Name = "ChaCha20Poly1305IETFDemo";
            this.Text = "ChaCha20Poly1305IETFDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button OpenDetachedBoxBTN;
        private System.Windows.Forms.Button CreateDetachedBoxBTN;
        private System.Windows.Forms.Button DecryptBTN;
        private System.Windows.Forms.Button EncryptBTN;
        private System.Windows.Forms.Button NoncePublicGenBTN;
        private System.Windows.Forms.Button KeyGenBTN;
    }
}