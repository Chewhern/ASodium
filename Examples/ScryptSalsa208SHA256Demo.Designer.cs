namespace LibSodiumBinding
{
    partial class ScryptSalsa208SHA256Demo
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
            this.PBKDF2BTN = new System.Windows.Forms.Button();
            this.PasswordHashBTN = new System.Windows.Forms.Button();
            this.CustomPBKDF2BTN = new System.Windows.Forms.Button();
            this.CustomPasswordHashBTN = new System.Windows.Forms.Button();
            this.PasswordHashWithParamsNeedsReHashBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // PBKDF2BTN
            // 
            this.PBKDF2BTN.Location = new System.Drawing.Point(13, 13);
            this.PBKDF2BTN.Name = "PBKDF2BTN";
            this.PBKDF2BTN.Size = new System.Drawing.Size(223, 77);
            this.PBKDF2BTN.TabIndex = 0;
            this.PBKDF2BTN.Text = "PBKDF2";
            this.PBKDF2BTN.UseVisualStyleBackColor = true;
            this.PBKDF2BTN.Click += new System.EventHandler(this.PBKDF2BTN_Click);
            // 
            // PasswordHashBTN
            // 
            this.PasswordHashBTN.Location = new System.Drawing.Point(13, 118);
            this.PasswordHashBTN.Name = "PasswordHashBTN";
            this.PasswordHashBTN.Size = new System.Drawing.Size(223, 77);
            this.PasswordHashBTN.TabIndex = 1;
            this.PasswordHashBTN.Text = "Password Hash";
            this.PasswordHashBTN.UseVisualStyleBackColor = true;
            this.PasswordHashBTN.Click += new System.EventHandler(this.PasswordHashBTN_Click);
            // 
            // CustomPBKDF2BTN
            // 
            this.CustomPBKDF2BTN.Location = new System.Drawing.Point(274, 13);
            this.CustomPBKDF2BTN.Name = "CustomPBKDF2BTN";
            this.CustomPBKDF2BTN.Size = new System.Drawing.Size(223, 77);
            this.CustomPBKDF2BTN.TabIndex = 2;
            this.CustomPBKDF2BTN.Text = "Custom PBKDF2";
            this.CustomPBKDF2BTN.UseVisualStyleBackColor = true;
            this.CustomPBKDF2BTN.Click += new System.EventHandler(this.CustomPBKDF2BTN_Click);
            // 
            // CustomPasswordHashBTN
            // 
            this.CustomPasswordHashBTN.Location = new System.Drawing.Point(274, 118);
            this.CustomPasswordHashBTN.Name = "CustomPasswordHashBTN";
            this.CustomPasswordHashBTN.Size = new System.Drawing.Size(223, 77);
            this.CustomPasswordHashBTN.TabIndex = 3;
            this.CustomPasswordHashBTN.Text = "Custom Password Hash";
            this.CustomPasswordHashBTN.UseVisualStyleBackColor = true;
            this.CustomPasswordHashBTN.Click += new System.EventHandler(this.CustomPasswordHashBTN_Click);
            // 
            // PasswordHashWithParamsNeedsReHashBTN
            // 
            this.PasswordHashWithParamsNeedsReHashBTN.Location = new System.Drawing.Point(542, 13);
            this.PasswordHashWithParamsNeedsReHashBTN.Name = "PasswordHashWithParamsNeedsReHashBTN";
            this.PasswordHashWithParamsNeedsReHashBTN.Size = new System.Drawing.Size(246, 77);
            this.PasswordHashWithParamsNeedsReHashBTN.TabIndex = 4;
            this.PasswordHashWithParamsNeedsReHashBTN.Text = "Password Hash With Params needs rehash?";
            this.PasswordHashWithParamsNeedsReHashBTN.UseVisualStyleBackColor = true;
            this.PasswordHashWithParamsNeedsReHashBTN.Click += new System.EventHandler(this.PasswordHashWithParamsNeedsReHashBTN_Click);
            // 
            // ScryptSalsa208SHA256Demo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.PasswordHashWithParamsNeedsReHashBTN);
            this.Controls.Add(this.CustomPasswordHashBTN);
            this.Controls.Add(this.CustomPBKDF2BTN);
            this.Controls.Add(this.PasswordHashBTN);
            this.Controls.Add(this.PBKDF2BTN);
            this.Name = "ScryptSalsa208SHA256Demo";
            this.Text = "ScryptSalsa208SHA256Demo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button PBKDF2BTN;
        private System.Windows.Forms.Button PasswordHashBTN;
        private System.Windows.Forms.Button CustomPBKDF2BTN;
        private System.Windows.Forms.Button CustomPasswordHashBTN;
        private System.Windows.Forms.Button PasswordHashWithParamsNeedsReHashBTN;
    }
}