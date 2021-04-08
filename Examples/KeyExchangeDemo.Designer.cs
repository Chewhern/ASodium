namespace LibSodiumBinding
{
    partial class KeyExchangeDemo
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
            this.CalculateSharedSecretBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // CalculateSharedSecretBTN
            // 
            this.CalculateSharedSecretBTN.Location = new System.Drawing.Point(13, 13);
            this.CalculateSharedSecretBTN.Name = "CalculateSharedSecretBTN";
            this.CalculateSharedSecretBTN.Size = new System.Drawing.Size(297, 85);
            this.CalculateSharedSecretBTN.TabIndex = 0;
            this.CalculateSharedSecretBTN.Text = "Calculate Shared Secret";
            this.CalculateSharedSecretBTN.UseVisualStyleBackColor = true;
            this.CalculateSharedSecretBTN.Click += new System.EventHandler(this.CalculateSharedSecretBTN_Click);
            // 
            // KeyExchangeDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.CalculateSharedSecretBTN);
            this.Name = "KeyExchangeDemo";
            this.Text = "KeyExchangeDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button CalculateSharedSecretBTN;
    }
}