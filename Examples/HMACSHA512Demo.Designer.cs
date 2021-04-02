namespace LibSodiumBinding
{
    partial class HMACSHA512Demo
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
            this.ComputeVerifyHMACBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // ComputeVerifyHMACBTN
            // 
            this.ComputeVerifyHMACBTN.Location = new System.Drawing.Point(12, 12);
            this.ComputeVerifyHMACBTN.Name = "ComputeVerifyHMACBTN";
            this.ComputeVerifyHMACBTN.Size = new System.Drawing.Size(222, 66);
            this.ComputeVerifyHMACBTN.TabIndex = 1;
            this.ComputeVerifyHMACBTN.Text = "Compute/Verify HMAC";
            this.ComputeVerifyHMACBTN.UseVisualStyleBackColor = true;
            this.ComputeVerifyHMACBTN.Click += new System.EventHandler(this.ComputeVerifyHMACBTN_Click);
            // 
            // HMACSHA512Demo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.ComputeVerifyHMACBTN);
            this.Name = "HMACSHA512Demo";
            this.Text = "HMACSHA512Demo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button ComputeVerifyHMACBTN;
    }
}