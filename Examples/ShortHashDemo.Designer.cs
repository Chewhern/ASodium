namespace LibSodiumBinding
{
    partial class ShortHashDemo
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
            this.ComputeHashBTN = new System.Windows.Forms.Button();
            this.ComputeHashVariantBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // ComputeHashBTN
            // 
            this.ComputeHashBTN.Location = new System.Drawing.Point(12, 12);
            this.ComputeHashBTN.Name = "ComputeHashBTN";
            this.ComputeHashBTN.Size = new System.Drawing.Size(222, 78);
            this.ComputeHashBTN.TabIndex = 0;
            this.ComputeHashBTN.Text = "Compute Hash";
            this.ComputeHashBTN.UseVisualStyleBackColor = true;
            this.ComputeHashBTN.Click += new System.EventHandler(this.ComputeHashBTN_Click);
            // 
            // ComputeHashVariantBTN
            // 
            this.ComputeHashVariantBTN.Location = new System.Drawing.Point(12, 121);
            this.ComputeHashVariantBTN.Name = "ComputeHashVariantBTN";
            this.ComputeHashVariantBTN.Size = new System.Drawing.Size(222, 78);
            this.ComputeHashVariantBTN.TabIndex = 1;
            this.ComputeHashVariantBTN.Text = "Compute hash for variant";
            this.ComputeHashVariantBTN.UseVisualStyleBackColor = true;
            this.ComputeHashVariantBTN.Click += new System.EventHandler(this.ComputeHashVariantBTN_Click);
            // 
            // ShortHashDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.ComputeHashVariantBTN);
            this.Controls.Add(this.ComputeHashBTN);
            this.Name = "ShortHashDemo";
            this.Text = "ShortHashDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button ComputeHashBTN;
        private System.Windows.Forms.Button ComputeHashVariantBTN;
    }
}