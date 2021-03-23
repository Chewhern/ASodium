namespace LibSodiumBinding
{
    partial class SodiumGuardedHeapAllocationDemo
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
            this.SodiumMallocBTN = new System.Windows.Forms.Button();
            this.SodiumAllocArrayBTN = new System.Windows.Forms.Button();
            this.SodiumFreeBTN = new System.Windows.Forms.Button();
            this.NoAccessBTN = new System.Windows.Forms.Button();
            this.ReadWriteBTN = new System.Windows.Forms.Button();
            this.ReadOnlyBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // SodiumMallocBTN
            // 
            this.SodiumMallocBTN.Location = new System.Drawing.Point(13, 13);
            this.SodiumMallocBTN.Name = "SodiumMallocBTN";
            this.SodiumMallocBTN.Size = new System.Drawing.Size(156, 66);
            this.SodiumMallocBTN.TabIndex = 0;
            this.SodiumMallocBTN.Text = "Sodium Malloc";
            this.SodiumMallocBTN.UseVisualStyleBackColor = true;
            this.SodiumMallocBTN.Click += new System.EventHandler(this.SodiumMallocBTN_Click);
            // 
            // SodiumAllocArrayBTN
            // 
            this.SodiumAllocArrayBTN.Location = new System.Drawing.Point(13, 99);
            this.SodiumAllocArrayBTN.Name = "SodiumAllocArrayBTN";
            this.SodiumAllocArrayBTN.Size = new System.Drawing.Size(156, 66);
            this.SodiumAllocArrayBTN.TabIndex = 1;
            this.SodiumAllocArrayBTN.Text = "Sodium Alloc Array";
            this.SodiumAllocArrayBTN.UseVisualStyleBackColor = true;
            this.SodiumAllocArrayBTN.Click += new System.EventHandler(this.SodiumAllocArrayBTN_Click);
            // 
            // SodiumFreeBTN
            // 
            this.SodiumFreeBTN.Location = new System.Drawing.Point(13, 184);
            this.SodiumFreeBTN.Name = "SodiumFreeBTN";
            this.SodiumFreeBTN.Size = new System.Drawing.Size(156, 66);
            this.SodiumFreeBTN.TabIndex = 2;
            this.SodiumFreeBTN.Text = "Sodium Free";
            this.SodiumFreeBTN.UseVisualStyleBackColor = true;
            this.SodiumFreeBTN.Click += new System.EventHandler(this.SodiumFreeBTN_Click);
            // 
            // NoAccessBTN
            // 
            this.NoAccessBTN.Location = new System.Drawing.Point(193, 12);
            this.NoAccessBTN.Name = "NoAccessBTN";
            this.NoAccessBTN.Size = new System.Drawing.Size(156, 66);
            this.NoAccessBTN.TabIndex = 3;
            this.NoAccessBTN.Text = "No Access";
            this.NoAccessBTN.UseVisualStyleBackColor = true;
            this.NoAccessBTN.Click += new System.EventHandler(this.NoAccessBTN_Click);
            // 
            // ReadWriteBTN
            // 
            this.ReadWriteBTN.Location = new System.Drawing.Point(193, 184);
            this.ReadWriteBTN.Name = "ReadWriteBTN";
            this.ReadWriteBTN.Size = new System.Drawing.Size(156, 66);
            this.ReadWriteBTN.TabIndex = 4;
            this.ReadWriteBTN.Text = "Read Write Only";
            this.ReadWriteBTN.UseVisualStyleBackColor = true;
            this.ReadWriteBTN.Click += new System.EventHandler(this.ReadWriteBTN_Click);
            // 
            // ReadOnlyBTN
            // 
            this.ReadOnlyBTN.Location = new System.Drawing.Point(193, 99);
            this.ReadOnlyBTN.Name = "ReadOnlyBTN";
            this.ReadOnlyBTN.Size = new System.Drawing.Size(156, 66);
            this.ReadOnlyBTN.TabIndex = 5;
            this.ReadOnlyBTN.Text = "Read Only";
            this.ReadOnlyBTN.UseVisualStyleBackColor = true;
            this.ReadOnlyBTN.Click += new System.EventHandler(this.ReadOnlyBTN_Click);
            // 
            // SodiumGuardedHeapAllocationDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.ReadOnlyBTN);
            this.Controls.Add(this.ReadWriteBTN);
            this.Controls.Add(this.NoAccessBTN);
            this.Controls.Add(this.SodiumFreeBTN);
            this.Controls.Add(this.SodiumAllocArrayBTN);
            this.Controls.Add(this.SodiumMallocBTN);
            this.Name = "SodiumGuardedHeapAllocationDemo";
            this.Text = "SodiumGuardedHeapAllocationDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button SodiumMallocBTN;
        private System.Windows.Forms.Button SodiumAllocArrayBTN;
        private System.Windows.Forms.Button SodiumFreeBTN;
        private System.Windows.Forms.Button NoAccessBTN;
        private System.Windows.Forms.Button ReadWriteBTN;
        private System.Windows.Forms.Button ReadOnlyBTN;
    }
}