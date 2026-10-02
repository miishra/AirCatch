#!/usr/bin/env python3
"""
Script to plot CFO distributions from BLE fingerprints.
Creates various visualizations: boxplots, violin plots, CDF, KDE plots grouped by MAC address.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde
from matplotlib.patches import Patch
import os

def get_device_color(device_type):
    """Return (face_color, edge_color) for device type."""
    colors = {
        "APPLE": ("#3b82f6", "#1e40af"),      # Professional blue
        "GOOGLE": ("#10b981", "#047857"),     # Emerald green
        "SAMSUNG": ("#8b5cf6", "#5b21b6"),    # Purple
        "TILE": ("#f59e0b", "#b45309"),       # Amber
    }
    return colors.get(device_type.upper(), ("#6b7280", "#374151"))

def main():
    # Fixed paths: this script draws exactly one thing, the paper's Figure 4,
    # from exactly one capture. Run it from the repository root.
    input_file = 'dataset/ble_packets_fingerprints_with_metadata_priv.csv'
    output_dir = '.cfo_priorwork_work'
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        return
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Read data
    print("Reading fingerprints file...")
    df = pd.read_csv(input_file)
    
    # CFO columns to plot (check which ones exist)
    cfo_cols_available = ['f0_Hz', 'est_cfo_Hz', 'cfo_quick_hz', 
                         'cfo_equal_00_hz', 'cfo_equal_11_hz', 
                         'cfo_jump_10_hz', 'cfo_jump_01_hz']
    cfo_cols = [col for col in cfo_cols_available if col in df.columns]
    
    if not cfo_cols:
        print(f"Error: No CFO columns found!")
        return
    
    print(f"Using CFO columns: {cfo_cols}")
    
    # Remove rows with missing adv_addr or tag_type
    df = df[df['adv_addr'].notna()].copy()
    df = df[df['tag_type'].notna()].copy()
    df['tag_type'] = df['tag_type'].str.upper()
    
    # Filter out packets containing "aafe40" in payload_hex
    if 'payload_hex' in df.columns:
        initial_count = len(df)
        aafe40_mask = df['payload_hex'].astype(str).str.lower().str.contains('aafe40', na=False)
        filtered_count = aafe40_mask.sum()
        df = df[~aafe40_mask].copy()
        print(f"Filtered out {filtered_count} packets containing 'aafe40' (total: {initial_count} -> {len(df)})")
    
    # Get unique MACs and their device types
    mac_device = df.groupby('adv_addr')['tag_type'].first().to_dict()
    
    # Get packet counts per MAC
    mac_counts = df.groupby('adv_addr').size().to_dict()
    
    # Group MACs by device type and create numbered labels
    device_type_groups = {}
    for device_type in sorted(df['tag_type'].unique()):
        macs = [mac for mac, dtype in mac_device.items() if dtype == device_type]
        # For Apple, sort by packet count and keep top 15
        if device_type == "APPLE":
            macs_sorted = sorted(macs, key=lambda m: mac_counts.get(m, 0), reverse=True)[:15]
            device_type_groups[device_type] = macs_sorted
        else:
            device_type_groups[device_type] = sorted(macs)
    
    # Create ordered list with device-numbered labels
    device_specs = []  # List of (mac, label, device_type)
    for device_type in ["APPLE", "GOOGLE", "SAMSUNG", "TILE"]:
        if device_type in device_type_groups:
            for i, mac in enumerate(device_type_groups[device_type], 1):
                label = f"{device_type.capitalize()} {i}"
                device_specs.append((mac, label, device_type))
    
    print(f"Found {len(device_specs)} devices")
    print(f"Total samples: {len(df)}")
    print(f"\nDevices by type:")
    for device_type in sorted(device_type_groups.keys()):
        print(f"  {device_type}: {len(device_type_groups[device_type])} devices")
    
    # ============================================
    # Plot for each CFO column
    # ============================================
    for cfo_col in cfo_cols:
        print(f"\n{'='*60}")
        print(f"Processing {cfo_col}")
        print(f"{'='*60}")
        
        # ============================================
        # 1. Violin plot by MAC address (custom KDE, no tails)
        # ============================================
        print(f"Creating violin plot for {cfo_col}...")
        
        MIN_SAMPLES = 6
        VIOLIN_WIDTH = 0.8
        
        # Collect valid data
        plot_data = []
        plot_labels = []
        plot_colors = []
        
        for mac, label, device_type in device_specs:
            mac_df = df[df['adv_addr'] == mac]
            face_color, edge_color = get_device_color(device_type)
            
            vals = mac_df[cfo_col].dropna() / 1000.0  # Convert to kHz
            if len(vals) >= MIN_SAMPLES:
                plot_data.append(vals.values)
                plot_labels.append(label)
                plot_colors.append((face_color, edge_color))
        
        if not plot_data:
            print(f"  Skipped: insufficient data")
            continue
        
        # Calculate global y-axis limits
        all_vals = np.concatenate(plot_data)
        global_ymin, global_ymax = all_vals.min(), all_vals.max()
        
        # USENIX 2-column width
        USENIX_2COL_WIDTH = 7.0
        fig, ax = plt.subplots(figsize=(USENIX_2COL_WIDTH, 5.0))
        
        # Create custom violin plots without tails
        for pos, (vals, (face_color, edge_color)) in enumerate(zip(plot_data, plot_colors)):
            # Strictly limit to data range - no KDE tails
            vmin, vmax = vals.min(), vals.max()
            
            # Use a tighter range for KDE evaluation to eliminate tails
            margin = (vmax - vmin) * 0.01
            y_range = np.linspace(vmin - margin, vmax + margin, 100)
            
            # Calculate KDE with tight bandwidth
            kde = gaussian_kde(vals, bw_method=0.10)
            density = kde(y_range)
            
            # Clip to actual data range - removes tails completely
            mask = (y_range >= vmin) & (y_range <= vmax)
            y_range_clipped = y_range[mask]
            density_clipped = density[mask]
            
            if len(y_range_clipped) > 0:
                # Normalize density for width
                density_clipped = density_clipped / density_clipped.max() * VIOLIN_WIDTH / 2
                
                # Plot left and right halves with device-specific colors
                ax.fill_betweenx(y_range_clipped, pos - density_clipped, pos + density_clipped, 
                                 facecolor=face_color, edgecolor=edge_color, 
                                 alpha=0.80, linewidth=1.0)
            
            # Add median line - subtle
            median_val = np.median(vals)
            ax.plot([pos - VIOLIN_WIDTH/2, pos + VIOLIN_WIDTH/2], 
                    [median_val, median_val], 
                    color='#000000', linewidth=0.8, alpha=0.6, zorder=10)
        
        # Axis styling
        ax.set_ylabel('CFO (kHz)', fontsize=10, fontweight='bold')
        ax.set_xlabel('Device', fontsize=10, fontweight='bold')
        ax.set_xticks(range(len(plot_labels)))
        ax.set_xticklabels(plot_labels, rotation=45, ha='right', fontsize=8)
        ax.set_xlim(-0.5, len(plot_labels) - 0.5)
        ax.set_ylim(global_ymin, global_ymax)
        ax.grid(True, axis="y", linestyle="--", alpha=0.4)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_linewidth(1.2)
        ax.spines["bottom"].set_linewidth(1.2)
        
        # Add legend for device types
        unique_types = [dt for dt in ["APPLE", "GOOGLE", "SAMSUNG", "TILE"] if dt in device_type_groups]
        legend_handles = []
        for dtype in unique_types:
            face_color, edge_color = get_device_color(dtype)
            legend_handles.append(Patch(facecolor=face_color, edgecolor=edge_color, 
                                       label=dtype.capitalize(), alpha=0.80))
        
        if legend_handles:
            ax.legend(handles=legend_handles, loc="lower center", 
                     bbox_to_anchor=(0.5, 1.02), ncol=len(legend_handles), 
                     columnspacing=1.0, handlelength=1.5, frameon=True, fontsize=8)
        
        plt.tight_layout()
        out_path = os.path.join(output_dir, f'{cfo_col}_violin_by_mac.pdf')
        plt.savefig(out_path, bbox_inches='tight')
        plt.close()
        print(f"  Saved: {out_path}")
        
        # ============================================
        # 2. CDF plot by MAC address
        # ============================================
        print(f"Creating CDF plot for {cfo_col}...")
        
        USENIX_2COL_WIDTH = 7.0
        fig, ax = plt.subplots(figsize=(USENIX_2COL_WIDTH, 4.0))
        
        for mac, label, device_type in device_specs:
            mac_df = df[df['adv_addr'] == mac]
            face_color, _ = get_device_color(device_type)
            
            vals = mac_df[cfo_col].dropna() / 1000.0
            if len(vals) >= MIN_SAMPLES:
                sorted_vals = np.sort(vals)
                cdf = np.arange(1, len(sorted_vals) + 1) / len(sorted_vals)
                ax.plot(sorted_vals, cdf, label=label, 
                       color=face_color, linewidth=1.5, alpha=0.8)
        
        ax.set_xlabel(f'{cfo_col} (kHz)', fontsize=10, fontweight='bold')
        ax.set_ylabel('CDF', fontsize=10, fontweight='bold')
        ax.legend(loc='best', fontsize=7, ncol=2, frameon=True)
        ax.grid(True, axis="both", linestyle="--", alpha=0.4)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_linewidth(1.2)
        ax.spines["bottom"].set_linewidth(1.2)
        
        plt.tight_layout()
        out_path = os.path.join(output_dir, f'{cfo_col}_cdf_by_mac.pdf')
        plt.savefig(out_path, bbox_inches='tight')
        plt.close()
        print(f"  Saved: {out_path}")
        
        # ============================================
        # 3. KDE density plot by MAC
        # ============================================
        print(f"Creating KDE plot for {cfo_col}...")
        
        USENIX_2COL_WIDTH = 7.0
        fig, ax = plt.subplots(figsize=(USENIX_2COL_WIDTH, 4.0))
        
        for mac, label, device_type in device_specs:
            mac_df = df[df['adv_addr'] == mac]
            face_color, _ = get_device_color(device_type)
            
            vals = mac_df[cfo_col].dropna() / 1000.0
            if len(vals) >= MIN_SAMPLES:
                # Use custom KDE with tight bandwidth
                kde = gaussian_kde(vals.values, bw_method=0.10)
                x_range = np.linspace(vals.min(), vals.max(), 200)
                density = kde(x_range)
                
                ax.plot(x_range, density, label=label, 
                       color=face_color, linewidth=1.5, alpha=0.8)
        
        ax.set_xlabel(f'{cfo_col} (kHz)', fontsize=10, fontweight='bold')
        ax.set_ylabel('Density', fontsize=10, fontweight='bold')
        ax.legend(loc='best', fontsize=7, ncol=2, frameon=True)
        ax.grid(True, axis="both", linestyle="--", alpha=0.4)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_linewidth(1.2)
        ax.spines["bottom"].set_linewidth(1.2)
        
        plt.tight_layout()
        out_path = os.path.join(output_dir, f'{cfo_col}_kde_by_mac.pdf')
        plt.savefig(out_path, bbox_inches='tight')
        plt.close()
        print(f"  Saved: {out_path}")
        
        # ============================================
        # 4. Statistics summary by MAC
        # ============================================
        print(f"\n{cfo_col} Statistics by Device:")
        print("=" * 100)
        print(f"{'Device':<20} {'N':<5} {'Mean (kHz)':<15} {'Std (kHz)':<15} {'Min (kHz)':<15} {'Max (kHz)':<15}")
        print("=" * 100)
        
        for mac, label, device_type in device_specs:
            mac_df = df[df['adv_addr'] == mac]
            vals = mac_df[cfo_col].dropna() / 1000.0
            
            if len(vals) > 0:
                print(f"{label:<20} {len(vals):<5} {vals.mean():<15.2f} {vals.std():<15.2f} {vals.min():<15.2f} {vals.max():<15.2f}")
    
    print(f"\n✓ All plots saved to: {output_dir}/")

if __name__ == '__main__':
    main()
