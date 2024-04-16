import matplotlib.pyplot as plt
from io import BytesIO
import base64
# import numpy as np
# import warnings

def generate_length_over_time_plotf(timestamps, lengths):
    plt.figure(figsize=(7, 5))
    plt.plot(timestamps, lengths, marker='o', linestyle='-',color='#0693e3')
    plt.xlabel('Time')
    plt.ylabel('Length')
    plt.title('Forward Packet Length Over Time')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.style.use('dark_background')
    plt.grid(True,color = "grey", linewidth = "1")
    l=plt.fill_between(timestamps, lengths)
    l.set_facecolors([[.5,.5,.8,.3]])
    l.set_edgecolors([[0, 0, .5, .3]])
    l.set_linewidths([3])
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plt.close()

    plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return plot_data

def generate_length_over_time_plotb(timestamps, lengths):
    plt.figure(figsize=(7, 5))
    plt.plot(timestamps, lengths, marker='o', linestyle='-',color='#0693e3')
    plt.xlabel('Time')
    plt.ylabel('Length')
    plt.title('Backward Packet Length Over Time')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.style.use('dark_background')
    plt.grid(True,color = "grey", linewidth = "1")
    l=plt.fill_between(timestamps, lengths)
    l.set_facecolors([[.5,.5,.8,.3]])
    l.set_edgecolors([[0, 0, .5, .3]])
    l.set_linewidths([3])
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plt.close()

    plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return plot_data

def generate_fwd_packets_per_sec_over_time_plot(timestamps, fwd_pack_per_sec):
    plt.figure(figsize=(14, 6))
    plt.plot(timestamps, fwd_pack_per_sec, marker='o', linestyle='-',color='#0693e3')
    plt.xlabel('Time')
    plt.ylabel('Fwd_packet_per_sec')
    plt.title('Fwd_packets_per_sec_over_time')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.style.use('dark_background')
    plt.grid(True,color = "grey", linewidth = "1")
    l=plt.fill_between(timestamps, fwd_pack_per_sec)
    l.set_facecolors([[.5,.5,.8,.3]])
    l.set_edgecolors([[0, 0, .5, .3]])
    l.set_linewidths([3])
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plt.close()

    plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return plot_data

def generate_stats_plot(min_len, mplt_len, backward_packet_len_mean, min_backward_len ,backward_packet_len_tot ,backward_packet_len_std ,avg_fwd_seg_size ,forward_packet_len_tot ,forward_packet_len_std ,fwd_packets_p_sec ,total_seg_size ,down_up_ratio_ ,packet_len_std ,idle_min_ ,idle_std_ ,flow_byt_per_sec ):

    keys = ['min_len', 'mplt_len', 'backward_packet_len_mean', 'min_backward_len', 'backward_packet_len_tot',
            'backward_packet_len_std', 'avg_fwd_seg_size', 'forward_packet_len_tot', 'forward_packet_len_std',
            'fwd_packets_p_sec', 'total_seg_size', 'down_up_ratio_', 'packet_len_std', 'idle_min_', 'idle_std_',
            'flow_byt_per_sec']

    values = [min_len, mplt_len, backward_packet_len_mean, min_backward_len, backward_packet_len_tot,
              backward_packet_len_std, avg_fwd_seg_size, forward_packet_len_tot, forward_packet_len_std,
              fwd_packets_p_sec, total_seg_size, down_up_ratio_, packet_len_std, idle_min_, idle_std_,
              flow_byt_per_sec]

    plt.figure(figsize=(12,5.5))
    bars = plt.bar(keys, values,color="#0693e3",zorder=2)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 0.01, round(yval, 2), ha='center', va='bottom')
    # plt.xlabel('Statistics')
    plt.ylabel('Values')
    # plt.title('Bar Graph of Statistical Parameters')
    plt.xticks(rotation=45, ha='right')
    # plt.xticks(range(len(keys)), keys)  
    plt.tight_layout()
    plt.style.use('dark_background')
    plt.grid(True, color="grey", linewidth="1")
    # gradientbars(bars)

    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plt.close()

    plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return plot_data 

# def gradientbars(bars):

#     grad = np.atleast_2d(np.linspace(0, 1, 256)).T
#     ax = bars[0].axes
#     lim = ax.get_xlim() + ax.get_ylim()
#     for bar in bars:
#         bar.set_zorder(1)
#         bar.set_facecolor('none')
#         x, y = bar.get_xy()
#         w, h = bar.get_width(), bar.get_height()
#         with warnings.catch_warnings():
#             warnings.filterwarnings("ignore", message="Attempting to set identical low and high ylims makes transformation singular; automatically expanding.")
#             ax.imshow(grad, extent=[x, x + w, y, y + h], aspect='auto', zorder=1)

#     ax.axis(lim)
