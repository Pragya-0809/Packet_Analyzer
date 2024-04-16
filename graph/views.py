from django.shortcuts import render, redirect
from .models import Create_acnt
from django.contrib import messages
from django.contrib.auth.models import User 
from django.contrib.auth import authenticate, login
from .utils import generate_length_over_time_plotf,generate_length_over_time_plotb, generate_fwd_packets_per_sec_over_time_plot
from .data3 import *
from .utils import generate_stats_plot
from django.http import JsonResponse
import joblib

def index(request):
    timestampsf = []
    lengthsf = []
    timestampsb = []
    lengthsb = []
    fwd_pack_per_sec=[]
    timestampfwd=[]

    keys = list(ip_stats_map.keys())
    selected_key = request.GET.get('key')


    if selected_key in ip_stats_map:
        timestampsf = [packets_fwd["timestamp"] for packets_fwd in ip_stats_map[selected_key]["packets_fwd"]]
        lengthsf = [packets_fwd["length"] for packets_fwd in ip_stats_map[selected_key]["packets_fwd"]]
        timestampsb = [packets_bwd["timestamp"] for packets_bwd in ip_stats_map[selected_key]["packets_bwd"]]
        lengthsb = [packets_bwd["length"] for packets_bwd in ip_stats_map[selected_key]["packets_bwd"]]

        packet_fwd_per_sec_data = ip_stats_map[selected_key].get("packet_fwd_per_sec", [])
        fwd_pack_per_sec = [packet_fwd_per_sec["fwd_packets_per_sec"] for packet_fwd_per_sec in packet_fwd_per_sec_data]
        timestampfwd = [packet_fwd_per_sec["timestamp"] for packet_fwd_per_sec in packet_fwd_per_sec_data]


    context = {
        'keys': keys,
        'selected_key': selected_key,
        'timestampsf': timestampsf,
        'lengthsf': lengthsf,
        'timestampsb': timestampsb,
        'lengthsb': lengthsb,
        'length_over_time_plotf': generate_length_over_time_plotf(timestampsf, lengthsf),
        'length_over_time_plotb': generate_length_over_time_plotb(timestampsb, lengthsb),
        'fwd_packets_per_sec_over_time_plot':generate_fwd_packets_per_sec_over_time_plot(timestampfwd,fwd_pack_per_sec)
        # 'ip_over_min_max_length':generate_ip_minlength_maxlength(keys,min_lengths_array,max_lengths_array)

    }

    return render(request, 'plot.html', context)

def index1(request):

    keys = list(ip_stats_map.keys())
    selected_key = request.GET.get('key')

    min_len = max_len = backward_packet_len_mean = min_backward_len = backward_packet_len_tot = backward_packet_len_std = avg_fwd_seg_size = forward_packet_len_tot = forward_packet_len_std =fwd_packets_p_sec = total_seg_size = down_up_ratio_ = packet_len_std = idle_min_ = idle_std_ = flow_byt_per_sec = 0

    if selected_key in ip_stats_map:
        stats_data = ip_stats_map[selected_key]
        min_len = stats_data.get("min_length", 0)
        max_len = stats_data.get("max_length", 0)
        backward_packet_len_mean = stats_data.get("backward_packet_length_mean", 0)
        min_backward_len = stats_data.get("min_backward_length", 0)
        backward_packet_len_tot = stats_data.get("backward_packet_length_tot", 0)
        backward_packet_len_std = stats_data.get("backward_packet_length_std", 0)
        avg_fwd_seg_size = stats_data.get("avg_fwd_segment_size", 0)
        forward_packet_len_tot = stats_data.get("forward_packet_length_tot", 0)
        forward_packet_len_std = stats_data.get("forward_packet_length_std", 0)
        fwd_packets_p_sec = stats_data.get("fwd_packets_per_sec", 0)
        total_seg_size = stats_data.get("total_segments_size", 0)
        down_up_ratio_ = stats_data.get("down_up_ratio", 0)
        packet_len_std = stats_data.get("packet_length_std", 0)
        idle_min_ = stats_data.get("idle_min", 0)
        idle_std_ = stats_data.get("idle_std", 0)
        flow_byt_per_sec = stats_data.get("flow_bytes_per_sec", 0)


    context = {
        'keys': keys,
        'selected_key': selected_key,
        'generate_stats_plot': generate_stats_plot(min_len, max_len, backward_packet_len_mean, min_backward_len ,backward_packet_len_tot ,backward_packet_len_std ,
        avg_fwd_seg_size ,forward_packet_len_tot ,forward_packet_len_std ,fwd_packets_p_sec ,total_seg_size ,down_up_ratio_ ,packet_len_std ,idle_min_ ,idle_std_ ,flow_byt_per_sec )
    }

    return render(request, 'plot2.html', context)


def login_view(request):
    if request.method == 'POST':
        uemail = request.POST.get('email')
        pass1 = request.POST.get('password')
        
        # Authenticate user
        myuser = authenticate(username=uemail, password=pass1)
        print(myuser)
        if myuser is not None:
            # Login successful, redirect to home page
            login(request, myuser) 
            return redirect('/home')
        else:
            # Account does not exist or credentials are incorrect
            messages.error(request, 'Invalid credentials')
            print("invalid")
            return redirect('/')  # Redirect to the login page with an error message
    return render(request, 'r1.html')

def create_account(request):
    if request.method=="POST":
        fname=request.POST.get("name")
        femail=request.POST.get("email")
        fpwd=request.POST.get("pwd")
        fcon_pwd=request.POST.get("c_pwd")
           
        if fpwd!=fcon_pwd:
            messages.warning(request,"Password is Incorrect")
            return redirect('/create_account')  # Redirect to the same page
        
        if not contains_only_alphabets(fname):
            messages.error(request, "Username must contain only alphabetic characters")
            return redirect('/create_account')

        if not femail.endswith('@gmail.com') and not femail.endswith('@banasthali.in'):
            messages.warning(request, "Email must end with either @gmail.com or @banasthali.in")
            return redirect('/create_account')

        if not re.match(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()-_+=\[\]{}|:;"\'<>,.?/~`])[0-9a-zA-Z!@#$%^&*()-_+=\[\]{}|:;"\'<>,.?/~`]{8,}$', fpwd):
            messages.error(request, "Password is not strong it should be of 8 charecters atleast and it must be combination of uppercase,lowercase, digits and special charecters")
            return redirect('/create_account')
        try:
            if User.objects.get(username=fname):
                messages.info(request,"UserName Is Taken")
                return redirect('/create_account')
        except:
            pass
        try:
            if User.objects.get(email=femail):
                messages.info(request,"Account with this email already exists.")
                return redirect('/create_account')
        except:
            pass

        myuser=User.objects.create_user(fname,femail,fpwd)
        myuser.save()
        messages.success(request,"Signup Success")
        return redirect('/home')
    info_messages = messages.get_messages(request)
    return render(request, 'create_account.html',{'info_messages': info_messages})
def contains_only_alphabets(name):
    return bool(re.match(r'^[a-zA-Z]+$',name))
    
def home(request):
    return render(request, 'home.html')

def about(request):
    return render(request, 'about.html')

def model_prediction(request):
    cls=joblib.load('graph/models_ml/model.joblib')
    # prediction=[]

    # for index, row in df.iterrows():
    #     input_data = np.array([row[' Avg Bwd Segment Size'], row[' Bwd Packets/s'], row[' Destination Port'], row[' Max Packet Length'], row[' Bwd Packet Length Max'], row[' Packet Length Std'], row[' Packet Length Mean'], row[' Average Packet Size'], row[' Packet Length Variance'], row[' Bwd Packet Length Std'], row[' Total Length of Fwd Packets'], row[' Flow Bytes/s'], row[' Avg Fwd Segment Size'], row[' Total Length of Bwd Packets'],row[' Flow Packets/s']]).reshape(1, -1)
    #     prediction.append(cls.predict(input_data)[0])
    #     prediction = [int(pred) for pred in prediction]
    # return JsonResponse({'prediction': prediction})
    # Create an empty dictionary to store predictions for each IP address
    predictions_dict = {}
    # ip_dictionary = {
    #     'IP Addresses': list(ip_stats_map.keys())
    # }
    ip = []
    for key, value in ip_stats_map.items():
        ip.append(key)


    for index, row in df.iterrows():
            ip_address = ip[index] 

            input_data = np.array([row[' Avg Bwd Segment Size'], row[' Bwd Packets/s'], row[' Destination Port'], row[' Max Packet Length'], row[' Bwd Packet Length Max'], row[' Packet Length Std'], row[' Packet Length Mean'], row[' Average Packet Size'], row[' Packet Length Variance'], row[' Bwd Packet Length Std'], row[' Total Length of Fwd Packets'], row[' Flow Bytes/s'], row[' Avg Fwd Segment Size'], row[' Total Length of Bwd Packets'], row[' Flow Packets/s']]).reshape(1, -1)
            
            pred = cls.predict(input_data)[0]

            predictions_dict[ip_address] = int(pred)

    return render(request, 'predictions.html', {'predictions': predictions_dict})
    # return JsonResponse({'predictions': predictions_dict})

#from django.shortcuts import render
#from .utils import generate_length_over_time_plot, generate_down_up_ratio_plot, generate_total_length_plot
#from .data import data

