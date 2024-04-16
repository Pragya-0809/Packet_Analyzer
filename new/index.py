from django.http import HttpResponse
from django.shortcuts import render

def webpag1(request):
    return render(request,'r1.html')

def webpag2(request):
    return render(request,'create_account.html')

def home(request):
    return render(request, 'home.html')