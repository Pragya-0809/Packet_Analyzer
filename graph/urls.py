"""
URL configuration for new project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# from django.contrib import admin
# from django.urls import path,include
# from graph import views

from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='webpage1'),
    path('create_account', views.create_account, name='create_accont'),
    path('home', views.home, name='home'),
    path('graph1/', views.index, name='index'),
    path('graph2/', views.index1, name='index'),
    path('pred/',views.model_prediction,name='model_prediction'),
    path('about/',views.about, name='about')
]
