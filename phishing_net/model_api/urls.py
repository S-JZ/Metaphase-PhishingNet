from django.urls import path
from . import views

urlpatterns = [
    path('', views.api_connect),
    path('sms/', views.get_messages),
    path('sms/create/', views.create_sms),
    path('sms/<str:key>/', views.get_message),
    path('sms/<str:key>/delete', views.delete_sms),
    ]