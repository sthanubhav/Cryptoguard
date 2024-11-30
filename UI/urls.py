from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.custom_login, name='login'),  
    path('dashboard/', views.home, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('files/', views.files, name='files'),
    path('shared/', views.shared_files, name='shared'),
    path('upload/', views.upload_file, name='upload_file'),
    path('security/', views.security_settings, name='security'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('update_share/', views.update_share, name='update_share'),
    path('delete_file/<int:file_id>/', views.delete_file, name='delete_file'),
    path('verify_integrity', views.verify_integrity, name='verify_integrity'),
    path('retrieve_main_logs/', views.retrieve_blockchain_logs, name='retrieve_main_logs'),
]
