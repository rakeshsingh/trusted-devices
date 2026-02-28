from django.urls import path
from . import views

urlpatterns = [
    path('', views.device_list, name='device_list'),
    path('register/', views.register_device_view, name='register_device'),
    path('audit-logs/', views.audit_log_list, name='audit_log_list'),
    path('device/<uuid:device_id>/<str:action>/', views.device_action, name='device_action'),
]
