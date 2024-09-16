from django.urls import path
from .views import *
urlpatterns=[
    path('auth/register',RegisterView.as_view(), name="Register"),
    path('auth/verify-email', VerifyMail.as_view(), name='verify-mail'),
    path('auth/login', LoginView.as_view(), name="user-login"),
    path('auth/resend-otp', SendOTP.as_view(), name="resend-otp"),
    path('auth/change-password', ChangePassword.as_view(), name="change-password")
]