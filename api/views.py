import bcrypt
from django.core.mail import send_mail
from django.core.validators import validate_email
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
import datetime
from django.utils import timezone
from .models import *
from django.core.exceptions import ValidationError
import random
from .serializers import *
from trustlink.settings import EMAIL_HOST_USER

# This endpoint handles the user signup part.
class RegisterView(APIView):
    def post(self, request):
        data = request.data
        #Validation of request Body
        if not data.get('firstName') or not isinstance(data.get('firstName'), str):
            return Response({'errors': [{'field': "firstName", 'message': "firstName is required as string"}]},
                            status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not data.get('lastName') or not isinstance(data.get('lastName'), str):
            return Response({'errors': [{'field': "lastName", 'message': "lastName is required as string"}]},
                            status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not data.get('username') or not isinstance(data.get('username'), str):
            return Response({'errors': [{'field': "username", 'message': "UserName is required as string"}]},
                            status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not data.get('email'):
            return Response({'errors': [{'field': "email", 'message': "email address is reequired as email"}]},
                            status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not data.get('password') or not isinstance(data.get('password'), str):
            return Response({'errors': [{'field': "password", 'message': "password is required as string"}]},
                            status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if data.get('phone') is not None and not isinstance(data.get('phone'), str):
            return Response({'errors': [{'field': "phone", 'message': "phone is required as string"}]},
                            status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        try:
            validate_email(data.get('email'))
        except ValidationError:
            return Response({
                "status": "Bad Request",
                "message": "Email must be valid email",
                "statusCode": 400
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        #Handle email Duplication
        if User.objects.filter(email=data.get('email')).exists():
            return Response({
                "status": "Bad Request",
                "message": "Email is taken. Proceed to verify email or Login.",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        #Ensure username is Unique
        if User.objects.filter(username=data.get('username')).exists():
            return Response({
                "status": "Bad Request",
                "message": "Username is taken. Try Another or set it as your email.",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        password = data.get("password")
        #Encrypt User Password
        encrypted = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        otp = str(random.randint(100000, 999999)) #Generate OTP
        try:
            user = User.objects.create(firstName=data.get('firstName'), lastName=data.get('lastName'),
                                       email=data.get('email'), username=data.get('username'),password=encrypted, phone=data.get("phone"), )
            UserOTP.objects.create(otp=otp, user=user)
            #Send User OTP
            send_mail('Welcome To Trustlink...Email Verification',
                      f'Your OTP code is {otp}',
                      EMAIL_HOST_USER, [user.email], fail_silently=False)
            return Response({
                "status": "success",
                "message": "User registered successfully. An OTP has been sent to your mail",
                "data": {
                    "user": UserSerializer(user).data
                }
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                "status": "Bad request",
                "message": e,
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)

# Verify Email Via OTP
class VerifyMail(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                "status": "Bad Request",
                "message": "Email Verification failed"
            }, status=status.HTTP_400_BAD_REQUEST)
        check_otp = UserOTP.objects.get(user=user)
        if check_otp.otp != otp:
            return Response({
                "Status": "Bad request",
                "message": "Email verification failed"
            }, status=status.HTTP_400_BAD_REQUEST)

        if timezone.now() > check_otp.otp_created_at + datetime.timedelta(minutes=11):
            return Response({
                "message": "OTP expired already"
            }, status=status.HTTP_400_BAD_REQUEST)

        check_otp.otp = None
        check_otp.otp_created_at = None
        check_otp.save()

        refresh = RefreshToken.for_user(user)
        token = str(refresh.access_token)

        return Response({
            "message": "Email verified successfully",
            "data": {
                "access_token": token,
                "user": UserSerializer(user).data
            }
        }, status=status.HTTP_200_OK)

#User Login
class LoginView(APIView):
    def post(self, request):
        data = request.data
        id = data.get('id')
        raw_password = data.get('password')
        try:
            try:
                user = User.objects.get(email=id)
            except User.DoesNotExist:
                try:
                    user = User.objects.get(username=id)
                except User.DoesNotExist:
                    return Response({
                        "message": "Invalid Username/Email",
                        "statusCode": 401
                    }, status=status.HTTP_401_UNAUTHORIZED)
            otp = UserOTP.objects.get(user=user)
            if otp.otp == None:
                if bcrypt.checkpw(raw_password.encode('utf-8'), user.password.encode('utf-8')):
                    refresh = RefreshToken.for_user(user)
                    token = str(refresh.access_token)
                    return Response({
                        "message": "Login successful",
                        "data": {
                            "access_token": token,
                            "user": UserSerializer(user).data
                        }
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "message": "Password is incorrect",
                        "statusCode": 401
                    }, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({
                    "message": "Email is unverified. please verify email.",
                    "statusCode": 401
                }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(e)
            return Response({
                "message": "Bad Request",
                "statusCode": 401
            }, status=status.HTTP_401_UNAUTHORIZED)

class SendOTP(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        otp = str(random.randint(100000, 999999))
        try:
            user = User.objects.get(email=email)
            ava_otp = UserOTP.objects.get(user=user)
            if ava_otp:
                if ava_otp.otp == None:
                    return Response({
                        "message":"User has been verified. Proceed to login"
                    })
                else:
                    ava_otp.otp = otp
                    ava_otp.otp_created_at = timezone.now()
                    ava_otp.save()
                    send_mail('Your OTP Code',
                              f'Your OTP code is {otp}',
                              EMAIL_HOST_USER, [user.email], fail_silently=False)
                    return Response({
                        "status": "success",
                        "message": "An OTP has been sent to your mail",
                    }, status=status.HTTP_201_CREATED)
            else:

                UserOTP.objects.create(otp=otp, user=user)
                send_mail('Your OTP Code',
                          f'Your OTP code is {otp}',
                          EMAIL_HOST_USER, [user.email], fail_silently=False)
                return Response({
                    "status": "success",
                    "message": "An OTP has been sent to your mail",
                }, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({
                "message":"User email has not been registered"
            })

class ChangePassword(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        confirm = data.get('confirm')
        try:
            user = User.objects.get(email=request.user.email)
        except user.DoesNotExist:
            return Response({
                "message": "You do not have an account with us",
                "statusCode": 401
            }, status=status.HTTP_401_UNAUTHORIZED)
        valid = bcrypt.checkpw(old_password.encode('utf-8'), user.password.encode('utf-8'))
        if valid == False:
            return Response({
                "message": "Existing Password is Wrong",
                "statusCode": 401
            }, status=status.HTTP_401_UNAUTHORIZED)
        if new_password != confirm:
            return Response({
                "message": "Passwords don't match",
                "statusCode": 401
            }, status=status.HTTP_401_UNAUTHORIZED)
        encrypted = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password = encrypted
        user.save()
        return Response({
            "message":"Password Successfully Updated",
            "statusCode":200
        }, status=status.HTTP_200_OK)


