import json
import os
from django.http import JsonResponse
from dotenv import load_dotenv
import bcrypt
import requests
from django.core.mail import send_mail
from django.core.validators import validate_email
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
import datetime
from django.utils import timezone
from .models import *
from django.core.exceptions import ValidationError
import random
from .serializers import *
from trustlink.settings import EMAIL_HOST_USER
load_dotenv()
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
                "message": str(e),
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

class BeginForgotPassword(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        try:
            user = User.objects.get(email=email)
        except  user.DoesNotExist:
            return Response({
                "message":"This email is not registered",
                "status":400
            }, status=status.HTTP_400_BAD_REQUEST)
        refresh = RefreshToken.for_user(user)
        token = str(refresh.access_token)

        domain = request.get_host()
        # reset_path = reverse('password-reset-confirm', kwargs={'token':token})

        protocol = 'https' if request.is_secure() else 'http'
        reset_url = f"{protocol}://{domain}/auth/complete-reset?token={token}"

        subject = "Password Reset Request"
        message = f"Hi, {user.firstName}, \n\nPlease Click the link below to reset your password. Ignore if you didn't request a new password. \n\n{reset_url}"
        send_mail(subject, message, EMAIL_HOST_USER, [user.email])

        return Response({
            "message":"Password reset link has been sent to your email",
            "status": 200,
        }, status=status.HTTP_200_OK)

class CompleteReset(APIView):
    def post(self, request):
        token = request.GET.get('token')
        data = request.data
        new_password = data.get('new_password')
        confirm = data.get('confirm')
        if not token:
            return Response({
                "message":"Token is missing",
                "status":400
            }, status=status.HTTP_400_BAD_REQUEST)
        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']

            user = User.objects.get(id=user_id)

            if new_password != confirm:
                return Response({
                    "message":"Passwords don't match",
                    "status":400
                }, status=status.HTTP_400_BAD_REQUEST)

            encrypted = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user.password = encrypted
            user.save()
            return Response({
                "message":"Password Reset Successfully",
                "status":200
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message":str(e),
                "statusCode":500
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Extracting banks data from the Kora API and storing in our DB
def store_banks(request):
    public_key = os.getenv("KORA_PUBLIC")
    print(public_key)
    # url = "https://api.paystack.co/bank"
    url = "https://api.korapay.com/merchant/api/v1/misc/banks?countyrCode=NG"
    headers = {
        "Authorization": f"Bearer {public_key}",
        "Content-Type": 'application/json'
    }
    payload = ""
    response = requests.get(url, headers=headers, data=payload)

    if response.status_code == 200:
        try:
            banks = response.json()
            for bank in banks.get('data', []):
                Banks.objects.update_or_create(
                    name=bank['name'].strip,
                    slug = bank['slug'],
                    code = bank['code']
                )
            return JsonResponse(banks)
        except ValueError:
            return JsonResponse({"error": "Invalid JSON response"}, status=500)
    else:
        return JsonResponse({"error": f"Request failed with status code {response.status_code}"},
                                status=response.status_code)

class CreateAccount(APIView):
    def get(self, request):
        try:
            banks = Banks.objects.all()
            return Response({
                "message":"Banks retrieved successfully.",
                "banks": BankSerializer(banks, many=True).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    permission_classes = [IsAuthenticated]
    def post(self, request):

        data = request.data
        code = data['code']
        account_number = data['account_number']
        user = request.user
        print(code, account_number,user)
        try:
            user_account = Account.objects.get(user=request.user)
            return Response({
                "message":"You can only have one account saved. Edit it from settings",
                "statusCode":400
            },status=status.HTTP_400_BAD_REQUEST)
        except Account.DoesNotExist:
            url = "https://api.korapay.com/merchant/api/v1/misc/banks/resolve"
            payload = json.dumps({
                "bank":code,
                "account":account_number
            })
            headers = {
                'Content-Type': 'application/json'
            }
            response = requests.request("POST",url, data=payload, headers=headers)
            print(response.text)
            if response.status_code == 200:
                details =response.json()
                dets = details.get('data')
                user_account = Account.objects.create(user=user,bankCode=code, accountNumber=account_number, accountName=str(dets['account_name']))
                return Response({
                    "message":"Account saved successfully",
                    "account details":AccountSerializer(user_account).data
                }, status=status.HTTP_201_CREATED)
            return Response({
                "message":f"request error with error code {response.status_code}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def kora_payout(request, amount, bank, account, name, email):
    url = "https://api.korapay.com/merchant/api/v1/transactions/disburse"

    payload = json.dumps({
        "reference": "your-uniq-reference-001",
        "destination": {
            "type": "bank_account",
            "amount": amount,
            "currency": "NGN",
            "narration": "Test Transfer Payment",
            "bank_account": {
                "bank": bank,
                "account": account
            },
            "customer": {
                "name": name,
                "email": email
            }
        }
    })
    headers = {
        'Content-Type': 'application/json',
        "Authorization": f"Bearer {os.getenv('KORA_SECRET')}"
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    result = response.json()
    return response.status_code
    print(response.text)

class WithdrawWallet(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        amount = data['amount']
        try:
            wallet = Wallet.objects.get(user=request.user)
            try:
                account = Account.objects.get(user= request.user)
                if wallet.balance - float(amount) >= 100:
                    payment = kora_payout(str(amount),str(account.bankCode), str(account.accountNumber),str(request.user.firstName),str(request.user.email))
                    if payment == 200:
                        return Response({
                            "message":"Withdrawal Processsed Successfully. You will be credited shortly",
                            "statusCode":200
                        }, status=status.HTTP_200_OK)
                    return Response({
                        "message":f"Request failed with status code {payment}"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                return Response({
                    "message":"Insufficient wallet balance",
                    "statusCode":400
                }, status=status.HTTP_400_BAD_REQUEST)
            except Account.DoesNotExist:
                return Response({
                    "message":"Account details not found"
                }, status=status.HTTP_404_NOT_FOUND)
        except Wallet.DoesNotExist:
            return Response({
                "message": "User Wallet not found"
            }, status=status.HTTP_404_NOT_FOUND)






