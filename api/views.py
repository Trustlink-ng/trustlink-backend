import base64
import hashlib
import hmac
import json
import os
import uuid
import rest_framework_simplejwt.tokens
from django.db import transaction
from django.http import JsonResponse
from dotenv import load_dotenv
import bcrypt
import requests
from django.core.mail import send_mail
from django.core.validators import validate_email
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import BlacklistMixin
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
import datetime
from django.utils import timezone
from django.core.exceptions import ValidationError
import random
from .serializers import *
from trustlink.settings import EMAIL_HOST_USER, KORA_SECRET
from Crypto.Cipher import AES
from Crypto import Random

load_dotenv()
from django.db.models import Q
from .models import *
from binascii import hexlify as hexa


# This endpoint handles the user signup part.
class RegisterView(APIView):
    def post(self, request):
        data = request.data
        # Validation of request Body
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
        # Handle email Duplication
        if User.objects.filter(email=data.get('email')).exists():
            return Response({
                "status": "Bad Request",
                "message": "Email is taken. Proceed to verify email or Login.",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        # Ensure username is Unique
        if User.objects.filter(username=data.get('username')).exists():
            return Response({
                "status": "Bad Request",
                "message": "Username is taken. Try Another or set it as your email.",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        password = data.get("password")
        # Encrypt User Password
        encrypted = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        otp = str(random.randint(100000, 999999))  # Generate OTP
        try:
            user = User.objects.create(firstName=data.get('firstName'), lastName=data.get('lastName'),
                                       email=data.get('email').lower(), username=data.get('username'),
                                       password=encrypted,
                                       phone=data.get("phone"), )
            UserOTP.objects.create(otp=otp, user=user)
            # Send User OTP
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
        if 'email' not in data or not data.get('email'):
            return Response({
                "status": "Bad Request",
                "message": "Email is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            # Validate that 'otp' is present
        if 'otp' not in data or not data.get('otp'):
            return Response({
                "status": "Bad Request",
                "message": "OTP is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        email = data.get('email').lower()
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


# User Login
class LoginView(APIView):
    def post(self, request):
        data = request.data
        if 'id' not in data or not data.get('id'):
            return Response({
                "status": "Bad Request",
                "message": "Email/Username is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            # Validate that 'otp' is present
        if 'password' not in data or not data.get('password'):
            return Response({
                "status": "Bad Request",
                "message": "password is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        id = data.get('id')
        raw_password = data.get('password')
        try:
            try:
                user = User.objects.get(email=id.lower())
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
                    # r_token = AccessToken.for_user(user)
                    try:
                        saved_token = Token.objects.get(user=user)
                        saved_token.refresh_token = refresh
                        saved_token.save()
                    except Token.DoesNotExist:
                        Token.objects.create(user=user, refresh_token=refresh)
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
        if 'email' not in data or not data.get('email'):
            return Response({
                "status": "Bad Request",
                "message": "Email is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        email = data.get('email').lower()
        otp = str(random.randint(100000, 999999))
        try:
            user = User.objects.get(email=email)
            ava_otp = UserOTP.objects.get(user=user)
            if ava_otp:
                if ava_otp.otp == None:
                    return Response({
                        "message": "User has been verified. Proceed to login"
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
                "message": "User email has not been registered"
            })


class ChangePassword(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        if 'old_password' not in data or not data.get('old_password'):
            return Response({
                "status": "Bad Request",
                "message": "old_password is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            # Validate that 'otp' is present
        if 'new_password' not in data or not data.get('new_password'):
            return Response({
                "status": "Bad Request",
                "message": "new_password is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'confirm' not in data or not data.get('confirm'):
            return Response({
                "status": "Bad Request",
                "message": "Confirm is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
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
            "message": "Password Successfully Updated",
            "statusCode": 200
        }, status=status.HTTP_200_OK)


class BeginForgotPassword(APIView):
    def post(self, request):
        data = request.data
        if 'email' not in data or not data.get('email'):
            return Response({
                "status": "Bad Request",
                "message": "Email is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        email = data.get('email').lower()
        try:
            user = User.objects.get(email=email)
        except  user.DoesNotExist:
            return Response({
                "message": "This email is not registered",
                "status": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        refresh = RefreshToken.for_user(user)
        token = str(refresh.access_token)

        domain = request.get_host()
        # reset_path = reverse('password-reset-confirm', kwargs={'token':token})

        protocol = 'https' if request.is_secure() else 'http'
        reset_url = f"http://localhost:5173/auth/complete-reset?token={token}"

        subject = "Password Reset Request"
        message = f"Hi, {user.firstName}, \n\nPlease Click the link below to reset your password. Ignore if you didn't request a new password. \n\n{reset_url}"
        send_mail(subject, message, EMAIL_HOST_USER, [user.email])

        return Response({
            "message": "Password reset link has been sent to your email",
            "status": 200,
        }, status=status.HTTP_200_OK)


class CompleteReset(APIView):
    def post(self, request):
        token = request.GET.get('token')
        data = request.data
        if 'new_password' not in data or not data.get('new_password'):
            return Response({
                "status": "Bad Request",
                "message": "New Password is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            # Validate that 'otp' is present
        if 'confirm' not in data or not data.get('confirm'):
            return Response({
                "status": "Bad Request",
                "message": "Confirm Password Please"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        new_password = data.get('new_password')
        confirm = data.get('confirm')
        if not token:
            return Response({
                "message": "Token is missing",
                "status": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']

            user = User.objects.get(id=user_id)

            if new_password != confirm:
                return Response({
                    "message": "Passwords don't match",
                    "status": 400
                }, status=status.HTTP_400_BAD_REQUEST)

            encrypted = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user.password = encrypted
            user.save()
            return Response({
                "message": "Password Reset Successfully",
                "status": 200
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": str(e),
                "statusCode": 500
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
                    slug=bank['slug'],
                    code=bank['code']
                )
            return JsonResponse(banks)
        except ValueError:
            return JsonResponse({"error": "Invalid JSON response"}, status=500)
    else:
        return JsonResponse({"error": f"Request failed with status code {response.status_code}"},
                            status=response.status_code)

class UserAccount(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            account = Account.objects.get(user=request.user)
            return Response({
                "message":"Account details retrieved successfully",
                "data":AccountSerializer(account).data
            }, status=status.HTTP_200_OK)
        except Account.DoesNotExist:
            return Response({
                "message":"No account details set up"
            }, status=status.HTTP_404_NOT_FOUND)

class CreateAccount(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            banks = Banks.objects.all()
            return Response({
                "message": "Banks retrieved successfully.",
                "banks": BankSerializer(banks, many=True).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




    def post(self, request):
        data = request.data
        if 'code' not in data or not data.get('code'):
            return Response({
                "status": "Bad Request",
                "message": "Bank Code is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            # Validate that 'otp' is present
        if 'account_number' not in data or not data.get('account_number'):
            return Response({
                "status": "Bad Request",
                "message": "Account Number is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        code = data['code']
        account_number = data['account_number']
        user = request.user
        print(code, account_number, user)
        try:
            user_account = Account.objects.get(user=request.user)
            return Response({
                "message": "You can only have one account saved. Edit it from settings",
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        except Account.DoesNotExist:
            url = "https://api.korapay.com/merchant/api/v1/misc/banks/resolve"
            payload = json.dumps({
                "bank": code,
                "account": account_number
            })
            headers = {
                'Content-Type': 'application/json'
            }
            response = requests.request("POST", url, data=payload, headers=headers)
            print(response.text)
            if response.status_code == 200:
                details = response.json()
                dets = details.get('data')
                user_account = Account.objects.create(user=user, bankCode=code, accountNumber=account_number,
                                                      accountName=str(dets['account_name']))
                return Response({
                    "message": "Account saved successfully",
                    "account details": AccountSerializer(user_account).data
                }, status=status.HTTP_201_CREATED)
            return Response({
                "message": f"request error with error code {response.status_code}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        data = request.data
        if 'code' not in data or not data.get('code'):
            return Response({
                "status": "Bad Request",
                "message": "Bank Code is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            # Validate that 'otp' is present
        if 'account_number' not in data or not data.get('account_number'):
            return Response({
                "status": "Bad Request",
                "message": "Account Number is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        code = data['code']
        account_number = data['account_number']
        user = request.user
        print(code, account_number, user)
        try:
            user_account = Account.objects.get(user=request.user)
            # Resolve Bank Account
            url = "https://api.korapay.com/merchant/api/v1/misc/banks/resolve"
            payload = json.dumps({
                "bank": code,
                "account": account_number
            })
            headers = {
                'Content-Type': 'application/json'
            }
            response = requests.request("POST", url, data=payload, headers=headers)
            print(response.text)
            if response.status_code == 200:
                details = response.json()
                dets = details.get('data')
                user_account.accountNumber = account_number
                user_account.bankCode = code
                user_account.accountName = str(dets['account_name'])
                user_account.save()
                return Response({
                    "message": "Account saved successfully",
                    "account details": AccountSerializer(user_account).data
                }, status=status.HTTP_201_CREATED)
            return Response({
                "message": f"request error with error code {response.status_code}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Account.DoesNotExist:
            return Response({
                "message": "You do not have any account saved"
            }, status=status.HTTP_404_NOT_FOUND)


def kora_payout(amount, bank, account, name, email):
    url = "https://api.korapay.com/merchant/api/v1/transactions/disburse"

    payload = json.dumps({
        "reference": f"pay-{name}-{str(uuid.uuid4())}",
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
    print("payload:", payload)
    print("response:", response.text)
    return response.status_code


class WithdrawWallet(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        if 'amount' not in data or not data.get('amount'):
            return Response({
                "status": "Bad Request",
                "message": "amount is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            # Validate that 'otp' is present
        if 'pin' not in data or not data.get('pin'):
            return Response({
                "status": "Bad Request",
                "message": "Pin is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        amount = data['amount']
        pin = str(data['pin'])
        try:
            wallet = Wallet.objects.get(user=request.user)
            try:
                account = Account.objects.get(user=request.user)
                if bcrypt.checkpw(pin.encode('utf-8'), account.user.pin.encode('utf-8')):
                    if wallet.balance - float(amount) >= 100:
                        payment = kora_payout(str(amount), str(account.bankCode), str(account.accountNumber),
                                              str(request.user.firstName), str(request.user.email))
                        if payment == 200:
                            History.objects.create(
                                wallet=wallet,
                                type='DEBIT',
                                amount=float(amount)
                            )
                            return Response({
                                "message": "Withdrawal Processsed Successfully. You will be credited shortly",
                                "statusCode": 200
                            }, status=status.HTTP_200_OK)
                        return Response({
                            "message": f"Request failed with status code {payment}"
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    return Response({
                        "message": "Insufficient wallet balance",
                        "statusCode": 400
                    }, status=status.HTTP_400_BAD_REQUEST)
                return Response({
                    "message": "Incorrect Transaction Pin"
                }, status=status.HTTP_401_UNAUTHORIZED)
            except Account.DoesNotExist:
                return Response({
                    "message": "Account details not found"
                }, status=status.HTTP_404_NOT_FOUND)
        except Wallet.DoesNotExist:
            return Response({
                "message": "User Wallet not found"
            }, status=status.HTTP_404_NOT_FOUND)


class CreateWallet(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        if 'pin' not in data:
            return Response({
                'message': 'Pin is required to create a wallet',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        if not isinstance(data['pin'], str) or not len(data['pin']) == 4:
            return Response({
                'message': 'Pin is required as a 4-digit string',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        try:
            int(data['pin'])
        except ValueError:
            return Response({
                'message': 'Pin is required as a 4-digit string',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if Wallet.objects.filter(user=request.user).exists():
            return Response({
                'message': 'Wallet already exists',
                'statusCode': 400
            }, status=status.HTTP_400_BAD_REQUEST)
        try:
            encrypted_pin = bcrypt.hashpw(data['pin'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            request.user.pin = encrypted_pin
            request.user.save()
            Wallet.objects.create(user=request.user, balance=0)
            return Response({
                'message': 'Wallet created successfully',
                'statusCode': 201
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        data = request.data
        if 'old_pin' not in data or not data.get('old_pin'):
            return Response({
                "status": "Bad Request",
                "message": "Old pin is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            # Validate that 'otp' is present
        if 'new_pin' not in data or not data.get('new_pin'):
            return Response({
                "status": "Bad Request",
                "message": "New pin is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'confirm' not in data or not data.get('confirm'):
            return Response({
                "status": "Bad Request",
                "message": "Confirm New pin is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        old_pin = data.get('old_pin')
        new_pin = data.get('new_pin')
        confirm = data.get('confirm')
        try:
            user = User.objects.get(email=request.user.email)
        except user.DoesNotExist:
            return Response({
                "message": "You do not have an account with us",
                "statusCode": 401
            }, status=status.HTTP_401_UNAUTHORIZED)
        valid = bcrypt.checkpw(old_pin.encode('utf-8'), user.pin.encode('utf-8'))
        if valid == False:
            return Response({
                "message": "Existing Pin is Wrong",
                "statusCode": 401
            }, status=status.HTTP_401_UNAUTHORIZED)
        if new_pin != confirm:
            return Response({
                "message": "Pins don't match",
                "statusCode": 401
            }, status=status.HTTP_401_UNAUTHORIZED)
        encrypted = bcrypt.hashpw(new_pin.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password = encrypted
        user.save()
        return Response({
            "message": "Pin Successfully Updated",
            "statusCode": 200
        }, status=status.HTTP_200_OK)

    def get(self, request):
        user = request.user
        try:
            wallet = Wallet.objects.get(user=user)
            return Response({
                "message": "Wallet retrieved successfully",
                "wallet": WalletSerializer(wallet).data
            }, status=status.HTTP_200_OK)
        except Wallet.DoesNotExist:
            return Response({
                "message": "Wallet does not exist"
            }, status=status.HTTP_404_NOT_FOUND)


class BankTransferDeposit(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data
        if not data.get('amount'):
            return Response({
                'message': 'Amount is required',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        try:
            float(data['amount'])
        except ValueError:
            return Response({
                'message': 'Amount is required as an integer or float',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        response, status_code = bank_pay(amount=data['amount'], user=user)
        if status_code == 200:
            data = response['data']['bank_account']
            data['statusCode'] = 200
            return Response(data, status=status.HTTP_200_OK)
        else:
            data = response.json()
            data['statusCode'] = response.status_code
            return Response(data, status=response.status_code)

        
class KoraWebhook(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Check if 'X-KORAPAY-SIGNATURE' header exists in the request
        if 'X-KORAPAY-SIGNATURE' not in request.headers:
            return Response({'error': 'Invalid request'}, status=400)
        webhook_signature = request.headers['X-KORAPAY-SIGNATURE']
        payload = json.loads(request.body)
        data_bytes = json.dumps(payload['data'], separators=(',', ':')).encode('utf-8')
        expected_signature = hmac.new(KORA_SECRET.encode('utf-8'), data_bytes, digestmod=hashlib.sha256).hexdigest()
        # Compare signatures to validate the request
        if webhook_signature != expected_signature:
            return Response({'error': 'Invalid signature'}, status=400)
        if History.objects.filter(reference = payload['data']['payment_reference']).exists() or Transaction.objects.filter(reference = payload['data']['payment_reference']).exists():
            return Response({
                'message': 'Transaction is already successful'
            }, status=status.HTTP_200_OK)
        try:
            with transaction.atomic():
                reference =  payload['data']['payment_reference']
                if 'transfer' in reference:
                    sender_id = int(reference.split('-')[1])
                    receiver_id = int(reference.split('-')[2])
                    description = reference.split('-')[3].replace('_', ' ')
                    sender = User.objects.get(id = sender_id)
                    receiver = User.objects.get(id = receiver_id)
                    amount = float(payload['data']['amount'])
                    code = random.randint(1000, 9999)
                    new_transaction = Transaction.objects.create(
                        mode="Kora",
                        sender=sender,
                        receiver=receiver,
                        description=description,
                        amount=float(amount),
                        code=code,
                        reference = reference
                    )
                    print('In!')
                    try:
                        send_mail('A payment has been made!!',
                                  f'{sender.email} just sent you ₦{amount}. \n\nRetrieve code from them to complete transaction',
                                  EMAIL_HOST_USER, [receiver.email], fail_silently=False)
                        send_mail('Your bank account has just been debited',
                                  f'You have just sent the sum of ₦{amount} to {receiver.email}. \n\nOnly give them the code({code}) when you are satisfied with your Purchase.',
                                  EMAIL_HOST_USER, [sender.email], fail_silently=False)
                    except Exception as e:
                        print(e)
                        
                    return Response({
                        "message": "Transaction initiated successfully",
                        "data": TransactionSerializer(new_transaction, context={'request': request}).data
                    }, status=status.HTTP_200_OK)
                else:
                    user_id = payload['data']['payment_reference'].split('-')[1]
                    user = User.objects.get(id=user_id)
                    wallet = Wallet.objects.get(user=user)
                    wallet.balance += float(payload['data']['amount'])
                    wallet.save()
                    History.objects.create(
                        type='CREDIT',
                        wallet=wallet,
                        amount=payload['data']['amount'], 
                        reference = payload['data']['reference']
                    )
                    send_mail('Deposit has been made to your wallet!!',
                            f"The sum of ₦{payload['data']['amount']} has been deposited to your wallet",
                            EMAIL_HOST_USER, [user.email], fail_silently=False)
                return Response({'message': 'Wallet credited successfully', 'amount': float(payload['data']['amount'])}, status=status. HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found'}, status=404)
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=500)

        return Response({'status': 'success'}, status=200)


class Users(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = User.objects.get(id=request.user.id)
            return Response({
                "message": "User retrieved Successfully",
                "data": UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({
                "message": "User not found",
            }, status=status.HTTP_404_NOT_FOUND)


def encryption_charge(encryptionKey, paymentData):
    try:
        iv = Random.get_random_bytes(16)
        encObj = AES.new(encryptionKey.encode("utf8"), AES.MODE_GCM, iv)
        cipherText, authTag = encObj.encrypt_and_digest(paymentData.encode("utf8"))
        iv64 = base64.b64encode(iv).decode('ascii')
        ivToHex = hexa(iv).decode()
        cipherTextToHex = hexa(cipherText).decode()
        authTagToHex = hexa(authTag).decode()
        result = ivToHex + ":" + cipherTextToHex + ":" + authTagToHex
        data = json.dumps({
            'charge_data': result
        })
        response, status_code = charge_card(data)
        return response, status_code

    except Exception as e:
        print(e)


def charge_card(data):
    url = 'https://api.korapay.com/merchant/api/v1/charges/card'

    header = {
        'Authorization': f'Bearer {KORA_SECRET}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url=url, data=data, headers=header)
    print(response.text)

    return response.json(), response.status_code


class CardDeposit(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print('cat')
        data = request.data
        user = request.user
        if 'number' not in data:
            return Response({
                'message': 'Card number is required in "card"',
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'cvv' not in data:
            return Response({
                'message': 'Cvv is required in "card"',
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'expiry_month' not in data:
            return Response({
                'message': 'Expiry month is required in "card"',
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'expiry_year' not in data:
            return Response({
                'message': 'Expiry year is required in "card"',
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        if 'amount' not in data:
            return Response({
                'message': 'Amount is required',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        payload = json.dumps({
            "reference": f"deposit-{user.id}-{str(uuid.uuid4())}",
            "card": {
                "number": data['number'],
                "cvv": data['cvv'],
                "expiry_month": data['expiry_month'],
                "expiry_year": data['expiry_year']
            },
            "amount": data['amount'],
            "currency": "NGN",
            "customer": {
                "name": f'{user.firstName} {user.lastName}',
                "email": user.email
            },
            "redirect_url":"https://trustlink-backend.vercel.app/api/webhook"
        })
        response, status_code = encryption_charge(encryptionKey=os.getenv('ENCRYPTION_KEY'), paymentData=payload)
        if status_code == 200:
            transaction_reference = response['data']['transaction_reference']
            if 'auth_model' not in response['data'] or response['data'].get('auth_model') == 'NO_AUTH':
                return Response(response['data'], status=status_code)
            print(response['data']['auth_model'])
            if response['data']['auth_model'] != 'NO_AUTH':
                if response['data']['auth_model'] == 'PIN':
                    return Response({
                        'transaction_reference': transaction_reference,
                        'message': 'PIN required',
                        'required fields': ['pin']
                    }, status=status.HTTP_200_OK)
                if response['data']['auth_model'] == 'OTP':
                    return Response({
                        'transaction_reference': transaction_reference,
                        'message': 'OTP required',
                        'required fields': ['otp']
                    }, status=status.HTTP_200_OK)
                if response['data']['auth_model'] == '3DS':
                    return Response({
                        'redirect_url': response['data']['redirect_url']
                    }, status=status.HTTP_200_OK)
                if response['data']['auth_model'] == 'AVS':
                    return Response({
                        'transaction_reference': transaction_reference,
                        'message': 'AVS requuired',
                        'Required fields': ['state', 'city', 'country', 'address', 'zip_code']
                    })
        else:
            return Response(response['data'], status=status_code)


class CardAuth(APIView):
    def post(self, request):
        auth_type = request.GET['type'].strip().lower()
        data = request.data
        if 'transaction_reference' not in data:
            return Response({
                'message': 'Transaction reference is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        payload = {'transaction_reference': data['transaction_reference']}

        if auth_type == 'otp':
            if 'otp' not in data:
                return Response({
                    'message': 'OTP is required'
                }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            else:
                try:
                    int(data['otp'])
                except ValueError:
                    return Response({
                        'message': 'OTP is not a numerical value'
                    }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

                payload['authorization'] = {
                    'otp': data['otp']
                }
        elif auth_type == 'pin':
            if 'pin' not in data:
                return Response({
                    'message': 'Pin is required'
                }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            else:
                try:
                    int(data['pin'])
                    payload['authorization'] = {
                        'pin': data['pin']
                    }
                except ValueError:
                    return Response({
                        'message': 'Pin is not a numerical value'
                    }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        elif auth_type == 'AVS':
            if 'state' not in data:
                return Response({
                    'message': 'State must be included in request body',
                }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            if 'city' not in data:
                return Response({
                    'message': 'City must be included in request body',
                }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            if 'country' not in data:
                return Response({
                    'message': 'Country must be included in request body',
                }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            if 'address' not in data:
                return Response({
                    'message': 'Address must be included in request body',
                }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            if 'zip_code' not in data:
                return Response({
                    'message': 'Zip code must be included in request body',
                }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
            payload['authorization'] = {
                'avs': {
                    'state': data['state'],
                    'city': data['city'],
                    'country': data['country'],
                    'address': data['address'],
                    'zip_code': data['zip_code']
                }}
        payload = json.dumps(payload)
        response, status_code = card_auth(payload)
        if status_code == 200:
            return Response(response['data'], status=status.HTTP_200_OK)
        else:
            return Response(response['data'], status=status_code)


def card_auth(data):
    url = 'https://api.korapay.com/merchant/api/v1/charges/card/authorize'
    header = {
        'Authorization': f'Bearer {KORA_SECRET}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url=url, data=data, headers=header)
    print(f'"Json reson"{response.json()}')
    return response.json(), response.status_code


class WalletPayment(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        if 'amount' not in data or not data.get('amount'):
            return Response({
                "status": "Bad Request",
                "message": "amount is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'recipient' not in data or not data.get('recipient'):
            return Response({
                "status": "Bad Request",
                "message": "No recipient indicated"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'pin' not in data or not data.get('pin'):
            return Response({
                "status": "Bad Request",
                "message": "Pin is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        amount = data['amount']
        recipient = data['recipient']
        pin = data['pin']
        description = data['description'] or ''
        try:
            try:
                recipient_user = User.objects.get(Q(email=recipient.lower()) | Q(username=recipient))
                sender_user = User.objects.get(email=request.user.email)
                if recipient_user == sender_user:
                    return Response({
                        "message":"You cannot make a transfer to yourself."
                    }, status=status.HTTP_400_BAD_REQUEST)
                if bcrypt.checkpw(pin.encode('utf-8'), sender_user.pin.encode('utf-8')):
                    if hasattr(sender_user, 'wallet'):
                        if sender_user.wallet.balance - float(amount) >= 100:
                            sender_user.wallet.balance = sender_user.wallet.balance - float(amount)
                            sender_user.wallet.save()
                            code = random.randint(1000, 9999)
                            transaction = Transaction.objects.create(
                                mode="Wallet",
                                sender=sender_user,
                                receiver=recipient_user,
                                description=description,
                                amount=float(amount),
                                code=code
                            )
                            History.objects.create(
                                wallet=sender_user.wallet,
                                type='DEBIT',
                                amount=amount,
                            )
                            send_mail('A payment has been made!!',
                                      f'{sender_user.email} just sent you ₦{amount}. \n\nRetrieve code from them to complete transaction',
                                      EMAIL_HOST_USER, [recipient_user.email], fail_silently=False)
                            send_mail('Your wallet has just been debited',
                                      f'You have just sent the sum of ₦{amount} to {recipient_user.email}. \n\nOnly give them the code({code}) when you are satisfied with your Purchase.',
                                      EMAIL_HOST_USER, [sender_user.email], fail_silently=False)
                            return Response({
                                "message": "Transaction initiated successfully",
                                "data": TransactionSerializer(transaction, context={'request': request}).data
                            }, status=status.HTTP_200_OK)
                        return Response({
                            "message": "Insufficient Balance",
                        }, status=status.HTTP_400_BAD_REQUEST)
                    return Response({
                        "message": "User wallet Not found",
                    }, status=status.HTTP_404_NOT_FOUND)
                return Response({
                    "message": "Incorrect transaction pin",
                }, status=status.HTTP_401_UNAUTHORIZED)
            except User.DoesNotExist:
                return Response({
                    "message": "Recipient Not Found, please confirm recipients details",
                }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error-{str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyPayment(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        data = request.data
        if 'code' not in data or not data.get('code'):
            return Response({
                "status": "Bad Request",
                "message": "Code is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        code = data['code']
        try:
            try:
                transaction = Transaction.objects.get(id=id)
                recipient = User.objects.get(email=request.user.email)
                if transaction.status == 'Pending':
                    if transaction.receiver == recipient:
                        if code == transaction.code:
                            recipient.wallet.balance += transaction.amount
                            recipient.wallet.save()
                            History.objects.create(
                                wallet=recipient.wallet,
                                type='CREDIT',
                                amount=transaction.amount
                            )
                            transaction.status = 'Completed'
                            transaction.save()
                            if transaction.sender != None:
                                send_mail(f'Transaction {transaction.id}-{transaction.date} has been completed!!',
                                          f'Your Wallet has been credited with ₦{transaction.amount}. \n\nThank you for Trusting Trustlink.',
                                          EMAIL_HOST_USER, [recipient.email], fail_silently=False)
                                send_mail(f'Transaction {transaction.id}-{transaction.date} has been completed!!',
                                          f"{recipient.email}'s Wallet has been credited with ₦{transaction.amount}. \n\nThank you for Trusting Trustlink.",
                                          EMAIL_HOST_USER, [transaction.sender.email], fail_silently=False)
                            send_mail(f'Transaction {transaction.id}-{transaction.date} has been completed!!',
                                      f'Your Wallet has been credited with ₦{transaction.amount}. \n\nThank you for Trusting Trustlink.',
                                      EMAIL_HOST_USER, [recipient.email], fail_silently=False)
                            return Response({
                                "message": "Transaction Successful. Your wallet will be credited shortly",
                                "data": TransactionSerializer(transaction, context={'request': request}).data
                            }, status=status.HTTP_200_OK)
                        return Response({
                            "message": "Invalid Verification Code."
                        }, status=status.HTTP_400_BAD_REQUEST)
                    return Response({
                        "message": "You do not have access to verify this transaction."
                    }, status=status.HTTP_401_UNAUTHORIZED)
                return Response({
                    "message": "This Transaction has been resolved."
                }, status=status.HTTP_400_BAD_REQUEST)
            except Transaction.DoesNotExist:
                return Response({
                    "message": f"Transaction with id {id} not found"
                }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error - {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, id):
        try:
            dispute = Transaction.objects.get(id=id)
            return Response({
                "message": "Transaction retrieved successfully",
                "data": TransactionSerializer(dispute, context={'request': request}).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error-{str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DisputeTransaction(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        data = request.data
        if 'reason' not in data or not data.get('reason'):
            return Response({
                "status": "Bad Request",
                "message": "Reason for Dispute is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        reason = data['reason']
        try:
            try:
                transaction = Transaction.objects.get(id=id)
                user = User.objects.get(email=request.user.email)
                if transaction.status == 'Pending':
                    if transaction.sender == user:
                        code = random.randint(1000, 9999)
                        if data.get('proof'):
                            dispute = Dispute.objects.create(
                                transaction=transaction,
                                reason=reason,
                                code=code,
                                evidence=data.get('proof')
                            )
                        else:
                            dispute = Dispute.objects.create(
                                transaction=transaction,
                                reason=reason,
                                code=code,
                            )
                        transaction.status = 'Cancelled'
                        transaction.save()
                        send_mail('Refund Requested!',
                                  f'{user.email} has requested a refund of the sum of ₦{transaction.amount} of transaction {transaction.id}-{transaction.date}. With reason: \n"{dispute.reason}" \n\nShare the code ({code}) with them to approve refund',
                                  EMAIL_HOST_USER, [transaction.receiver.email], fail_silently=False)
                        send_mail('Refund Requested!',
                                  f'Your refund request of transaction {transaction.id}-{transaction.date} has been sent to {transaction.receiver.email}. \n\nRetrieve approval code from them.',
                                  EMAIL_HOST_USER, [user.email], fail_silently=False)
                        return Response({
                            "message": "Refund request successfully sent.",
                            "data": DisputeSerializer(dispute, context={'request':request}).data
                        }, status=status.HTTP_200_OK)
                    return Response({
                        "message": "You cannot request refund as you did not initiate transaction"
                    }, status=status.HTTP_401_UNAUTHORIZED)
                return Response({
                    "message": "Transaction as been resolved."
                }, status=status.HTTP_400_BAD_REQUEST)
            except Transaction.DoesNotExist:
                return Response({
                    "message": f"Transaction with ID {id}does not exist"
                }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error - {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, id):
        data = request.data
        if 'code' not in data or not data.get('code'):
            return Response({
                "status": "Bad Request",
                "message": "Code is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        code = data['code']
        try:
            try:
                dispute = Dispute.objects.get(id=id)
                recipient = User.objects.get(email=request.user.email)
                if dispute.transaction.status == 'Cancelled':
                    if dispute.transaction.sender == recipient:
                        if code == dispute.code:
                            recipient.wallet.balance = + dispute.transaction.amount
                            recipient.wallet.save()
                            dispute.transaction.status = 'Refunded'
                            dispute.transaction.save()
                            dispute.status = "Resolved"
                            dispute.save()
                            History.objects.create(
                                wallet=recipient.wallet,
                                type='CREDIT',
                                amount=dispute.transaction.amount
                            )
                            send_mail(
                                f'Transaction {dispute.transaction.id}-{dispute.transaction.date} Refund Successful!!',
                                f'Your Wallet has been credited with ₦{dispute.transaction.amount}. \n\nThank you for Trusting Trustlink.',
                                EMAIL_HOST_USER, [recipient.email], fail_silently=False)
                            send_mail(
                                f'Transaction {dispute.transaction.id}-{dispute.transaction.date} has been completed!!',
                                f"{recipient.email}'s Wallet has been credited with ₦{dispute.transaction.amount}. \n\nThank you for Trusting Trustlink.",
                                EMAIL_HOST_USER, [dispute.transaction.receiver.email], fail_silently=False)
                            return Response({
                                "message": "Transaction Successful. Your wallet will be credited shortly",
                                "data": TransactionSerializer(dispute.transaction, context={'request': request}).data
                            }, status=status.HTTP_200_OK)
                        return Response({
                            "message": "Invalid Verification Code."
                        }, status=status.HTTP_400_BAD_REQUEST)
                    return Response({
                        "message": "You do not have access to verify this transaction."
                    }, status=status.HTTP_401_UNAUTHORIZED)
                return Response({
                    "message": "This Transaction has been resolved or refund has not been requested."
                }, status=status.HTTP_400_BAD_REQUEST)
            except Transaction.DoesNotExist:
                return Response({
                    "message": f"TDispute with id {id} not found"
                }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error - {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, id):
        try:
            dispute = Dispute.objects.get(id=id)
            return Response({
                "message": "Dispute retrieved successfully",
                "data": DisputeSerializer(dispute, context={"request":request}).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error-{str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AllDispute(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            print(request.user)
            disputes = Dispute.objects.filter(Q(transaction__sender=request.user) | Q(transaction__receiver=request.user))
            return Response({
                "message":"All disputes retrieved successfully",
                "data":DisputeSerializer(disputes, many=True, context={'request':request}).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message":str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class OutgoingHistory(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = User.objects.get(email=request.user.email)
            transactions = user.sent_transactions.all()
            status_query = request.query_params.get('status')
            if status_query:
                transactions = transactions.filter(status=status_query)
            return Response({
                "message": "Transactions retrieved successfully",
                "data": TransactionSerializer(transactions, many=True, context={'request': request}).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error - {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class IncomingHistory(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = User.objects.get(email=request.user.email)
            transactions = user.received_transactions.all()
            status_query = request.query_params.get('status')
            if status_query:
                transactions = transactions.filter(status=status_query)
            return Response({
                "message": "Transactions retrieved successfully",
                "data": TransactionSerializer(transactions, many=True, context={'request': request}).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error - {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WalletHistory(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        try:
            wallet = Wallet.objects.get(user=user)
            return Response({
                "message": "Wallet History retrieved successfully",
                "data": HistorySerializer(wallet.history, many=True).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "messsage": str(e),

            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SpecificHistory(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        try:
            history = History.objects.get(id=id)
            return Response({
                "message": "Record retrieved successfully",
                "data": HistorySerializer(history).data
            }, status=status.HTTP_200_OK)
        except History.DoesNotExist as e:
            return Response({
                "message": str(e)
            }, status=status.HTTP_404_NOT_FOUND)


class GeneralTransaction(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        try:
            transactions = Transaction.objects.filter(Q(sender=user) | Q(receiver=user))
            return Response({
                "message": "Transactions retrieved successfully",
                "data": TransactionSerializer(transactions, many=True, context={'request': request}).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def checkout(amount, narration, customer_name, customer_email, id):
    url = "https://api.korapay.com/merchant/api/v1/charges/initialize"

    payload = json.dumps({
        "amount": str(amount),
        "redirect_url": "https://trustlink-backend.vercel.app/api/checkout",
        "currency": "NGN",
        "reference": f"{str(uuid.uuid4())}",
        "narration": narration,
        "channels": [
            "card",
            "bank_transfer"
        ],
        "default_channel": "card",
        "customer": {
            "name": customer_name,
            "email": customer_email
        },
        "notification_url": "https://webhook.site/8d321d8d-397f-4bab-bf4d-7e9ae3afbd50",
        "metadata": {
            "user_id": id
        }
    })
    headers = {
        "Authorization": f"Bearer {os.getenv('KORA_SECRET')}",
        "Content-Type": "application/json"
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    result = response.json()

    return result


class GeneratePayment(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        if 'amount' not in data or not data.get('amount'):
            return Response({
                "status": "Bad Request",
                "message": "amount is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'customer_name' not in data or not data.get('customer_name'):
            return Response({
                "status": "Bad Request",
                "message": "No customer name indicated"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'customer_email' not in data or not data.get('customer_email'):
            return Response({
                "status": "Bad Request",
                "message": "Customer email required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'narration' not in data or not data.get('narration'):
            return Response({
                "status": "Bad Request",
                "message": "narration is required"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        amount = data['amount']
        customer_name = data['customer_name']
        customer_email = data['customer_email']
        narration = data['narration']
        response = checkout(amount, narration, customer_name, customer_email, str(request.user.id))
        if response['status'] == True:
            return Response({
                "message": "Link created successfully",
                "data": response['data'].get('checkout_url')
            }, status=status.HTTP_200_OK)
        return Response({
            "message": str(response['message']),
            "data": response['data']
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaymentRedirectAPIView(APIView):
    def get(self, request):
        reference = request.GET.get('reference')
        if not reference:
            return Response({
                "status": "error",
                "message": "Transaction reference not provided"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Call KoraPay API to verify transaction status using the reference
        url = f"https://api.korapay.com/merchant/api/v1/charges/{reference}"
        headers = {
            "Authorization": f"Bearer {os.getenv('KORA_SECRET')}"
        }

        try:
            response = requests.get(url, headers=headers)
            transaction_data = response.json()
            if transaction_data['data'].get('status') == "success":
                id = int(transaction_data['data']['metadata'].get('user_id'))
                user = User.objects.get(pk=id)
                try:
                    code = random.randint(1000, 9999)
                    transaction = Transaction.objects.create(
                        mode="Kora",
                        receiver=user,
                        description=transaction_data['data'].get('description'),
                        amount=float(transaction_data['data'].get('amount_paid')),
                        code=code
                    )
                    send_mail('A payment has been made!!',
                              f'{transaction_data["data"]["customer"].get("name")} just sent you ₦{transaction_data["data"].get("amount_paid")}. \n\nRetrieve code from them to complete transaction',
                              EMAIL_HOST_USER, [user.email], fail_silently=False)
                    send_mail('Payment Successful',
                              f'You have just sent the sum of ₦{transaction_data["data"].get("amount_paid")} to {user.email}. \n\nOnly give them the code({code}) when you are satisfied with your Purchase.',
                              EMAIL_HOST_USER, [transaction_data["data"]["customer"].get("email")], fail_silently=False)
                    return Response({
                        "message": "Transaction initiated successfully",
                        "data": TransactionSerializer(transaction, context={"request": request}).data
                    }, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response({
                        "status": "error",
                        "message": f"An error occurred: {str(e)}"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                # Return transaction failure details
                return Response({
                    "status": "failed",
                    "message": "Transaction failed or incomplete",
                    "transaction": transaction_data
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "status": "error",
                "message": f"An error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



def bank_pay(amount, user, metadata=None):
    url = 'https://api.korapay.com/merchant/api/v1/charges/bank-transfer'
    payload = {
        "reference": f"deposit-{user.id}-{str(uuid.uuid4())}",
        "amount": f'{amount}',
        "currency": "NGN",
        "customer": {
            'name': f'{user.firstName} {user.lastName}',
            "email": f'{user.email}'
        },
    }
    if metadata:
        payload['reference'] = f"transfer-{metadata['sender_id']}-{metadata['receiver_id']}-{metadata['description'].replace(' ', '_')}-{str(uuid.uuid4())[:6]}"
    print(payload['reference'])
    payload = json.dumps(payload)
    headers = {
        'Authorization': f'Bearer {KORA_SECRET}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url=url, data=payload, headers=headers)
    return response.json(), response.status_code

class TransferPayment(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        data = request.data
        if not data.get('amount'):
            return Response({
                'message': 'Amount is required',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'recipient' not in data:
            return Response({
                "status": "Bad Request",
                "message": "No recipient indicated"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        
        if not User.objects.filter(username = data['recipient'].lower()).exists() and not User.objects.filter(email = data['recipient'].lower()).exists():
            return Response({
                    "message": "Recipient Not Found, please confirm recipients details",
                }, status=status.HTTP_404_NOT_FOUND)
        recipient = data['recipient']
        recipient_user = User.objects.get(Q(email=recipient.lower()) | Q(username=recipient))
        if recipient_user == user:
            return Response({'message': 'You can only transfer to other accounts'}, status=status.HTTP_400_BAD_REQUEST)
        if not hasattr(recipient_user, 'wallet'):
            return Response({
                'message': 'Recipient wallet not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        try:
            float(data['amount'])
        except ValueError:
            return Response({
                'message': 'Amount is required as an integer or float',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        
        metadata = {
            'sender_id': user.id,
            'receiver_id':recipient_user.id,
        }
        if data.get('description') is not None: 
            description = data.get('description')
            metadata['description'] = description
        
        print(metadata)
        response, status_code = bank_pay(amount=data['amount'], user=user, metadata=metadata)
        print(response)
        if status_code == 200:
            data = response['data']['bank_account']
            data['statusCode'] = 200
            return Response(data, status=status.HTTP_200_OK)
        else:
            data = response['data']
            data['statusCode'] = status_code
            return Response(data, status=status_code)
        
class CardPayment(APIView):
    def post(self, request):
        print('cat')
        data = request.data
        user = request.user
        if 'number' not in data:
            return Response({
                'message': 'Card number is required in "card"',
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'cvv' not in data:
            return Response({
                'message': 'Cvv is required in "card"',
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'expiry_month' not in data:
            return Response({
                'message': 'Expiry month is required in "card"',
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if 'expiry_year' not in data:
            return Response({
                'message': 'Expiry year is required in "card"',
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        if 'amount' not in data:
            return Response({
                'message': 'Amount is required',
                'statusCode': 422
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        
        if 'recipient' not in data:
            return Response({
                "status": "Bad Request",
                "message": "No recipient indicated"
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        
        if not User.objects.filter(username = data['recipient'].lower()).exists() and not User.objects.filter(email = data['recipient'].lower()).exists():
            return Response({
                    "message": "Recipient Not Found, please confirm recipients details",
                }, status=status.HTTP_404_NOT_FOUND)
        recipient = data['recipient']
        recipient_user = User.objects.get(Q(email=recipient.lower()) | Q(username=recipient))
        if False:#recipient_user == user:
            return Response({'message': 'You can only transfer to other accounts'}, status=status.HTTP_400_BAD_REQUEST)
        if not hasattr(recipient_user, 'wallet'):
            return Response({
                'message': 'Recipient wallet not found'
            }, status=status.HTTP_404_NOT_FOUND)
        metadata = {
            'sender_id': user.id,
            'receiver_id':recipient_user.id,
        }

        metadata['description'] = data.get('description', 'Payment')

        payload = json.dumps({
            "reference": f"transfer-{metadata['sender_id']}-{metadata['receiver_id']}-{metadata['description'].replace(' ', '_')}-{str(uuid.uuid4())[:6]}",
            "card": {
                "number": data['number'],
                "cvv": data['cvv'],
                "expiry_month": data['expiry_month'],
                "expiry_year": data['expiry_year']
            },
            "amount": data['amount'],
            "currency": "NGN",
            "customer": {
                "name": f'{user.firstName} {user.lastName}',
                "email": user.email
            },
            "redirect_url":"https://trustlink-backend.vercel.app/api/webhook",
            'metadata': metadata
        })
        response, status_code = encryption_charge(encryptionKey=os.getenv('ENCRYPTION_KEY'), paymentData=payload)
        
        if status_code == 200:
            transaction_reference = response['data']['transaction_reference']
            if 'auth_model' not in response['data'] or response['data'].get('auth_model') == 'NO_AUTH':
                return Response(response['data'], status=status_code)
         
            if response['data']['auth_model'] != 'NO_AUTH':
                if response['data']['auth_model'] == 'PIN':
                    return Response({
                        'transaction_reference': transaction_reference,
                        'message': 'PIN required',
                        'required fields': ['pin']
                    }, status=status.HTTP_200_OK)
                if response['data']['auth_model'] == 'OTP':
                    return Response({
                        'transaction_reference': transaction_reference,
                        'message': 'OTP required',
                        'required fields': ['otp']
                    }, status=status.HTTP_200_OK)
                if response['data']['auth_model'] == '3DS':
                    return Response({
                        'redirect_url': response['data']['redirect_url']
                    }, status=status.HTTP_200_OK)
                if response['data']['auth_model'] == 'AVS':
                    return Response({
                        'transaction_reference': transaction_reference,
                        'message': 'AVS requuired',
                        'Required fields': ['state', 'city', 'country', 'address', 'zip_code']
                    })
        else:
            return Response(response['data'], status=status_code)
