import json
import os
import uuid
from django.http import JsonResponse
from dotenv import load_dotenv
import bcrypt
import requests
from django.core.mail import send_mail
from django.core.validators import validate_email
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
import datetime
from django.utils import timezone
from django.core.exceptions import ValidationError
import random
from .serializers import *
from trustlink.settings import EMAIL_HOST_USER, KORA_SECRET

load_dotenv()
from django.db.models import Q
from .models import *

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
                                       email=data.get('email').lower(), username=data.get('username'), password=encrypted,
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
        reset_url = f"{protocol}://{domain}/auth/complete-reset?token={token}"

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

class CreateAccount(APIView):
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

    permission_classes = [IsAuthenticated]

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
        pin = data['amount']
        try:
            wallet = Wallet.objects.get(user=request.user)
            try:
                account = Account.objects.get(user=request.user)
                if bcrypt.checkpw(pin.encode('utf-8'), account.user.pin.encode('utf-8')):
                    if wallet.balance - float(amount) >= 100:
                        payment = kora_payout(str(amount), str(account.bankCode), str(account.accountNumber),
                                              str(request.user.firstName), str(request.user.email))
                        if payment == 200:
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
        url = 'https://api.korapay.com/merchant/api/v1/charges/bank-transfer'
        payload = json.dumps({
            "reference": f"deposit-{user.id}-{str(uuid.uuid4())}",  # unique reference for each deposit
            "amount": data['amount'],
            "currency": "NGN",
            "customer": {
                'name': f'{user.firstName} {user.lastName}',
                "email": f'{user.email}'
            },
            # 'notification_url' : '' #webhook kora calls on success
        })
        headers = {
            'Authorization': f'Bearer {KORA_SECRET}',
            'Content-Type': 'application/json'
        }
        response = requests.post(url=url, data=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()['data']['bank_account']
            data['statusCode'] = 200
            return Response(data, status=status.HTTP_200_OK)
        else:
            data = response.json()
            data['statusCode'] = response.status_code
            return Response(data, status=response.status_code)

class KoraWebhook(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Check if the request is a POST
        if 'HTTP_X_KORAPAY_SIGNATURE' not in request.headers:
            return Response({'error': 'Invalid request'}, status=400)

        # Get the request body and signature
        request_body = json.loads(request.body)
        webhook_signature = request.headers['HTTP_X_KORAPAY_SIGNATURE']

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
        description = data['description']or''
        try:
            try:
                recipient_user = User.objects.get(Q(email=recipient.lower()) | Q(username=recipient))
                sender_user = User.objects.get(email=request.user.email)
                if bcrypt.checkpw(pin.encode('utf-8'), sender_user.pin.encode('utf-8')):
                    if hasattr(sender_user, 'wallet'):
                        if sender_user.wallet.balance - float(amount) >= 100:
                            sender_user.wallet.balance = sender_user.wallet.balance - float(amount)
                            sender_user.wallet.save()
                            code = random.randint(1000, 9999)
                            transaction = Transaction.objects.create(
                                mode="Wallet",
                                sender = sender_user,
                                receiver= recipient_user,
                                description = description,
                                amount = float(amount),
                                code = code
                            )
                            send_mail('A payment has been made!!',
                                      f'{sender_user.email} just sent you ₦{amount}. \n\nRetrieve code from them to complete transaction',
                                      EMAIL_HOST_USER, [recipient_user.email], fail_silently=False)
                            send_mail('Your wallet has just been debited',
                                      f'You have just sent the sum of ₦{amount} to {recipient_user.email}. \n\nOnly give them the code({code}) when you are satisfied with your Purchase.',
                                      EMAIL_HOST_USER, [sender_user.email], fail_silently=False)
                            return Response({
                                "message":"Transaction initiated successfully",
                                "data":TransactionSerializer(transaction).data
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
                "message":f"Internal Server Error-{str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyPayment(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request,id):
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
                            recipient.wallet.balance =+ transaction.amount
                            recipient.wallet.save()
                            transaction.status = 'Completed'
                            transaction.save()
                            send_mail(f'Transaction {transaction.id}{transaction.date} has been completed!!',
                                      f'Your Wallet has been credited with ₦{transaction.amount}. \n\nThank you for Trusting Trustlink.',
                                      EMAIL_HOST_USER, [recipient.email], fail_silently=False)
                            send_mail(f'Transaction {transaction.id}{transaction.date} has been completed!!',
                                      f"{recipient.email}'s Wallet has been credited with ₦{transaction.amount}. \n\nThank you for Trusting Trustlink.",
                                      EMAIL_HOST_USER, [recipient.email], fail_silently=False)
                            return Response({
                                "message":"Transaction Successful. Your wallet will be credited shortly",
                                "data":TransactionSerializer(transaction).data
                            }, status=status.HTTP_200_OK)
                        return Response({
                            "message":"Invalid Verification Code."
                        }, status=status.HTTP_400_BAD_REQUEST)
                    return Response({
                        "message": "You do not have access to verify this transaction."
                    }, status=status.HTTP_401_UNAUTHORIZED)
                return Response({
                    "message":"This Transaction has been resolved."
                }, status=status.HTTP_400_BAD_REQUEST)
            except Transaction.DoesNotExist:
                return Response({
                    "message": f"Transaction with id {id} not found"
                }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "message": f"Internal Server Error - {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




