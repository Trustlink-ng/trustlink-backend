from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['firstName','lastName','email','phone', 'username']

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['id','mode','sender','receiver','amount','description','date','status']

class BankSerializer(serializers.ModelSerializer):
    class Meta:
        model = Banks
        fields = '__all__'

class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = '__all__'

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = "__all__"
class DisputeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dispute
        fields = ['transaction', 'reason', 'evidence']