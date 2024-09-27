from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['firstName','lastName','email','phone', 'username']

class TransactionSerializer(serializers.ModelSerializer):
    sender = UserSerializer()
    receiver = UserSerializer()
    type = serializers.SerializerMethodField()
    class Meta:
        model = Transaction
        fields = ['id','mode','sender','receiver','amount','description','date','status', 'type']

    def get_type(self, obj):
        request = self.context.get('request')  # Get the current user from the context
        user = request.user
        if obj.sender == user:
            return "DEBIT"
        elif obj.receiver == user:
            return "CREDIT"
        return None

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
        fields = ['id','transaction', 'reason', 'evidence']

class HistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = History
        fields = '__all__'