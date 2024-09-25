from django.urls import path
from .views import *

urlpatterns = [
    path('auth/register', RegisterView.as_view(), name="Register"),
    path('auth/verify-email', VerifyMail.as_view(), name='verify-mail'),
    path('auth/login', LoginView.as_view(), name="user-login"),
    path('auth/resend-otp', SendOTP.as_view(), name="resend-otp"),
    path('auth/change-password', ChangePassword.as_view(), name="change-password"),
    path('auth/reset-password', BeginForgotPassword.as_view(), name='begin-reset'),
    path('auth/complete-reset', CompleteReset.as_view(), name='complete-reset'),
    path('store-banks', store_banks),
    path('api/account', CreateAccount.as_view(), name="create"),
    path('api/wallet', CreateWallet.as_view(), name='create-wallet'),
    path('api/deposit/transfer', BankTransferDeposit.as_view()),
    path('api/withdraw', WithdrawWallet.as_view(), name='withdrawal'),
    path('api/me', Users.as_view(), name="user"),
    path('api/wallet/pay', WalletPayment.as_view(), name='pay-with-wallet'),
    path('api/verify-transaction/<int:id>', VerifyPayment.as_view(), name="verify-payment"),
    path('api/dispute-transaction/<int:id>', DisputeTransaction.as_view(), name="dispute-transaction"),
    path('api/outgoing/trans', OutgoingHistory.as_view(), name='outgoing-history'),
    path('api/incoming/trans', IncomingHistory.as_view(), name='incoming-history'),
    path('api/wallet/history', WalletHistory.as_view(), name='wallet-history'),
    path('api/history/<int:id>', SpecificHistory.as_view(), name='specific-history'),
    path('api/trans/history', GeneralTransaction.as_view(), name='general=transaction'),
    path('api/generate', GeneratePayment.as_view(), name="generate-payment"),
    path('api/checkout', PaymentRedirectAPIView.as_view(), name="payment-redirect")
]
