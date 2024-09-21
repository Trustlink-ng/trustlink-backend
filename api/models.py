from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser):
    firstName = models.CharField(max_length=255)
    lastName = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=12, blank=True, null=True)
    username = models.CharField(max_length=25, unique=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True, null=True)
    pin = models.CharField(max_length=256, null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = ('email')
    REQUIRED_FIELDS = ['firstName', 'lastName']

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"{self.firstName} {self.lastName}"

    def get_short_name(self):
        return self.firstName

    def has_perm(self, perm, obj=None):
        return self.is_superuser or super().has_perm(perm, obj)

    def has_module_perms(self, app_label):
        return self.is_superuser

class UserOTP(models.Model):
    user = models.ForeignKey(User, on_delete = models.CASCADE)
    otp = models.CharField(max_length=7, null=True)
    otp_created_at = models.DateTimeField(auto_now_add=True, null=True)

class Account(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='account')
    bankCode = models.CharField(max_length=255)
    accountNumber = models.CharField(max_length=255)
    accountName = models.CharField(max_length=255)

    def __str__(self):
        return self.accountName
class Transaction(models.Model):
    MODE_CHOICES = [
        ('Kora', 'Kora'),
        ('Wallet', 'Wallet'),
    ]

    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Completed', 'Completed'),
        ('Cancelled', 'Cancelled'),
        ('Refunded', 'Refunded'),
    ]

    mode = models.CharField(max_length=10, choices=MODE_CHOICES)
    sender = models.ForeignKey(User, related_name='sent_transactions', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_transactions', on_delete=models.CASCADE)
    description = models.CharField(max_length=255)
    amount = models.FloatField()
    date = models.DateTimeField(auto_now_add=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')
    code = models.CharField(max_length=5)

    def __str__(self):
        return f"{self.sender.email} to {self.receiver.email} on {self.date}"

class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    balance = models.FloatField()

    def __str__(self):
        return self.user.username

class History(models.Model):
    TYPE = [
        ('CREDIT', 'CREDIT'),
        ("DEBIT", "DEBIT")
    ]
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='history')
    type = models.CharField(max_length=7, choices=TYPE)
    amount = models.FloatField()
    date = models.DateTimeField(auto_now_add=True, null=True)

class Banks(models.Model):
    name = models.CharField(max_length=255)
    slug = models.CharField(max_length=255)
    code = models.CharField(max_length=20)

    def __str__(self):
        return self.name

class Dispute(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Resolved', 'Resolved'),
    ]
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, related_name='refund')
    reason = models.CharField(max_length=300, null=True, blank=True)
    evidence = models.ImageField(upload_to='images/', blank=True, null=True)
    code= models.CharField(max_length=6)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')

    def __str__(self):
        return f"{self.transaction.sender} to {self.transaction.receiver}"






