from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(User)
admin.site.register(Wallet)
admin.site.register(Account)
admin.site.register(Transaction)
admin.site.register(History)
admin.site.register(Banks)