from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from ecom.users.models import User


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm):
        model = User
        fields = ("username",)


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ("username",)
