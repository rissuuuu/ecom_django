from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.db.models import JSONField
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_enum_choices.fields import EnumChoiceField
from django_lifecycle import hook

from cura.apps.models import App
from cura.core.enums import UserStatusEnum
from cura.core.models import BaseModel
from cura.utils.date_utils import time_diff_min


class ActiveUserManager(BaseUserManager):
    def get_queryset(self):
        return super(ActiveUserManager, self).get_queryset().using(self._db).filter(deleted_date__isnull=True)

    def _create_user(self, username, password, **extra_fields):
        if not username:
            raise ValueError("The given username must be set")
        username = self.model.normalize_username(username)
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))

        return self._create_user(username, password, **extra_fields)


class InactiveUserManager(BaseUserManager):
    def get_queryset(self):
        return super(InactiveUserManager, self).get_queryset().using(self._db).filter(deleted_date__isnull=False)


class AllUserManager(BaseUserManager):
    def get_queryset(self):
        return super(AllUserManager, self).get_queryset().using(self._db).all()


class User(AbstractBaseUser, BaseModel, PermissionsMixin):
    username = models.CharField(verbose_name="Username", max_length=200, unique=True)
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the users can log into this admin site."),
    )
    is_superuser = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the users can log into this admin site."),
    )
    first_login = models.DateTimeField(null=True)
    salt = models.CharField(null=True, max_length=100)  # Remove null=True
    status = EnumChoiceField(UserStatusEnum, default=UserStatusEnum.LOGGED_IN)

    disable_notification = models.BooleanField(default=False)

    # Presence Indicates trial Users
    trial_expiry_date = models.DateField(null=True)

    USERNAME_FIELD = "username"

    objects = None
    active_objects = ActiveUserManager()
    inactive_objects = InactiveUserManager()
    all_objects = AllUserManager()

    @hook("after_create")
    def create_user_otp(self):
        UserOtp.active_objects.get_or_create(user=self)

    def validate_otp(self, otp):
        if self.user_otp and self.user_otp.otp_senttime:
            if time_diff_min(timezone.now(), self.user_otp.otp_senttime) < 10:
                return check_password(otp, self.user_otp.otp)
            else:
                return False
        else:
            return False

    @property
    def is_customer(self):
        return self.groups.filter(name="CUSTOMER").exists()

    @property
    def is_seller(self):
        return self.groups.filter(name="SELLER").exists()

    @property
    def is_dealer(self):
        return self.groups.filter(name="DEALER").exists()

    @property
    def to_json(self):
        return {
            "is_staff": self.is_staff,
            "username": self.username,
        }

    class Meta:
        app_label = "users"
        db_table = "ecom_user"


class UserOtp(BaseModel):
    user = models.OneToOneField(User, null=True, on_delete=models.PROTECT, related_name="user_otp")
    country_code = models.CharField(_("Country Code"), max_length=10, default="+91")
    # Used primarily for trial signup otp, where users are not created
    mobile_number = models.CharField(
        _("Mobile Number"),
        max_length=64,
        null=True,
    )

    otp = models.CharField(max_length=128, null=True)
    otp_senttime = models.DateTimeField(null=True)

    class Meta:
        app_label = "users"
        db_table = "ecom_user_otp"
