from django.contrib.auth.models import User
from django.db import models


# Create your models here.
class Permission(models.Model):
    name = models.CharField(max_length=100)


class UserTmp(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    permissions = models.ForeignKey(Permission, blank=True, on_delete=models.SET_NULL, null=True)


class Role(models.Model):
    name = models.CharField(max_length=100)
    permissions = models.ManyToManyField(Permission)


class Suspect(models.Model):
    users = models.ForeignKey(UserTmp, on_delete=models.SET_NULL, blank=True, null=True)
    name = models.CharField(max_length=100)
    files = models.FileField(upload_to='assets')
