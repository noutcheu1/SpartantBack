from rest_framework.serializers import Serializer, ModelSerializer
from rest_framework import fields, serializers
from .models import (UserTmp, Permission, Role, Suspect)
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token


class SetPasswordSerializers(Serializer):
    """
    Description: Model Description
    """

    email = fields.CharField(write_only=True, required=True)

    class Meta:
        pass


class SetpassSerializers(Serializer):
    """
    Description: Model Description
    """
    old_password = fields.CharField(write_only=True, required=True)
    newpassword = fields.CharField(write_only=True, required=True)


class LoginSerializer(Serializer):
    """
    Description: Model Description
    """
    email = fields.CharField()
    password = fields.CharField(write_only=True, required=True)
    token = fields.SerializerMethodField()

    def get_token(self, instance: User):
        return Token.objects.get(user=instance).key

    class Meta:
        extra_kwargs = {'password': {"write_only": True}}


class UserSerializer(ModelSerializer):
    """
    Description: Model Description
    """

    password = fields.CharField(write_only=True)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    def update(self, instance: User, validated_data):
        validated_data.pop('password')

        for key, value in validated_data.items():
            setattr(instance, key, value)

            instance.save()

        return instance

    class Meta:
        model = User

        fields = ('id', 'username', 'password', 'first_name', 'email',)
        extra_kwargs = {'password': {"write_only": True}}


class UserTmpSerializer(ModelSerializer):
    """
    Description: Model Description
    """

    def create(self, validated_data):
        return UserTmp.objects.create(**validated_data)

    def update(self, instance: UserTmp, validated_data):
        validated_data.pop('user')

        for key, value in validated_data.items():
            setattr(instance, key, value)

            instance.save()

    class Meta:
        model = UserTmp
        fields = ('id', 'user', 'permissions')


class LogoutSerializer(Serializer):
    """
    Description: Model Description
    """
    message = fields.CharField(write_only=True)

    class Meta:
        pass


class UsersSerializer(Serializer):
    """
    Description: Model Description
    """
    user_id = fields.IntegerField(required=True)
    username = fields.CharField(required=True)

    class Meta:
        pass

