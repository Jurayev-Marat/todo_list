from .models import *
from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from django.contrib.auth import authenticate


# class UserSerializers(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['username' , 'email' , 'password' , 'phone']
#         read_only_fields = ['is_admin' , 'is_staff' , 'is_active']

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                {
                    'success': False,
                    'delail': "User does not exist"
                }
            )

        auth_user = authenticate(username=user.username, password=password)
        if auth_user is None:
            raise serializers.ValidationError(
                {
                    'success': False,
                    'detail': "Username or password is invalid"
                }
            )

        attrs['user'] = auth_user
        return attrs


class TokenSerializer(serializers.Serializer):
    access = serializers.CharField()
    refresh = serializers.CharField()


class EmailRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Bu email allaqachon bor!")
        return value


class EmailConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.IntegerField()


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user


class SendOTPSerialzer(serializers.Serializer):
    phone = serializers.CharField()


class VerifyOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()
    otp = serializers.CharField()


class TodoSerializer(serializers.ModelSerializer):
    user_phone = serializers.CharField(source='user.username',
                                       read_only=True)  # telefon raqami username sifatida saqlangan

    class Meta:
        model = Todo
        fields = ['id', 'title', 'completed', 'user', 'user_phone']
        read_only_fields = ['user']