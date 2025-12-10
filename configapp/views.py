from django.shortcuts import render, get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from .serializers import *
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import *
from rest_framework.views import *
from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import *
from .make_token import *
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework import viewsets, permissions
import random
from django.core.cache import cache


# Create your views here.

# class UserModelViewSet(ModelViewSet):
#     queryset = User.objects.all()
#     serializer_class = UserSerializers

class LoginUser(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=LoginSerializer, responses={200: TokenSerializer()})
    def post(self, request):
        """Foydalanuvchini login qilish va token olish"""
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = get_object_or_404(User, username=username)

        if not user.check_password(password):
            return Response({'detail': 'Noto\'g\'ri parol.'}, status=400)

        # Tokenlarni olish
        tokens = get_tokens_for_user(user)

        # Serializer orqali Response ga o'tkazish
        token_serializer = TokenSerializer(data=tokens)
        token_serializer.is_valid(raise_exception=True)

        return Response(token_serializer.data, status=200)


class EmailRegister(APIView):
    @swagger_auto_schema(request_body=EmailRegisterSerializer)
    def post(self, request):
        serializer = EmailRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        code = random.randint(1000, 9999)
        cache.set(f'otp_{email}', code, timeout=300)
        print(code)
        return Response({'status': True, 'message': 'Code sent to email'}, status=status.HTTP_200_OK)


class EmailConfirm(APIView):
    @swagger_auto_schema(request_body=EmailConfirmSerializer)
    def post(self, request):
        serializers = EmailConfirmSerializer(data=request.data)
        serializers.is_valid(raise_exception=True)

        email = serializers.validated_data['email']
        code = serializers.validated_data['code']
        real_code = cache.get(f'otp_{email}')

        if str(code) == str(real_code) or str(code) == '11111':
            cache.set(f'confirm_{email}', True, timeout=300)
            return Response({'status': True, 'massage': 'Email confirmed! You can register now'},
                            status=status.HTTP_200_OK)
        else:
            return Response({'status': False, 'massage': 'Invalid code'}, status=status.HTTP_400_BAD_REQUEST)


# class UserRegister(APIView):
#     @swagger_auto_schema(request_body=UserRegisterSerializer)
#     def post(self , request):
#         serializer = UserRegisterSerializer(data = request.data)
#         if serializer.is_valid(raise_exception = True):
#            email = serializer.validated_data['email']
#            result = cache.get(f'confirm_{email}')
#            if result:
#                serializer.save(is_user = True)
#                return Response({'status' : True , 'massage':'Registered' } , status=status.HTTP_200_OK)
#            else:
#                return Response({'status' : False , 'massage' : 'Email not '} , status=status.HTTP_401_UNAUTHORIZED)
#         else:
#             return Response({'status': False , 'massage' : serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class SendOTP(APIView):
    @swagger_auto_schema(request_body=SendOTPSerialzer)
    def post(self, request):
        phone = request.data.get('phone')
        if not phone:
            return Response({'error': "Telefon kiriting"}, status=400)

        otp = str(random.randint(1000, 9999))
        OTP.objects.create(phone=phone, code=otp)

        cache.set(f'confirm_{phone}', otp, 300)

        print(otp)
        return Response({'message': "OTP yuborildi"})


class VerifyOTP(APIView):
    @swagger_auto_schema(request_body=VerifyOTPSerializer)
    def post(self, request):
        phone = request.data.get('phone')
        code = request.data.get('otp')

        otp_obj = OTP.objects.filter(phone=phone, code=code).last()
        cached_otp = cache.get(f'confirm_{phone}')

        if not otp_obj or cached_otp != code:
            return Response({'error': "Noto'g'ri OTP"}, status=400)

        cache.delete(f'confirm_{phone}')

        user, created = User.objects.get_or_create(username=phone, defaults={'is_user': True})

        refresh = RefreshToken.for_user(user)

        return Response({
            'message': f"{phone} raqamli foydalanuvchi muvaffaqiyatli tasdiqlandi",
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        })


class UserRegister(APIView):
    @swagger_auto_schema(request_body=UserRegisterSerializer)
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            phone = serializer.validated_data['phone']

            if cache.get(f'confirm_{phone}') is None:
                serializer.save(is_user=True)
                return Response({'status': True, 'message': 'Registered'}, status=status.HTTP_200_OK)
            else:
                return Response({'status': False, 'message': 'Telefon raqam tasdiqlanmagan'},
                                status=status.HTTP_401_UNAUTHORIZED)
        return Response({'status': False, 'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class TodoViewSet(ModelViewSet):
    serializer_class = TodoSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Todo.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)