from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
import re
from django.contrib import messages



class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def authenticate_user(self, email, password):
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                return user
            else:
                # messages.error(request, "Incorrect password.")
                raise serializers.ValidationError('Incorrect password.')
        except User.DoesNotExist:
            raise serializers.ValidationError('User with this email does not exist.')


    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = self.authenticate_user(email, password)

        if user:
            data['user'] = user
        else:
            raise serializers.ValidationError('Invalid email or password')

        return data



class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    # name = serializers.CharField(style={'input_type': 'first_name'}, write_only=True) 
    
    
    class Meta:
        model = User
        fields = ['first_name','last_name', 'email',  'password', 'password2']
        extra_kwargs = {
            'password' : {'write_only': True}
        }
        
    
    def validate_password(self, password):
        if len(password) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters long.')
        
        if not re.search(r'[a-zA-Z]', password):
            raise serializers.ValidationError('Password must contain at least one alphabet.')
        
        if not re.search(r'\d', password):
            raise serializers.ValidationError('Password must contain at least one digit.')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise serializers.ValidationError('Password must contain at least one special character.')
        
        return password
    
    def create(self, validated_data):
        # username = validated_data['username']
        email = validated_data['email']

        # if User.objects.filter(username=username).exists():
        #     raise ValidationError({'username': ['User with this username already exists.']})

        if User.objects.filter(username=email).exists():
            raise ValidationError({'email': ['User with this email already exists.']})
        
        if User.objects.filter(email=email).exists():
            raise ValidationError({'email': ['User with this email already exists.']})

        user = User.objects.create(
            username=email,
            email=email,
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    



