from django.shortcuts import render, redirect
from django.contrib import messages
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import RegistrationSerializer, LoginSerializer
from rest_framework import status
from datetime import datetime
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework import permissions
from openai import OpenAI
import json
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from rest_framework.decorators import api_view
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import time
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sessions.models import Session
from django.contrib.sessions.backends.db import SessionStore
from openai import Client
import time
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import authentication_classes, permission_classes
from django.conf import settings
import stripe
from datetime import timedelta

stripe.api_key = settings.STRIPE_SECRET_KEY


@api_view(['GET'])
def home(request):
    return render(request,"index.html")

@api_view(['GET'])
def register(request):
    return render(request,"register.html")

@api_view(['GET'])
def terms(request):
    return render(request,"terms_conditions.html")

@api_view(['GET'])
def policy(request):
    return render(request,"privacy.html")

@api_view(['GET'])
def sign(request):
    return render(request,"login.html")

@api_view(['GET'])
def success(request):
    return render(request, "success.html")

@api_view(['GET'])
def cancel(request):
    return render(request, "cancel.html")



class RegistrationAPIView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()  
            messages.success(request, 'Registration Successful!')
            return render(request, "login.html")  
        else:
            password_error = serializer.errors.get('password', [])
            error_messages = [f" {error}" for error in password_error]
            messages.error(request, ', '.join(error_messages))
            return render(request, "register.html", {'form': serializer.data})
        
    

class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data.get('user')
            if user:
                token, created = Token.objects.get_or_create(user=user)
             
                return Response({
                    'status': True,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'username': user.username,
                    'token': token.key  
                }, status=status.HTTP_200_OK)
               
            else:
                # messages.error(request,"Invalid credentials")
                return Response({'status': False, 'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
                
        else:
            return render(request, "login.html", {'errors': serializer.errors})

class LogoutAPIView(APIView):
    def post(self, request):
        token=request.headers.get('Authorization')
        try:
            token = Token.objects.get(key=token)
            token.delete()
            return Response({'status':"True",
                'message': 'Logout successful'}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({'status':"False",
                'error': 'Token not found'}, status=status.HTTP_400_BAD_REQUEST)




client = OpenAI(api_key="OPENAI_KEY")


from django.utils import timezone


@api_view(['GET'])
def chatbott(request):
    return render(request, "chatbot.html")

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def ask_question(request,pk=1):
    if request.method == 'POST':
        user = request.user

        time_joined = user.date_joined
        print(user, user.id, time_joined)
        time_joined = user.date_joined
        current_time = timezone.now()
        print("current time", current_time)

        # Calculate the time difference
        time_difference = current_time - time_joined   

        # Extract the number of days
        days_difference = time_difference.days

        print(f"{user} joined {days_difference} days ago.")

        if days_difference  >=0:
            print("you are able")
        
            question = request.data['question']
            print(question)

            thread_id = request.COOKIES.get('thread_id')

            if thread_id:
                thread_id = thread_id
            else:
                thread = client.beta.threads.create()
                thread_id = thread.id

            print("===?>", thread_id)

            assistant = client.beta.assistants.create(
                name="Med Mock Interviewer",
                instructions="Med Mock Interviewer Setup Guide 1. Session Start: Type anything to initiate the session 2. Introduction: Briefly explain the purpose (mock interviews for pre-med students) and gather student preferences. 3. Language Selection: Ask for the preferred language and use it throughout the session. Also ask for the country of choice (questions will be tailored around current health care concepts in this country) 4. Interview Type: Offer a choice between Multiple Mini Interview (MMI) or Panel-style interview. For the MMI style questions  5. Questions: For the MMI questions, ALWAYS create original, difficult, and current questions that fall into one of the categories: Scenario, Policy (relevant to country), Personal, Acting-Station, and Quirky. Randomly swap between question categories. For Panel-style interviews, ask Scenario, Ethical, and Personal questions.  6. Role Assumption: Begin the interview without unnecessary commentary. Maintain a formal, concise tone. No exclamations or superfluous remarks. Do not reveal question types or provide feedback unless explicitly requested. 7. Giving Feedback: After completing all interview questions (there should be 8 questions for panel or MMI):Always tell the interviewee what they did wrong. Then suggest improved responses, demonstrating optimal answers.",
                tools=[{"type": "code_interpreter"}],
                model="gpt-4-1106-preview",
            )

            message = client.beta.threads.messages.create(
                thread_id=thread_id,
                role="user",
                content=question
            )

            run = client.beta.threads.runs.create(
                thread_id=thread_id,
                assistant_id=assistant.id
            )

            run = client.beta.threads.runs.retrieve(
                thread_id=thread_id,
                run_id=run.id
            )

            time.sleep(15) 

            messages = client.beta.threads.messages.list(
                thread_id=thread_id,
            )

            result = []
            for message in reversed(messages.data):
                result.append({'role': message.role, 'content': message.content[0].text.value})

            response = messages.data[0].content[0].text.value if messages.data else "No response"
            print(result)

            response =  JsonResponse({"response": response})
            response.set_cookie('thread_id', thread_id)
            return response
        
        else:
            print("you are no eligible")
            response = JsonResponse({"response": "Your plan is finished. Please recharge."})
            return response
        

@api_view(['GET', 'POST'])
def one_month(request):
    data = request.user
    user_id = data.id
    print(user_id)
    session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': 'price_1OKEatGn1RVdWg2YWUHpEkB2',  
                    'quantity': 1,
                }],
                mode='subscription',
                metadata={
                    'user_id': user_id  
                },
                success_url='http://127.0.0.1:8000/success/'
                ,  
                cancel_url='http://127.0.0.1:8000/cancel/'  
            )

    payment_url = session.url
            
    return Response (payment_url)


@api_view(['GET', 'POST'])
def three_month(request):
    data = request.user
    user_id = data.id
    print(user_id)
    session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': 'price_1OKFTmGn1RVdWg2Yw7PFhVie',  
                    'quantity': 1,
                }],
                mode='subscription',
                metadata={
                    'user_id': user_id  
                },
                success_url='http://127.0.0.1:8000/order/success/'
                ,  
                cancel_url='http://127.0.0.1:8000/cancel/'  
            )

    payment_url = session.url
            
    return Response (payment_url)


@csrf_exempt
@api_view(['GET', 'POST'])
def stripe_webhook(request):
    payload = request.body
    print(payload)
    sig_header = request.headers.get('Stripe-Signature', None)

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, 'whsec_BLWVZV53m5djUVUh45p3jsxJ8DbCH9Xw'
        )
    except ValueError as e:
        return JsonResponse({'error': 'Invalid payload'}, status=400)
    except stripe.error.SignatureVerificationError as e:
        return JsonResponse({'error': 'Invalid signature'}, status=400)

    if event['type'] == 'checkout.session.completed':

        payload_dict = json.loads(payload)

        ID = payload_dict['data']['object']['metadata'].get('user_id')
        print(f"User ID is==: {ID}")
        amount_paid = payload_dict['data']['object']['amount_total']
        print(amount_paid)

        try:
            user = User.objects.get(id=ID)
            if amount_paid==900:
                user.date_joined += timedelta(days=30)
            elif amount_paid==2900:
                user.date_joined += timedelta(days=90)
            else:
                pass

            user.save()
            print(f"User's datejoined updated: {user.date_joined}")
        except User.DoesNotExist:
            print("User not found")


    return JsonResponse({'status': 'success'})