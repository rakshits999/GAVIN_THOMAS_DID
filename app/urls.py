from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from django.conf import settings
from django.conf.urls.static import static
from . import views

from app.views import *

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('terms-conditions/', views.terms, name='policy'),
    path('privacy-policy/', views.policy, name='policy'),
    path('sign-up/', views.sign, name='sign'),
    path('signup/', RegistrationAPIView.as_view(), name='signup'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('chatbot/', views.chatbott, name='chatbott'),
    path('ask/', views.ask_question, name='ask_question'),
    path('stripe_one_month/', views.one_month, name='onemonth'),
    path('stripe_three_month/', views.three_month, name='three_month'),
    path('stripe_webhook/', views.stripe_webhook, name='three_month'),
    path('success/', views.success, name='success'),
    path('cancel/', views.cancel, name='cancel'),

]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)