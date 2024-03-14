from django.http import HttpResponseNotAllowed, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage
from core import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import login, logout
from . tokens import generate_token
from django.contrib.auth.hashers import check_password
from django.utils.html import escape
import requests
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
import random
import string
import time
from django.urls import reverse
from datetime import datetime, timedelta

@csrf_exempt
def validate_recaptcha(recaptcha_response):
    secret_key = settings.RECAPTCHA_PRIVATE_KEY
    payload = {'response': recaptcha_response, 'secret': secret_key}
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    return result['success']

def home(request):
    return render(request, "index.html")

def signup(request):
    if request.method == "POST":
        username = escape(request.POST['username'])
        first_name = escape(request.POST['first_name'])
        last_name = escape(request.POST['last_name'])
        email = escape(request.POST['email'])
        password = escape(request.POST['password'])
        confirm_password = escape(request.POST['confirm_password'])

        recaptcha_response = request.POST.get('g-recaptcha-response')
        recaptcha_return = validate_recaptcha(recaptcha_response)
        if not recaptcha_return:
            messages.error(request, "Please complete the reCAPTCHA!")
            return redirect('signup')

        if User.objects.filter(username=username):
            messages.error(request, "Please try some other username!")
            return redirect('signup')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Entered email already registered!")
            return redirect('signup')
        
        myuser = User.objects.create_user(username=username, email=email, password=password)
        myuser.first_name = first_name
        myuser.last_name = last_name
        myuser.is_active = False
        myuser.save()
        
        current_site = get_current_site(request)
        email_subject = " Confirm your Email!"
        message = render_to_string('email_confirmation.html', {
            'name': first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email],
        )
        email.content_subtype = "html"
        email.send()

        messages.success(request, "Your account has been created successfully. Please check your email to confirm your email address!")

        return redirect('signin')
        
    return render(request, "signup.html")


def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        myuser.save()
        messages.success(request, "Your Account has been activated!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')

def signin(request):
    if request.method == 'POST':
        username = escape(request.POST['username'])
        password = escape(request.POST['password'])

        recaptcha_response = request.POST.get('g-recaptcha-response')
        recaptcha_return = validate_recaptcha(recaptcha_response)
        if not recaptcha_return:
            messages.error(request, "Please complete the reCAPTCHA!")
            return redirect('signin')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, "Bad Credentials!")
            return redirect('signin')

        stored_password = user.password
        check = check_password(password, stored_password)

        if check:
            if user.is_active:
                otp = generate_otp()
                request.session['otp'] = otp
                request.session['otp_timestamp'] = time.time()
                request.session['username'] = username
                
                send_otp_email(user.email, otp)
                messages.success(request, "An OTP has been sent on your registered mail id!")
                return render(request, 'verify_otp.html', {'username': username})
            else:
                messages.error(request, "Your account is not activated yet. Please check your email for the activation link!")
                return redirect('signin')
        else:
            messages.error(request, "Bad Credentials!")
            return redirect('signin')
        
    return render(request, "signin.html")

def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, "No user with that email address exists! Please register yourself first!")
                return redirect('password_reset')
            
            current_site = get_current_site(request)
            email_subject = "Reset Your Password!"
            message = render_to_string('email_password_reset.html', {
                'name': user.first_name,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user)
            })
            email = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [user.email],
            )
            email.content_subtype = "html"
            email.send()
            messages.success(request, "An email has been sent with instructions to reset your password!")
            return redirect('signin')
    else:
        form = PasswordResetForm()
    
    return render(request, 'password_reset_form.html', {'form': form})

def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password1')
            user.set_password(new_password)
            user.save()
            messages.success(request, "Your password has been reset successfully. You can now sign in with your new password!")
            return redirect('signin')
        else:
            form = SetPasswordForm(user)
        return render(request, 'password_reset_confirm.html', {'form': form, 'uidb64': uidb64, 'token': token})
    else:
        messages.error(request, "The password reset link is invalid or has expired!")
        return redirect('password_reset')

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(email, otp):
    email_subject = ' Your OTP for Sign In!'
    message = f'Your OTP for sign in is: {otp}'
    email = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email],
            )
    email.send()

def verify_otp(request):
    if request.method == 'POST':
        otp_entered = escape(request.POST['otp'])
        stored_otp = request.session.get('otp')
        username = request.session.get('username')
        otp_timestamp = request.session.get('otp_timestamp')

        recaptcha_response = request.POST.get('g-recaptcha-response')
        recaptcha_return = validate_recaptcha(recaptcha_response)
        if not recaptcha_return:
            messages.error(request, "Please complete the reCAPTCHA!")
            return redirect('signin')

        if stored_otp == otp_entered:
            current_time = datetime.now()
            otp_validity_seconds = 120
            otp_timestamp = datetime.fromtimestamp(otp_timestamp)
            if current_time - otp_timestamp <= timedelta(seconds=otp_validity_seconds):
                user = User.objects.get(username=username)
                login(request, user)
                first_name = user.first_name
                return render(request, "index.html", {'first_name': first_name})
            else:
                del request.session['otp']
                del request.session['otp_timestamp']
                del request.session['username']
                messages.error(request, "OTP has expired. Please request a new OTP!")
                return HttpResponseRedirect(reverse('resend_otp') + f'?username={username}')
        else:
            messages.error(request, "Invalid OTP. Please try again!")
            return redirect('verify_otp')
        
    return HttpResponseNotAllowed(['POST'])

def resend_otp(request):
    if request.method == 'GET':
        username = request.GET['username']
        user_email = User.objects.filter(username=username).values_list('email', flat=True).first()
        
        otp = generate_otp()
        request.session['otp'] = otp
        request.session['otp_timestamp'] = time.time()
        request.session['username'] = username
        
        send_otp_email(user_email, otp)
        messages.success(request, "New OTP has been sent to your email!")
        return render(request, 'verify_otp.html')
    else:
        return HttpResponseNotAllowed(['GET'])

def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully!")
    return redirect('home')
