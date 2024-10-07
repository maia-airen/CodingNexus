from django.contrib.auth.decorators import login_required
from django.http import BadHeaderError
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.contrib import messages
from django.conf import settings
from .models import UserProfile
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
import random

#@login_required(login_url='login')
def home(request):
    return render(request, 'home.html')

def course(request):
    return render(request, 'courses.html')

def classroom(request):
    return render(request, 'classroom.html')

def about(request):
    return render(request, 'about.html')

def profile(request):
    return render(request, 'profile.html')

def view_profile(request):
    return render(request, 'viewprofile.html')

def edit_profile(request):
    return render(request, 'editprofile.html')

def change_password(request):
    return render(request, 'change_password.html')

def my_classes(request):
    return render(request, 'my_class.html')

def my_exercises(request):
    return render(request, 'my_exercise.html')

def my_quizzes(request):
    return render(request, 'my_quizz.html')

def delete_account(request):
    return render(request, 'delete_account.html')

def generate_otp():
    """Generate a 6-digit OTP."""
    return random.randint(100000, 999999)

def send_otp_email(user, otp):
    email_subject = "Your OTP Code"
    
    html_message = render_to_string('emailotp.html', {
        'lastname': user.last_name,
        'otp': otp,
    })
    
    text_message = strip_tags(html_message)

    email = EmailMultiAlternatives(
        email_subject,
        text_message,
        settings.EMAIL_HOST_USER,
        [user.email],
    )
    
    email.attach_alternative(html_message, "text/html")
    
    try:
        email.send(fail_silently=False)
    except BadHeaderError:
        return False
    return True

def user_register(request):
    if request.method == 'POST':
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        bmonth = request.POST['bmonth']
        bday = request.POST['bday']
        byear = request.POST['byear']
        gender = request.POST['gender']
        email = request.POST['email']
        password = request.POST['password']
        cpassword = request.POST['cpassword']
        
        role = request.POST.get('role')
        if not role:
            messages.error(request, "Please select a role (Student or Instructor).")
            return redirect('register')
        
        if password != cpassword:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        try:
            user = User.objects.create_user(
                username=email, email=email, password=password, first_name=firstname, last_name=lastname
            )
            user.is_active = False
            user.save()

            otp = generate_otp()
            email_sent = send_otp_email(user, otp)

            if not email_sent:
                messages.error(request, "Error sending OTP email. Please try again.")
                return redirect('register')

            request.session['registration_data'] = {
                'user_id': user.id,
                'firstname': firstname,
                'lastname': lastname,
                'bmonth': bmonth,
                'bday': bday,
                'byear': byear,
                'gender': gender,
                'role': role,
                'otp': otp,
            }

            messages.success(request, 'OTP has been sent to your email. Please verify your account.')
            return redirect('verify_otp')

        except Exception as e:
            messages.error(request, f"Registration failed: {e}")
            return redirect('register')

    return render(request, 'register.html')

def verify_otp(request):
    if request.method == 'POST':
        input_otp = request.POST['otp']
        session_data = request.session.get('registration_data')

        if session_data and input_otp == str(session_data['otp']):
            user = User.objects.get(id=session_data['user_id'])
            user_profile = UserProfile.objects.create(
                user=user,
                firstname=session_data['firstname'],
                lastname=session_data['lastname'],
                birthmonth=session_data['bmonth'],
                birthday=session_data['bday'],
                birthyear=session_data['byear'],
                gender=session_data['gender'],
                role=session_data['role']
            )

            user.is_active = True 
            user.save()

            del request.session['registration_data']
            messages.success(request, 'Your account has been verified and registered successfully!')
            return redirect('login')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
            return redirect('verify_otp')

    return render(request, 'verification.html')

def user_login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, username=email, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, "Login successful.")
            return redirect('home')
        else:
            messages.error(request, "Invalid credentials.")
            return redirect('login')

    return render(request, 'login.html')

def user_logout(request):
    logout(request)
    messages.success(request, 'Logged out successfully!')
    return redirect('login')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))  # Removed .decode()

            email_subject = "Reset Your Password"
            email_template = 'emailfpass.html'
            email_context = {
                'email': user.email,
                'domain': request.get_host(),
                'uid': uid,
                'token': token,
            }
            email_message = render_to_string(email_template, email_context)
            email = EmailMessage(email_subject, email_message, settings.DEFAULT_FROM_EMAIL, [user.email])
            email.content_subtype = "html"
            email.send(fail_silently=False)
            
            messages.success(request, "Password reset link has been sent to your email.")
            return redirect('forgot-password')

        except User.DoesNotExist:
            messages.error(request, "Email not found.")
            return redirect('forgot-password')

    return render(request, 'forgot-password.html')

def reset_password(request):
    if request.method == 'GET':
        uidb64 = request.GET.get('uid')
        token = request.GET.get('token')

        print(f"uidb64: {uidb64}, token: {token}")  # Debugging output

        if uidb64 is None or token is None:
            messages.error(request, "Invalid password reset link.")
            return redirect('forgot-password')

        try:
            # Decode the uidb64 to get the user ID
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
            print(f"User found: {user}")  # Debugging output

            # Render the reset password template
            return render(request, 'reset-password.html', {'uid': uid, 'token': token})

        except (TypeError, ValueError, User.DoesNotExist):
            messages.error(request, "Invalid password reset link.")
            return redirect('forgot-password')

    elif request.method == 'POST':
        uid = request.POST['uid']
        token = request.POST['token']
        password = request.POST['password']
        cpassword = request.POST['cpassword']

        # Check if passwords match
        if password != cpassword:
            messages.error(request, "Passwords do not match.")
            return render(request, 'reset-password.html', {'uid': uid, 'token': token})

        try:
            # Verify the user using uid and token
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                user.set_password(password)  # Set the new password
                user.save()  # Save the user with the new password
                messages.success(request, "Your password has been reset successfully! You can now log in.")
                return redirect('login')
            else:
                messages.error(request, "Invalid password reset link.")
                return redirect('forgot-password')

        except User.DoesNotExist:
            messages.error(request, "Invalid password reset link.")
            return redirect('forgot-password')

    # If neither GET nor POST, render the reset password page
    return render(request, 'reset-password.html') 