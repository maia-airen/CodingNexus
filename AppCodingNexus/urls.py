from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),
    path('course/', views.course, name='course'),
    path('classroom/', views.classroom, name='classroom'),
    path('about/', views.about, name='about'),
    path('profile/', views.profile, name='profile'),
    path('view_profile/', views.view_profile, name='view_profile'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('delete_account/', views.delete_account, name='delete_account'),
    path('my_classes/', views.my_classes, name='my_classes'),
    path('my_exercises/', views.my_exercises, name='my_exercises'),
    path('my_quizzes/', views.my_quizzes, name='my_quizzes'),
    path('register/', views.user_register, name='register'),
    path('forgot-password/', views.forgot_password, name='forgot-password'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset-password'),
]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)