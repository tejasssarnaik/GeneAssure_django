
from django.urls import path
from Geneapp.views import *



urlpatterns = [
    path('index/', index_view),
    path('login/', login_view, name='login'),
    path('register/', register_view),
    path('forgot/', forgot_view),
    path('wes/', wes_view),
    path('wgs/', wgs_view),
    path('tngs/', tngs_view),
    path('data/', data_view),
    path('wgsdata/', wgsdata_view),
    path('activate/<str:uidb64>/<str:token>/', activate_account, name='activate'),
    path('reset_password/',reset_password, name='reset_password'),	
    path('reset_password/<str:uidb64>/<str:token>/',reset_password_link, name='reset_password_link'),
    path('',landingpage_view),
    path('workflow/',workflow_view)

    



]

