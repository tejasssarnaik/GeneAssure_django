
from django.contrib import admin
from django.urls import path,include
from Geneapp.views import *
urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include('Geneapp.urls')),

  
   

]

