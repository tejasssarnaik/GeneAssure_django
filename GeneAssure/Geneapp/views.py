# from django.shortcuts import render,redirect
# import os
# import json
# import csv
# from django.contrib.auth.decorators import login_required
# from django.contrib.auth.models import User
# from django.http import HttpResponse
# from django.contrib import messages
# from django.contrib.sites.shortcuts import get_current_site
# from django.template.loader import render_to_string
# from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# from django.contrib.auth.tokens import default_token_generator
# from django.contrib.auth import authenticate, login
# from django.core.mail import send_mail
# from django.contrib.auth import update_session_auth_hash



# # Create your views here.

# @login_required(login_url='login')
# def index_view(request):
#     return render(request,'Geneapp\index.html')




# def login_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('password')

#         user = authenticate(request, username=email, password=password)

#         if user is not None:
#             if user.is_active:
#                 login(request, user)
#                 return redirect('/index/')
#             else:
#                 messages.error(request, "Your account is not active. Please activate your account.")
#         else:
#             messages.error(request, "Invalid email or password. Please try again.")

#     return render(request, 'Geneapp/login.html')




# def register_view(request):
#     if request.method == 'POST':
#         fname = request.POST.get('fname')
#         lname = request.POST.get('lname')
#         email = request.POST.get('email')
#         password1 = request.POST.get('password1')
#         password2 = request.POST.get('password2')

#         if password1 != password2:
#             messages.add_message(request, messages.ERROR, "Passwords do not match.")
#             return render(request, 'Geneapp/register.html')

#         try:
#             my_user = User.objects.get(username=email)
#             messages.add_message(request, messages.ERROR, "User with this email already exists.")
#             return render(request, 'Geneapp/register.html')
#         except User.DoesNotExist:
#             pass

#         try:
#             my_user = User.objects.create_user(username=email, first_name=fname, last_name=lname, email=email, password=password1)

#             # Send verification email
#             current_site = get_current_site(request)
#             mail_subject = 'Activate your account'
#             message = render_to_string('Geneapp/verification_email.html', {
#                 'user': my_user,
#                 'domain': current_site.domain,
#                 'uid': urlsafe_base64_encode(str(my_user.pk).encode()),
#                 'token': default_token_generator.make_token(my_user),
#             })
#             my_user.email_user(mail_subject, message)

#             messages.add_message(request, messages.SUCCESS, "User registered successfully. Please check your email for verification instructions.")
#             return redirect('/register/')
#         except Exception as e:
#             messages.add_message(request, messages.ERROR, f"Error: {e}")
#     return render(request, 'Geneapp/register.html')





# def activate_account(request, uidb64, token):
#     try:
#         uid = urlsafe_base64_decode(uidb64).decode()
#         user = User.objects.get(pk=uid)

#         if default_token_generator.check_token(user, token):
#             if not user.is_active:
#                 user.is_active = True
#                 user.save()
#             messages.success(request, "Your account has been activated! You can now login.")
#         else:
#             messages.error(request, "Invalid activation link.")
#     except Exception as e:
#         messages.error(request, f"Error: {e}")

#     return redirect('login')




# def forgot_view(request):
#     return render(request,'Geneapp\\forgot-password.html')





# def wes_view(request):
#     return render(request,'Geneapp\wes.html')




# def wgs_view(request):
#     return render(request,'Geneapp\wgs.html')




# def tngs_view(request):
#     return render(request,'Geneapp\\tngs.html')



# def reset_password(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         try:
#             user = User.objects.get(email=email)
#             token = default_token_generator.make_token(user)
#             uid = urlsafe_base64_encode(str(user.pk).encode())
#             reset_link = f"http://127.0.0.1:8000/reset_password/{uid}/{token}/"  # Replace with your actual URL

#             # Send reset link to user's email
#             subject = 'Password Reset'
#             message = f'Click the link to reset your password: {reset_link}'
#             sender = 'admin@example.com'  # Replace with your actual sender email
#             recipient_list = [email]
#             send_mail(subject, message, sender, recipient_list)

#             # Add a success message (optional)
#             messages.success(request, "Password reset link sent successfully.")
#         except User.DoesNotExist:
#             messages.error(request, "User with this email does not exist.")

#         return redirect('/reset_password/')

#     return render(request, 'Geneapp/forgot-password.html')






# def reset_password_link(request, uidb64, token):
#     try:
#         uid = urlsafe_base64_decode(uidb64).decode()
#         user = User.objects.get(pk=uid)

#         if default_token_generator.check_token(user, token):
#             if request.method == 'POST':
#                 new_password = request.POST.get('new_password')
#                 confirm_password = request.POST.get('confirm_password')

#                 if new_password == confirm_password:
#                     user.set_password(new_password)
#                     user.save()
#                     update_session_auth_hash(request, user)  # Keep the user logged in
#                     messages.success(request, "Password updated successfully.")
#                     return redirect('login')
#                 else:
#                     messages.error(request, "Passwords do not match.")

#             return render(request, 'Geneapp/reset-password.html', {'uidb64': uidb64, 'token': token})
#         else:
#             messages.error(request, "Invalid reset link.")
#     except Exception as e:
#         messages.error(request, f"Error: {e}")

#     return redirect('login')










# def data_view(request):
#     if request.method == 'POST' and all(request.FILES.get(f) for f in ['fastq1', 'fastq2','known variant', 'bed']):
#         fastq1_files = request.FILES.getlist('fastq1')
#         fastq2_files = request.FILES.getlist('fastq2')
#         # reference_genome = request.FILES['reference genome']
#         known_variant_files = request.FILES.getlist('known variant')
#         bed_files = request.FILES.getlist('bed')
#         selected_option = request.POST.get('selected_option')

#         # FASTQ1_PATH = [f'e:/files/{file.name}' for file in fastq1_files]
#         # FASTQ2_PATH = [f'e:/files/{file.name}'for file in fastq2_files]
#         # # Reference_genome_PATH = f'e:/files/{reference_genome.name}'
#         # Known_variant_PATH = [f'e:/files/{file.name}'for file in known_variant_files]
#         # Bed_PATH = [f'e:/files/{file.name}'for file in bed_files]
#         selected_option_string = f"{selected_option}"

#         # config_content = f"FASTQ1_PATH='{FASTQ1_PATH}'\nFASTQ2_PATH='{FASTQ2_PATH}'\n" \
#         #                  f"Known_variant_PATH='{Known_variant_PATH}'\n" \
#         #                  f"Bed_PATH='{Bed_PATH}'\n" \
#         #                  f"{selected_option_string}\n"

#         fastq_pairs = list(zip(fastq1_files, fastq2_files))
#         fastq_data = [{'SAMPLE_ID': f1.name.split('_')[0], 'FASTQ1': f1.name, 'FASTQ2': f2.name} for f1, f2 in fastq_pairs]
#         csv_path = 'E:/django Project/GeneAssure/medadata.csv' 


#         with open(csv_path, mode='w', newline='') as csv_file:
#             fieldnames = ['SAMPLE_ID','FASTQ1', 'FASTQ2']
#             writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

#             writer.writeheader()
#             for row in fastq_data:
#                 writer.writerow(row)             

#         # with open('config.sh', 'w') as config_file:
#         #     config_file.write(config_content)
        
#         # csv_files = [f'e:/django Project/GeneAssure/{file.name}' for file in request.FILES.getlist('csv_files')]
#         known_variant_files = [f'e:/files/{file.name}' for file in known_variant_files]
#         bed_files = [f'e:/files/{file.name}' for file in bed_files]

#         data = {
#             "csv": csv_path,
#             "Known_variant_PATH": known_variant_files,
#             "Bed_PATH": bed_files,
#             selected_option: selected_option_string
#         }

#         with open('data.json', 'w') as json_file:
#                 json.dump(data, json_file)

    
            
#         log_file_path = r'E:\\files\\GA_log_202304271308_07.log'

#         if os.path.exists(log_file_path):
#             with open(log_file_path, 'r') as log_file:
#                 log_content = log_file.read()
#         else:
#             log_content = "Log file not found."

    
#         return render(request, 'geneapp\data.html', {'fastq1': fastq1_files, 'fastq2': fastq2_files,  
#                                                      'known_variant': known_variant_files,
#                                                      'bed': bed_files,'log_content': log_content,
#                                                      })
#     else:
#         return render(request, 'geneapp\data.html')
    



# def wgsdata_view(request):
#     if request.method == 'POST' and all(request.FILES.get(f) for f in ['fastq1', 'fastq2','known variant',]):
#         fastq1_files = request.FILES.getlist('fastq1')
#         fastq2_files = request.FILES.getlist('fastq2')
#         # reference_genome = request.FILES['reference genome']
#         known_variant_files = request.FILES.getlist('known variant')
#         # bed = request.FILES['bed']
#         selected_option = request.POST.get('selected_option')

#         # FASTQ1_PATH = f'e:/files/{fastq1.name}'
#         # FASTQ2_PATH = f'e:/files/{fastq2.name}'
#         # Reference_genome_PATH = f'e:/files/{reference_genome.name}'
#         # Known_variant_PATH = f'e:/files/{known_variant.name}'
#         # Bed_PATH = f'e:/files/{bed.name}'
#         selected_option_string = f"{selected_option}='{selected_option}'"

#         # config_content = f"FASTQ1_PATH='{FASTQ1_PATH}'\nFASTQ2_PATH='{FASTQ2_PATH}'\n" \
#         #                  f"Known_variant_PATH='{Known_variant_PATH}'\n" \
#         #                  f"{selected_option_string}\n"
                         

#         # with open('config.sh', 'w') as config_file:
#         #     config_file.write(config_content)

#         fastq_pairs = list(zip(fastq1_files, fastq2_files))
#         fastq_data = [{'SAMPLE_ID': f1.name.split('_')[0], 'FASTQ1': f1.name, 'FASTQ2': f2.name} for f1, f2 in fastq_pairs]
#         csv_path = 'E:/django Project/GeneAssure/medadata.csv' 


#         with open(csv_path, mode='w', newline='') as csv_file:
#             fieldnames = ['SAMPLE_ID','FASTQ1', 'FASTQ2']
#             writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

#             writer.writeheader()
#             for row in fastq_data:
#                 writer.writerow(row) 
        

#         known_variant_files = [f'e:/files/{file.name}' for file in known_variant_files]


#         data = {
#             "csv": csv_path,
#             "Known_variant_PATH": known_variant_files,
#             selected_option: selected_option_string
#         }

#         with open('data.json', 'w') as json_file:
#                 json.dump(data, json_file)



#         log_file_path = r'E:\\files\\GA_log_202304271308_07.log'

#         if os.path.exists(log_file_path):
#             with open(log_file_path, 'r') as log_file:
#                 log_content = log_file.read()
#         else:
#             log_content = "Log file not found."


#         return render(request, 'geneapp\data.html', {'fastq1': fastq1_files, 'fastq2': fastq2_files,  
#                                                      'known_variant': known_variant_files,
#                                                      'log_content': log_content})
#     else:
#         return render(request, 'geneapp\data.html')
    





from django.shortcuts import render, redirect
import os
import json
import csv
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.contrib.auth import update_session_auth_hash

# Create your views here.

@login_required(login_url='login')
def index_view(request):
    return render(request, 'Geneapp/index.html')

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, username=email, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                return redirect('/index/')
            else:
                messages.error(request, "Your account is not active. Please activate your account.")
        else:
            messages.error(request, "Invalid email or password. Please try again.")

    return render(request, 'Geneapp/login.html')

def register_view(request):
    if request.method == 'POST':
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.add_message(request, messages.ERROR, "Passwords do not match.")
            return render(request, 'Geneapp/register.html')

        try:
            my_user = User.objects.get(username=email)
            messages.add_message(request, messages.ERROR, "User with this email already exists.")
            return render(request, 'Geneapp/register.html')
        except User.DoesNotExist:
            pass

        try:
            my_user = User.objects.create_user(username=email, first_name=fname, last_name=lname, email=email, password=password1)

            # Send verification email
            current_site = get_current_site(request)
            mail_subject = 'Activate your account'
            message = render_to_string('Geneapp/verification_email.html', {
                'user': my_user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(str(my_user.pk).encode()),
                'token': default_token_generator.make_token(my_user),
            })
            my_user.email_user(mail_subject, message)

            messages.add_message(request, messages.SUCCESS, "User registered successfully. Please check your email for verification instructions.")
            return redirect('/register/')
        except Exception as e:
            messages.add_message(request, messages.ERROR, f"Error: {e}")
    return render(request, 'Geneapp/register.html')

def activate_account(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            if not user.is_active:
                user.is_active = True
                user.save()
            messages.success(request, "Your account has been activated! You can now login.")
        else:
            messages.error(request, "Invalid activation link.")
    except Exception as e:
        messages.error(request, f"Error: {e}")

    return redirect('login')

def forgot_view(request):
    return render(request, 'Geneapp/forgot-password.html')

def wes_view(request):
    return render(request, 'Geneapp/wes.html')

def wgs_view(request):
    return render(request, 'Geneapp/wgs.html')

def tngs_view(request):
    return render(request, 'Geneapp/tngs.html')

def reset_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(str(user.pk).encode())
            reset_link = f"http://127.0.0.1:8000/reset_password/{uid}/{token}/"  # Replace with your actual URL

            # Send reset link to user's email
            subject = 'Password Reset'
            message = f'Click the link to reset your password: {reset_link}'
            sender = 'admin@example.com'  # Replace with your actual sender email
            recipient_list = [email]
            send_mail(subject, message, sender, recipient_list)

            # Add a success message (optional)
            messages.success(request, "Password reset link sent successfully.")
        except User.DoesNotExist:
            messages.error(request, "User with this email does not exist.")

        return redirect('/reset_password/')

    return render(request, 'Geneapp/forgot-password.html')

def reset_password_link(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            if request.method == 'POST':
                new_password = request.POST.get('new_password')
                confirm_password = request.POST.get('confirm_password')

                if new_password == confirm_password:
                    user.set_password(new_password)
                    user.save()
                    update_session_auth_hash(request, user)  # Keep the user logged in
                    messages.success(request, "Password updated successfully.")
                    return redirect('login')
                else:
                    messages.error(request, "Passwords do not match.")

            return render(request, 'Geneapp/reset-password.html', {'uidb64': uidb64, 'token': token})
        else:
            messages.error(request, "Invalid reset link.")
    except Exception as e:
        messages.error(request, f"Error: {e}")

    return redirect('login')

def data_view(request):
    if request.method == 'POST' and all(request.FILES.get(f) for f in ['fastq1', 'fastq2','known variant', 'bed']):
        fastq1_files = request.FILES.getlist('fastq1')
        fastq2_files = request.FILES.getlist('fastq2')
        known_variant_files = request.FILES.getlist('known variant')
        bed_files = request.FILES.getlist('bed')
        selected_option = request.POST.get('selected_option')

        selected_option_string = f"{selected_option}"

        fastq_pairs = list(zip(fastq1_files, fastq2_files))
        fastq_data = [{'SAMPLE_ID': f1.name.split('_')[0], 'FASTQ1': f1.name, 'FASTQ2': f2.name} for f1, f2 in fastq_pairs]
        csv_path = 'GeneAssure/medadata.csv' 

        with open(csv_path, mode='w', newline='') as csv_file:
            fieldnames = ['SAMPLE_ID','FASTQ1', 'FASTQ2']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

            writer.writeheader()
            for row in fastq_data:
                writer.writerow(row)             

        known_variant_files = [f'e:/files/{file.name}' for file in known_variant_files]
        bed_files = [f'e:/files/{file.name}' for file in bed_files]

        data = {
            "csv": csv_path,
            "Known_variant_PATH": known_variant_files,
            "Bed_PATH": bed_files,
            selected_option: selected_option_string
        }

        with open('data.json', 'w') as json_file:
            json.dump(data, json_file)

        log_file_path = r'E:/files/GA_log_202304271308_07.log'

        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as log_file:
                log_content = log_file.read()
        else:
            log_content = "Log file not found."

        return render(request, 'geneapp/data.html', {'fastq1': fastq1_files, 'fastq2': fastq2_files,  
                                                     'known_variant': known_variant_files,
                                                     'bed': bed_files,'log_content': log_content,
                                                     })
    else:
        return render(request, 'geneapp/data.html')

def wgsdata_view(request):
    if request.method == 'POST' and all(request.FILES.get(f) for f in ['fastq1', 'fastq2','known variant']):
        fastq1_files = request.FILES.getlist('fastq1')
        fastq2_files = request.FILES.getlist('fastq2')
        known_variant_files = request.FILES.getlist('known variant')
        selected_option = request.POST.get('selected_option')

        selected_option_string = f"{selected_option}='{selected_option}'"

        fastq_pairs = list(zip(fastq1_files, fastq2_files))
        fastq_data = [{'SAMPLE_ID': f1.name.split('_')[0], 'FASTQ1': f1.name, 'FASTQ2': f2.name} for f1, f2 in fastq_pairs]
        csv_path = 'GeneAssure/medadata.csv' 

        with open(csv_path, mode='w', newline='') as csv_file:
            fieldnames = ['SAMPLE_ID','FASTQ1', 'FASTQ2']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

            writer.writeheader()
            for row in fastq_data:
                writer.writerow(row) 

        known_variant_files = [f'e:/files/{file.name}' for file in known_variant_files]

        data = {
            "csv": csv_path,
            "Known_variant_PATH": known_variant_files,
            selected_option: selected_option_string
        }

        with open('data.json', 'w') as json_file:
            json.dump(data, json_file)

        log_file_path = r'E:/files/GA_log_202304271308_07.log'

        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as log_file:
                log_content = log_file.read()
        else:
            log_content = "Log file not found."

        return render(request, 'geneapp/data.html', {'fastq1': fastq1_files, 'fastq2': fastq2_files,  
                                                     'known_variant': known_variant_files,
                                                     'log_content': log_content})
    else:
        return render(request, 'geneapp/data.html')




def landingpage_view(request):
    return render(request,'Geneapp/landingpage.html')

def workflow_view(request):
    return render(request,'Geneapp/workflow.html')

