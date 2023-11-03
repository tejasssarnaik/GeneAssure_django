# # Use an official Python runtime as a parent image
# FROM python:3.11

# # Set the working directory in the container
# WORKDIR /app

# # Copy the requirements file into the container at /app
# COPY requirements.txt /app/

# # Install any needed packages specified in requirements.txt
# RUN pip install -r requirements.txt

# # Copy the current directory contents into the container at /app
# COPY . /app


# # Expose the port the app runs on
# EXPOSE 8000

# # Define environment variable for Django
# ENV DJANGO_SETTINGS_MODULE=GeneAssure.settings

# # Run Django's development server
# CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]


FROM python:3.11

WORKDIR /app

COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY . /app/

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
