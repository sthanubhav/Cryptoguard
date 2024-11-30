import hashlib
import os
from azure.storage.blob import BlobServiceClient
from django.conf import settings
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model, login as auth_login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.core.mail import send_mail
from storages.backends.azure_storage import AzureStorage
from web3 import Web3
import hashlib
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from django.http import HttpResponse, JsonResponse
from azure.core.exceptions import ResourceNotFoundError
from django.core.exceptions import ValidationError
import requests

from django.core.files.base import ContentFile
from .decorators import *
from UI.models import *
import logging



db_logger = logging.getLogger('db')

User = get_user_model()


class AzureStorage:
    def __init__(self, account_name, account_key, container_name):
        self.blob_service_client = BlobServiceClient(
            account_url=f"https://{account_name}.blob.core.windows.net/",
            credential=account_key
        )
        self.container_client = self.blob_service_client.get_container_client(container_name)

    def save(self, file_name, file_content):
        blob_client = self.container_client.get_blob_client(file_name)
        blob_client.upload_blob(file_content)
        return file_name

    def get(self, file_name):
        try:
            blob_client = self.container_client.get_blob_client(file_name)
            download_stream = blob_client.download_blob()
            return download_stream.readall()
        except ResourceNotFoundError:
            # Handle the case where the blob does not exist
            db_logger.error(f"Blob '{file_name}' does not exist in the container.")
            return None
        except Exception as e:
            # Handle other exceptions
            db_logger.error(f"Error downloading blob '{file_name}': {str(e)}")
            return None
        
from django.urls import reverse
@login_required
def home(request):
    user_profile = request.user.userprofile
    
    if not user_profile.mfa_enabled:
        return redirect(reverse('security'))  # Redirect to the security settings page if MFA is not enabled

    # Check if MFA is not verified
    elif not user_profile.mfa_verified:
        return redirect(reverse('verify_otp'))

    try:
        # Initialize the BlobServiceClient
        connection_string = settings.AZURE_CONNECTION_STRING
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)

        # Get the specific container
        container_name = settings.AZURE_CONTAINER
        container_client = blob_service_client.get_container_client(container_name)

        # Initialize variables for total size and number of blobs
        total_size = 0
        num_blobs = 0

        # Iterate over blobs to calculate total size and count
        for blob in container_client.list_blobs():
            blob_client = container_client.get_blob_client(blob)
            blob_properties = blob_client.get_blob_properties()
            total_size += blob_properties.size
            num_blobs += 1

        # Convert total storage capacity to gigabytes
        total_storage_capacity = 1000000000  # Example: 1 GB
        total_storage_capacity_gb = total_storage_capacity / (1024 ** 3)  # Convert bytes to GB

        # Convert used storage to gigabytes
        used_storage_gb = total_size / (1024 ** 3)  # Convert bytes to GB

        # Calculate available storage in gigabytes
        available_storage_gb = total_storage_capacity_gb - used_storage_gb

        # Calculate the used and available percentages
        used_percentage = (used_storage_gb / total_storage_capacity_gb) * 100
        available_percentage = 100 - used_percentage

        # Log the successful retrieval of storage information
        db_logger.info("Storage information retrieved successfully.", extra={'user': request.user.username})

        # Pass the data to the template context
        context = {
            'used_percentage': used_percentage,
            'available_percentage': available_percentage,
            # Add other data needed for the dashboard here
        }

        # Render the dashboard template with the context
        return render(request, 'dashboard/home.html', context)
    
    except Exception as e:
        # Log any errors that occur during the process
        db_logger.error(f"Error retrieving storage information: {str(e)}", extra={'user': request.user.username})
        error_message = str(e)
        context = {'error_message': error_message}
        return render(request, 'dashboard/home.html', context)




    
@login_required
@manager_or_admin_required
def update_share(request):
    if request.method == 'POST':
        file_id = request.POST.get('fileId')
        share = request.POST.get('share') == 'true'
        try:
            uploaded_file = UploadedFile.objects.get(id=file_id)
            uploaded_file.shared = share
            uploaded_file.save()

            # Log the file sharing update action
            db_logger.info(f"File '{uploaded_file.file_name}' sharing status updated by user '{request.user.username}'",extra={'user': request.user.username})

            return redirect('files')  # Redirect to the files page after updating
        except UploadedFile.DoesNotExist:
            # Log if the file was not found
            db_logger.error(f"File sharing update failed: File with ID {file_id} not found",extra={'user': request.user.username})
            return JsonResponse({'success': False, 'error': 'File not found'})
    return redirect('files') 

@login_required
@manager_or_admin_required
def delete_file(request, file_id):
    if request.method == 'POST':
        uploaded_file = get_object_or_404(UploadedFile, id=file_id)
        
        # Delete from Azure Blob Storage
        try:
            # Initialize the BlobServiceClient with your connection string
            blob_service_client = BlobServiceClient.from_connection_string(settings.AZURE_CONNECTION_STRING)
            
            # Get the blob container client
            container_client = blob_service_client.get_container_client(settings.AZURE_CONTAINER)
            
            # Delete the blob with the specified file name
            blob_client = container_client.get_blob_client(blob=uploaded_file.file_name)
            blob_client.delete_blob()

            # Log the successful deletion from Azure Blob Storage
            db_logger.info(f"File '{uploaded_file.file_name}' deleted from Azure Blob Storage.",extra={'user': request.user.username})

        except Exception as e:
            # Handle any errors during deletion from Azure Blob Storage
            # Log the error
            db_logger.error(f"Error deleting file '{uploaded_file.file_name}' from Azure Blob Storage: {str(e)}",extra={'user': request.user.username})
            return JsonResponse({'success': False, 'error': str(e)})
        
        # Delete from the database
        uploaded_file.delete()

        # Log the successful deletion from the database
        db_logger.info(f"File '{uploaded_file.file_name}' deleted from the database.",extra={'user': request.user.username})

        # Redirect the user to a relevant page after successful deletion
        return redirect('files')
    else:
        return JsonResponse({'success': False, 'error': 'Invalid request'})
    
@login_required
@manager_or_admin_required
def files(request):
    user_profile = request.user.userprofile
    if user_profile.mfa_verified:
        # Retrieve uploaded files from the database
        uploaded_files = UploadedFile.objects.filter(user_id=request.user.id)

        # Proceed with rendering the template
        context = {'uploaded_files': uploaded_files}
        return render(request, 'dashboard/files.html', context)
    else:
        return redirect('verify_otp')
    
@login_required
def shared_files(request):
    user_profile = request.user.userprofile
    if user_profile.mfa_verified:
        # Retrieve shared files from the database
        shared_files = UploadedFile.objects.filter(shared=True)

        # Proceed with rendering the template
        context = {'uploaded_files': shared_files}
        return render(request, 'dashboard/shared.html', context)
    else:
        return redirect('verify_otp')

@login_required
def verify_integrity(request):
    url = request.GET.get('url')
    hash = request.GET.get('hash')

    try:
        # Retrieve file content from the URL
        response = requests.get(url)
        if response.status_code == 200:
            file_content = response.content
                    
            # Calculate hash of the downloaded file content
            downloaded_file_hash = hashlib.sha256(file_content).hexdigest()

            # Compare with the provided hash
            if downloaded_file_hash == hash:
                db_logger.info(f"File integrity verified. User: {request.user.id}",extra={'user': request.user.username})
                return JsonResponse({'valid': True})
            else:
                db_logger.warning("File integrity check failed: Hash mismatch.",extra={'user': request.user.username})
                return JsonResponse({'valid': False})
        else:
            db_logger.error("Failed to download file: HTTP status code not 200.",extra={'user': request.user.username})
            return JsonResponse({'valid': False, 'error': 'Failed to download file'})

    except Exception as e:
        db_logger.error(f"Error during file integrity verification: {str(e)}",extra={'user': request.user.username})
        return JsonResponse({'valid': False, 'error': str(e)})

@login_required
@manager_or_admin_required
def upload_file(request):
    try:
        if request.method == 'POST' and request.FILES:
            uploaded_file = request.FILES['file']
            file_name = uploaded_file.name

            max_file_size = 1 * 1024 * 1024 * 1024  # 1 GB
            if uploaded_file.size > max_file_size:
                raise ValidationError("File size exceeds the maximum allowed size.")

            file_content = uploaded_file.read()
            if not file_content:
                raise ValidationError("Uploaded file content is empty.")

            file_hash = hashlib.sha256(file_content).hexdigest()

            # Connect to the local Ethereum node
            web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))

            # Load contract ABI and address
            contract_address = '0x5b38BD88f4f7898AB68CF8c8a9627e8C5a1f0C3C'
            contract_abi = [
                {
                    'anonymous': False,
                    'inputs': [{'indexed': False, 'internalType': 'string', 'name': 'hash', 'type': 'string'},
                                {'indexed': False, 'internalType': 'string', 'name': 'url', 'type': 'string'},
                                {'indexed': False, 'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}],
                    'name': 'FileUploaded',
                    'type': 'event'
                },
                {
                    'inputs': [{'internalType': 'string', 'name': 'hash', 'type': 'string'}],
                    'name': 'getFile',
                    'outputs': [{'internalType': 'string', 'name': '', 'type': 'string'}],
                    'stateMutability': 'view',
                    'type': 'function'
                },
                {
                    'inputs': [{'internalType': 'string', 'name': 'hash', 'type': 'string'},
                                {'internalType': 'string', 'name': 'url', 'type': 'string'}],
                    'name': 'uploadFile',
                    'outputs': [],
                    'stateMutability': 'nonpayable',
                    'type': 'function'
                }
            ]

            # Instantiate contract
            contract = web3.eth.contract(address=contract_address, abi=contract_abi)
            sender_address = '0x31A5826B4cF87fB437CFBa47504959F49F91A051'

            # Construct the file URL
            file_url = f'https://{settings.AZURE_ACCOUNT_NAME}.blob.core.windows.net/{settings.AZURE_CONTAINER}/{file_name}'

            # Store file metadata in Ethereum and database
            tx_hash = contract.functions.uploadFile(file_hash, file_url).transact({'from': sender_address})
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

            # Store file metadata in the database
            UploadedFile.objects.create(file_name=file_name, file_url=file_url, file_hash=file_hash,
                                            user_id=request.user.id)

            # Upload file to Azure Blob Storage
            azure_storage = AzureStorage(
                account_name=settings.AZURE_ACCOUNT_NAME,
                account_key=settings.AZURE_ACCOUNT_KEY,
                container_name=settings.AZURE_CONTAINER
            )
            file_path = azure_storage.save(file_name, ContentFile(file_content))

             # Verify file integrity
            downloaded_file_content = azure_storage.get(file_path)
            if downloaded_file_content:
                downloaded_file_hash = hashlib.sha256(downloaded_file_content).hexdigest()
                if downloaded_file_hash == file_hash:
                    # File integrity verified
                    db_logger.info("File uploaded successfully and integrity verified.",extra={'user': request.user.username})
                    messages.success(request, 'File uploaded successfully and integrity verified.')
                else:
                    # File integrity check failed
                    db_logger.warning("File integrity check failed. The uploaded file may have been tampered with.",extra={'user': request.user.username})
                    messages.error(request, 'File integrity check failed. The uploaded file may have been tampered with.')
            else:
                # Error downloading file content
                db_logger.error("Error downloading file content.",extra={'user': request.user.username})
                messages.error(request, 'Error downloading file content.')

        else:
            # Add error message if no file is uploaded
            db_logger.error("No file uploaded.",extra={'user': request.user.username})
            messages.error(request, 'No file uploaded.')

    except Exception as e:
        # Log the error
        db_logger.error(f'Error uploading file: {str(e)}',extra={'user': request.user.username})
        # Add error message
        messages.error(request, f'Error uploading file: {str(e)}')

    return render(request, 'dashboard/files.html', {'messages': messages.get_messages(request)})

@login_required
def security_settings(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)

    if user_profile.mfa_enabled and not user_profile.mfa_verified:
        return redirect(reverse('verify_otp')) 

    try:
        user_profile, created = UserProfile.objects.get_or_create(user=request.user)
        if request.method == 'POST':
            mfa_enabled = request.POST.get('mfa_enabled', False) == 'on'
            user_profile.mfa_enabled = mfa_enabled
            user_profile.save()
            db_logger.info("Security settings updated successfully.",extra={'user': request.user.username})
            messages.success(request, 'Security settings updated successfully.')
            return redirect('security')

        return render(request, 'dashboard/security.html', {'mfa_enabled': user_profile.mfa_enabled})
    except Exception as e:
        db_logger.error(f'Error updating security settings: {str(e)}',extra={'user': request.user.username})
        messages.error(request, 'Error updating security settings. Please try again.')
        return redirect('security')


def custom_login(request):
    try:
        if request.method == 'POST':
            form = AuthenticationForm(request, request.POST)
            if form.is_valid():
                user = form.get_user()
                if user is not None:
                    auth_login(request, user)

                    if user.userprofile.mfa_enabled:
                        request.session['mfa_verification_pending'] = True
                        return redirect('verify_otp')
                    else:
                        return redirect('dashboard')
                else:
                    messages.error(request, 'Invalid username or password. Please try again.')
        else:
            form = AuthenticationForm()

        return render(request, 'registration/login.html', {'form': form, 'messages': messages.get_messages(request)})
    except Exception as e:
        db_logger.error(f'Error during login: {str(e)}',extra={'user': request.user.username})
        messages.error(request, 'An error occurred during login. Please try again.')
        return redirect('login')


def logout_view(request):
    try:
        user_profile = request.user.userprofile
        user_profile.mfa_verified = False
        user_profile.save()
        logout(request)
        db_logger.info("User logged out successfully.",extra={'user': request.user.username})
        return redirect('login')
    except Exception as e:
        db_logger.error(f'Error during logout: {str(e)}',extra={'user': request.user.username})
        messages.error(request, 'An error occurred during logout. Please try again.')
        return redirect('login')


@login_required
def verify_otp(request):
    try:
        user_profile = request.user.userprofile
        
        # Check if MFA is enabled for the user
        if not user_profile.mfa_enabled:
            return redirect('dashboard')  # Redirect to the dashboard if MFA is not enabled

        # Check if MFA is already verified
        if user_profile.mfa_verified:
            return redirect('dashboard')  # Redirect to the dashboard if MFA is already verified

        if request.method == 'POST':
            otp = request.POST.get('otp')
            expected_otp = request.session.get('otp')
            if otp == expected_otp:
                del request.session['otp']
                user_profile.mfa_verified = True
                user_profile.save()
                db_logger.info('OTP verification successful', extra={'user': request.user.username})
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
        else:
            user_email = request.user.email
            if user_email:
                otp = '123456'
                request.session['otp'] = otp
                send_mail(
                    'OTP Verification',
                    f'Your OTP is: {otp}',
                    'your-email@gmail.com',
                    [user_email],
                    fail_silently=False,
                )
                db_logger.info(f'OTP sent to {user_email} for user: {request.user.username}', extra={'user': request.user.username})
                return render(request, 'registration/verify_otp.html')
            else:
                messages.error(request, 'No email associated with the user.')
                return redirect('dashboard')
        return render(request, 'registration/verify_otp.html')
    except Exception as e:
        db_logger.error(f'Error during OTP verification: {str(e)}', extra={'user': request.user.username})
        messages.error(request, 'An error occurred during OTP verification. Please try again.')
        return redirect('dashboard')



def retrieve_blockchain_logs(request):
    # Retrieve all logs from the database
    logs = BLockchainLog.objects.all()

    # Create a string with log data
    log_data = ""
    for log in logs:
        log_data += f"{log.create_datetime} | {log.user} | {log.msg}\n"

    # Create the HTTP response with the log data
    response = HttpResponse(log_data, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="blockchain_logs.txt"'
    return response


