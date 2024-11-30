from __future__ import unicode_literals
import logging
import csv

from django.contrib import admin
from django.utils import timezone
from django.utils.html import format_html
from django.http import HttpResponse

from .models import StatusLog, BLockchainLog
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

# Import Web3 library
from web3 import Web3

# Connect to Ganache Ethereum node
ganache_url = 'http://127.0.0.1:7545'
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Load contract ABI and address
contract_address = "0x25376eE9Db64229a7Ff27507959029752797f1DC"
contract_abi = [{'anonymous': False, 'inputs': [{'indexed': True, 'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}, {'indexed': False, 'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}, {'indexed': True, 'internalType': 'address', 'name': 'user', 'type': 'address'}, {'indexed': False, 'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'indexed': False, 'internalType': 'string', 'name': 'message', 'type': 'string'}, {'indexed': False, 'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'name': 'LogAdded', 'type': 'event'}, {'anonymous': False, 'inputs': [{'indexed': True, 'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}, {'indexed': True, 'internalType': 'address', 'name': 'deleter', 'type': 'address'}, {'indexed': False, 'internalType': 'uint256', 'name': 'deletedTimestamp', 'type': 'uint256'}, {'indexed': False, 'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'indexed': False, 'internalType': 'string', 'name': 'message', 'type': 'string'}, {'indexed': False, 'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'name': 'LogDeleted', 'type': 'event'}, {'anonymous': False, 'inputs': [{'indexed': True, 'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}, {'indexed': True, 'internalType': 'address', 'name': 'editor', 'type': 'address'}, {'indexed': False, 'internalType': 'string', 'name': 'oldMessage', 'type': 'string'}, {'indexed': False, 'internalType': 'string', 'name': 'newMessage', 'type': 'string'}], 'name': 'LogEdited', 'type': 'event'}, {'inputs': [{'internalType': 'uint256', 'name': '_level', 'type': 'uint256'}, {'internalType': 'string', 'name': '_message', 'type': 'string'}, {'internalType': 'string', 'name': '_traceback', 'type': 'string'}], 'name': 'addLog', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'}, {'inputs': [{'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}], 'name': 'deleteLog', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'}, {'inputs': [{'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}, {'internalType': 'string', 'name': 'newMessage', 'type': 'string'}], 'name': 'editLog', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'}, {'inputs': [], 'name': 'getAllLogs', 'outputs': [{'components': [{'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}, {'internalType': 'address', 'name': 'user', 'type': 'address'}, {'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'internalType': 'string', 'name': 'message', 'type': 'string'}, {'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'internalType': 'struct AdminLogger.Log[]', 'name': '', 'type': 'tuple[]'}], 'stateMutability': 'view', 'type': 'function'}, {'inputs': [{'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}], 'name': 'getLog', 'outputs': [{'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}, {'internalType': 'address', 'name': 'user', 'type': 'address'}, {'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'internalType': 'string', 'name': 'message', 'type': 'string'}, {'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'stateMutability': 'view', 'type': 'function'}, {'inputs': [], 'name': 'getLogsCount', 'outputs': [{'internalType': 'uint256', 'name': '', 'type': 'uint256'}], 'stateMutability': 'view', 'type': 'function'}, {'inputs': [{'internalType': 'uint256', 'name': '', 'type': 'uint256'}], 'name': 'logs', 'outputs': [{'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}, {'internalType': 'address', 'name': 'user', 'type': 'address'}, {'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'internalType': 'string', 'name': 'message', 'type': 'string'}, {'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'stateMutability': 'view', 'type': 'function'}]

# Create contract instance
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

# Define sender address
sender_address = '0x31A5826B4cF87fB437CFBa47504959F49F91A051'

def add_log_to_contract(user_address, level, message, traceback):
    # Convert level to uint256
    level_uint256 = int(level)
    # Convert message and traceback to string
    message_str = str(message)
    traceback_str = str(traceback)
    # Call the addLog function with the converted arguments
    tx_hash = contract.functions.addLog(level_uint256, message_str, traceback_str).transact({'from': user_address})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

# Define custom UserAdmin
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'get_groups')

    def get_groups(self, obj):
        return ', '.join([group.name for group in obj.groups.all()])
    get_groups.short_description = 'Groups'

# Unregister default UserAdmin and register CustomUserAdmin
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

# Define StatusLogAdmin
class StatusLogAdmin(admin.ModelAdmin):
    list_display = ('colored_msg', 'traceback', 'create_datetime_format', 'user')
    list_display_links = ('colored_msg',)
    list_filter = ('level',)
    list_per_page = 10

    def colored_msg(self, instance):
        if instance.level in [logging.NOTSET, logging.INFO]:
            color = 'green'
        elif instance.level in [logging.WARNING, logging.DEBUG]:
            color = 'orange'
        else:
            color = 'red'
        return format_html('<span style="color: {color};">{msg}</span>', color=color, msg=instance.msg)

    colored_msg.short_description = 'Message'

    def traceback(self, instance):
        return format_html('<pre><code>{content}</code></pre>', content=instance.trace if instance.trace else '')

    def create_datetime_format(self, instance):
        return timezone.localtime(instance.create_datetime).strftime('%Y-%m-%d %X')

    create_datetime_format.short_description = 'Created at'

# Register StatusLogAdmin
admin.site.register(StatusLog, StatusLogAdmin)


from django.db.models.signals import post_save
from django.dispatch import receiver

# Signal handler to add log to the contract and save to the database when a StatusLog instance is created
@receiver(post_save, sender=StatusLog)
def handle_status_log_creation(sender, instance, created, **kwargs):
    if created:
        # Save log to the database
        instance.save()

        # Save log to the BlockchainLog model
        blockchain_log = BLockchainLog.objects.create(
            logger_name=instance.logger_name,
            level=instance.level,
            msg=instance.msg,
            trace=instance.trace,
            create_datetime=instance.create_datetime,
            user=instance.user
        )

        # Trigger function to add log to smart contract
        add_log_to_contract(sender_address, instance.level, instance.msg, instance.trace)

