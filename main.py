# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


#def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
 #   print(f'Hi, {name}')  # Press ⌘F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
#if __name__ == '__main__':
#    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

from botbuilder.core import TurnContext, MessageFactory
from botbuilder.schema import ActivityTypes
from botbuilder.core.adapters import BotFrameworkAdapter, BotFrameworkAdapterSettings
from flask import Flask, request, Response
from cryptography.fernet import Fernet
import re

app = Flask(__name__)
adapter_settings = BotFrameworkAdapterSettings("", "")
adapter = BotFrameworkAdapter(adapter_settings)

# Sensitive data detection function
def detect_sensitive_data(text):
    patterns = {
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'dob': r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
        'ssn': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
    }

    detected_data = {}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            detected_data[key] = matches

    return detected_data

# Encryption and decryption functions
def generate_key():
    return Fernet.generate_key()

def encrypt(text, key):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode('utf-8'))
    return encrypted_text

def decrypt(encrypted_text, key):
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text)
    return decrypted_text.decode('utf-8')

encryption_key = generate_key()

async def on_message_activity(turn_context: TurnContext):
    text = turn_context.activity.text
    detected_data = detect_sensitive_data(text)

    if detected_data:
        encrypted_text = encrypt(text, encryption_key)
        response_text = f"Encrypted message: {encrypted_text}"
    else:
        response_text = f"Your message: {text}"

    activity = MessageFactory.text(response_text)
    await turn_context.send_activity(activity)

@app.route("/api/messages", methods=["POST"])
def messages():
    if "application/json" in request.headers["Content-Type"]:
        body = request.json
    else:
        return Response(status=415)

    activity = Activity().deserialize(body)
    auth_header = request.headers.get("Authorization", "")

    async def aux_func(turn_context: TurnContext):
        await on_message_activity(turn_context)

    try:
        task = loop.run_until_complete(adapter.process_activity(activity, auth_header, aux_func))
        return Response(status=201)
    except Exception as exception:
        raise exception

if __name__ == "__main__":
    try:
        import nest_asyncio
        nest_asyncio.apply()
        import asyncio
        loop = asyncio.get_event_loop()
        app.run("localhost", port=3978)
    except Exception as error:
        raise error

