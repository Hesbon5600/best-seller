"""JWT Configuration"""
import jwt
from django.conf import settings
from rest_framework import authentication, exceptions
from rest_framework.exceptions import AuthenticationFailed
from src.api.models import Customer
from django.conf import settings


class JWTAuthentication(authentication.BaseAuthentication):
    """
    This is called on every request to check if the user is authenticated
    """

    def authenticate(self, request):
        """This method authenticates the token and the provided credentials"""
        exceptions.AuthenticationFailed
        auth_header = authentication.get_authorization_header(
            request).decode('utf-8')
        if not auth_header or auth_header.split()[0].lower() != 'bearer':

            return None
        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms="HS256", )
        except Exception as error:
            exception_mapper = {
                jwt.ExpiredSignatureError: 'Token expired. Please login to get a new token',
                jwt.DecodeError: 'Authorization failed due to an Invalid token.Authorization failed due to an Invalid token.',
                jwt.InvalidIssuerError: "Cannot verify the token provided as the expected issuer does not match.",
            }
            message = exception_mapper.get(
                type(error), 'Authorization failed.Authorization failed.')
            raise exceptions.AuthenticationFailed(message)
        try:
            user = Customer.objects.get(email=payload['email'])
        except Customer.DoesNotExist:
            raise exceptions.AuthenticationFailed("User does not exist")

        return user, token
