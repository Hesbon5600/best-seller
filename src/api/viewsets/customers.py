import logging
import re
from itertools import groupby

from django.contrib.auth import login
from django.contrib.auth.models import AnonymousUser
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from requests.exceptions import HTTPError
from rest_framework import generics, permissions, status, exceptions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework_simplejwt.views import TokenObtainPairView
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import MissingBackend, AuthTokenError, AuthForbidden
from social_django.utils import load_strategy, load_backend

from src.api import errors, serializers
from src.api.models import Customer
from src.api.serializers import (CustomerSerializer, CreateCustomerSerializer, UpdateCustomerSerializer,
                                 SocialSerializer, CustomerAddressSerializer, LoginSerializer)
from ..renderers import UserJSONRenderer

from src.api.validators import (
    validate_field_required, validate_email,
    validate_password, validate_shipping_region_id,
    valiate_email_password_combination, validate_phone_number,
    validate_extra_fields)

logger = logging.getLogger(__name__)


class CustomerUpdateAPIView(generics.UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    
    @swagger_auto_schema(method="PUT", request_body=CreateCustomerSerializer)
    @api_view(['PUT'])
    def update(self):
        user_data = self.data
        error = validate_password(user_data.get('password', ''))\
            or validate_email(user_data.get('email', ''), action='update', request=self)\
            or validate_phone_number(user_data.get('day_phone', ''))\
            or validate_phone_number(user_data.get('eve_phone', ''))\
            or validate_phone_number(user_data.get('mob_phone', ''))
        if error:
            return error
        serializer = UpdateCustomerSerializer(
            self.user,
            data=user_data,
            partial=True,
            context={'request': self}
        )
        if serializer.is_valid():
            self.check_object_permissions(self, user_data)
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


update_customer = CustomerUpdateAPIView.update


class CustomerRetrieveAPIView(generics.RetrieveAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = CustomerSerializer
    def get(self, request):
        try:
            customer = request.user
        except Customer.DoesNotExist:
            raise exceptions.APIException(
                detail='Customer does not exist', code=404)
        serializer = self.serializer_class(customer)

        return Response(serializer.data, status=status.HTTP_200_OK)


get_update_customer = CustomerRetrieveAPIView.as_view()


# @swagger_auto_schema(method="POST", request_body=CreateCustomerSerializer)
class RegistrationAPIView(generics.CreateAPIView):
    # Allow any user (authenticated or not) to hit this endpoint.
    permission_classes = (permissions.AllowAny,)
    renderer_classes = (UserJSONRenderer,)
    @swagger_auto_schema(method="POST", request_body=CreateCustomerSerializer)
    @api_view(['POST'])

    def post(self):
        serializer_class = CreateCustomerSerializer
        user = self.data
        error = validate_field_required(user, 'username')\
            or validate_field_required(user, 'email')\
            or validate_field_required(user, 'password')\
            or validate_email(user.get('email', ''), action='signup')\
            or validate_password(user.get('password', ''))\
            or validate_shipping_region_id(user.get('shipping_region_id', ''))
        if error:
            return error
        serializer = serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class LoginAPIView(generics.CreateAPIView):
    """
    Takes a set of user credentials and returns an access 
    token the authentication of those credentials.
    """
    logger.debug("Login a customer")
    permission_classes = (permissions.AllowAny,)
    renderer_classes = (UserJSONRenderer,)
    @swagger_auto_schema(method="POST", request_body=LoginSerializer)
    @api_view(['POST'])
    def post(self):
        serializer_class = LoginSerializer
        user = self.data
        error = validate_field_required(user, 'email')\
            or validate_field_required(user, 'password')\
            or validate_email(user.get('email', ''), action='login')\
            or valiate_email_password_combination(user.get('email', ''),
                                                  user.get('password', ''))
        if error:
            return error
        serializer = serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validate(data=user), status=status.HTTP_200_OK)


token_obtain = LoginAPIView.post


class SocialLoginView(generics.GenericAPIView):
    """Log in using facebook"""
    serializer_class = SocialSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        logger.debug("Login a customer")
        """Authenticate user through the access_token"""
        serializer = SocialSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        provider = "facebook"
        strategy = load_strategy(request)

        try:
            backend = load_backend(strategy=strategy, name=provider,
                                   redirect_uri=None)

        except MissingBackend:
            return Response({'error': 'Please provide a valid provider'},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            if isinstance(backend, BaseOAuth2):
                access_token = serializer.data.get('access_token')
            user = backend.do_auth(access_token)
        except HTTPError as error:
            logger.error(str(error))
            return Response({
                "error": {
                    "access_token": "Invalid token",
                    "details": str(error)
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except AuthTokenError as error:
            logger.error(str(error))
            return Response({
                "error": "Invalid credentials",
                "details": str(error)
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            authenticated_user = backend.do_auth(access_token, user=user)

        except HTTPError as error:
            return Response({
                "error": "invalid token",
                "details": str(error)
            }, status=status.HTTP_400_BAD_REQUEST)

        except AuthForbidden as error:
            return Response({
                "error": "invalid token",
                "details": str(error)
            }, status=status.HTTP_400_BAD_REQUEST)

        if authenticated_user and authenticated_user.is_active:
            # generate JWT token
            login(request, authenticated_user)
            refresh = RefreshToken.for_user(user)

            try:
                customer = Customer.objects.get(
                    name=user.first_name + ' ' + user.last_name)
            except Customer.DoesNotExist:
                customer = Customer.objects.create(user_id=user.id, name=user.first_name + ' ' + user.last_name,
                                                   email=user.email)

            serializer_element = CustomerSerializer(customer)
            response = Response({
                'customer': {
                    'schema': serializer_element.data
                },
                'accessToken': 'Bearer ' + str(refresh.access_token),
                'expires_in': '24h'
            }, 200)
            logger.debug("Success")
            return response


@permission_classes((IsAuthenticated,))
@swagger_auto_schema(method="PUT", request_body=CustomerAddressSerializer)
@api_view(['PUT'])
def update_address(request):
    """    
    Update the address from customer
    """
    # TODO: place the code here


class CustomerAddressUpdateAPIView(generics.UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = CustomerAddressSerializer

    def update(self, request):
        user_data = request.data
        error = validate_extra_fields('address_1', user_data.get('address_1', ''), 'USR_16')\
            or validate_extra_fields('address_2', user_data.get('address_2', ''), 'USR_16')\
            or validate_extra_fields('city', user_data.get('city', ''), 'USR_17')\
            or validate_extra_fields('region', user_data.get('region', ''), 'USR_18')\
            or validate_extra_fields('postal_code', user_data.get('postal_code', ''), 'postal_code')\
            or validate_shipping_region_id(user_data.get('shipping_region_id', ''))
        if error:
            return error
        serializer = UpdateCustomerSerializer(
            request.user,
            data=user_data,
            partial=True,
            context={'request': request}
        )
        if serializer.is_valid():
            self.check_object_permissions(request, user_data)
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


update_address = CustomerAddressUpdateAPIView.as_view()


def count_consecutive(num):
    return max(len(list(g)) for _, g in groupby(num))


def validate_credit_card(num):
    logger.debug("Validating credit card")
    pattern = re.compile(r'(?:\d{4}-){3}\d{4}|\d{16}')

    if not pattern.fullmatch(num) or count_consecutive(num.replace('-', '')) >= 4:
        return False
    else:
        return True


@swagger_auto_schema(method='PUT', request_body=openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'credit_card': openapi.Schema(type=openapi.TYPE_STRING, description='Credit Card.', required=['true']),
    }
))
@api_view(['PUT'])
def update_credit_card(request):
    """    
    Update the credit card from customer
    """
    logger.debug("Updating credit card")
    if 'credit_card' in request.data:

        if not validate_credit_card(request.data.get('credit_card')):
            logger.error(errors.USR_08.message)
            return errors.handle(errors.USR_08)

        try:
            customer = request.user.customer
            customer.credit_card = request.data.get('credit_card', None)
            customer.save()
            serializer_element = CustomerSerializer(customer)
            logger.debug("Success")
            return Response(serializer_element.data)
        except AttributeError:
            logger.error(errors.USR_10.message)
            return errors.handle(errors.USR_10)
        except Exception as error:
            errors.COM_02.message = str(error)
            logger.error(errors.COM_02.message)
            return errors.handle(errors.COM_02)
    else:
        errors.COM_02.field = 'credit_card'
        logger.error(errors.COM_02.message)
        return errors.handle(errors.COM_02)
