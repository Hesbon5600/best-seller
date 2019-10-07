from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.models import AnonymousUser

from api import payments, errors
from api.models import Product, Orders
from api.payments import PaymentError
import logging

logger = logging.getLogger(__name__)


@swagger_auto_schema(method='POST', request_body=openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'stripeToken': openapi.Schema(type=openapi.TYPE_STRING,
                                      description="The API token, you can use this example to get it: https://stripe.com/docs/stripe-js/elements/quickstart",
                                      required=['true']),
        'order_id': openapi.Schema(type=openapi.TYPE_INTEGER,
                                   description="The order ID recorded before (Check the Order Documentation)",
                                   required=['true']),
        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Description to order.", required=['true']),
        'amount': openapi.Schema(type=openapi.TYPE_INTEGER, description="Only numbers like: 999", required=['true']),
        'currency': openapi.Schema(type=openapi.TYPE_STRING,
                                   description="Check here the options: https://stripe.com/docs/currencies",
                                   default='USD')

    }
))
@api_view(['POST'])
def charge(request):
    """
    This method receive a front-end payment and create a charge.
    """
    user = request.user
    if isinstance(user, AnonymousUser):
        logger.error(errors.USR_10.message)
        return errors.handle(errors.USR_10)

    data = request.data
    order_id = data.get('order_id', '')
    amount = data.get('amount', '')
    currency = data.get('currency', '')
    description = data.get('description', '')

    try:
        Orders.objects.get(pk=order_id)
    except Orders.DoesNotExist:
        return errors.handle(errors.ORD_01)
    response = payments.create(amount=amount,
                               order_id=order_id,
                               currency=currency,
                               description=description)
    if response.status != 'succeeded':
        err_data = response.__dict__
        return Response(data={'message': err_data['message'],
                              'status': err_data['status']
                              }, status=err_data['status'])
    response['message'] = 'Payment made successfully!'
    return Response(data=response, status=200)


@api_view(['POST'])
def webhooks(request):
    """
    Endpoint that provide a synchronization
    """
    user = request.user
    if isinstance(user, AnonymousUser):
        logger.error(errors.USR_10.message)
        return errors.handle(errors.USR_10)
    response = payments.create_webhook()
    return Response(data=response, status=201)
