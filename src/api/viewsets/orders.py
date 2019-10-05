from django.contrib.auth.models import AnonymousUser
from django.core.mail import EmailMultiAlternatives
from django.shortcuts import render
from django.utils import timezone
from django.template.loader import render_to_string

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from src.api import errors
from src.api.models import Orders, OrderDetail, ShoppingCart, Product
from src.api.serializers import OrdersSaveSerializer, OrdersSerializer, OrdersDetailSerializer
from src.api.validators import validate_order_input
import logging

from src.turing_backend import settings

logger = logging.getLogger(__name__)


@swagger_auto_schema(method='POST', request_body=openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'cart_id': openapi.Schema(type=openapi.TYPE_STRING, description='Cart ID.', required=['true']),
        'shipping_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Shipping ID.', required=['true']),
        'tax_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Tax ID.', required=['true']),
    }
))
@api_view(['POST'])
def create_order(request):
    """
    Create a Order
    """
    user = request.user
    data = request.data
    if isinstance(user, AnonymousUser):
        logger.error(errors.USR_10.message)
        return errors.handle(errors.USR_10)
    error = validate_order_input(request.data)
    if error:
        return error
    data['customer_id'] = user.customer_id
    data['created_on'] = timezone.now()
    data['status'] = 0
    total = 0
    for item in ShoppingCart.objects.filter(cart_id=data['cart_id']).all():
        product = Product.objects.get(product_id=item.product_id)
        total += product.price * item.quantity if \
            float(product.discounted_price) == 0 else \
            product.discounted_price * item.quantity
    data['total_amount'] = total
    serializer = OrdersSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    return Response(data={'order_id': serializer.save().pk}, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def order(request, order_id):
    """
    Get Info about Order
    """
    user = request.user
    if isinstance(user, AnonymousUser):
        logger.error(errors.USR_10.message)
        return errors.handle(errors.USR_10)
    try:
        order = Orders.objects.get(pk=order_id)
    except Orders.DoesNotExist:
        return errors.handle(errors.ORD_01)
    serializer = OrdersSerializer()
    data = serializer.to_representation(order)
    return Response(data=data, status=status.HTTP_200_OK)


@api_view(['GET'])
def order_details(request, order_id):
    """
    Get Info about Order
    """
    logger.debug("Getting detail info")
    user = request.user
    if isinstance(user, AnonymousUser):
        logger.error(errors.USR_10.message)
        return errors.handle(errors.USR_10)
    try:
        order = Orders.objects.get(pk=order_id)
    except Orders.DoesNotExist:
        return errors.handle(errors.ORD_01)
    data = []
    data= {
        "order_id": order.pk,
        "total_amount": order.total_amount,
        "created_on": order.created_on,
        "shipped_on": order.shipped_on,
        'status': order.status,
        "name": user.username,
    }
    return Response(data=data, status=status.HTTP_200_OK)


@api_view(['GET'])
def orders(request):
    """
    Get orders by Customer
    """
    user = request.user
    if isinstance(user, AnonymousUser):
        logger.error(errors.USR_10.message)
        return errors.handle(errors.USR_10)
    orders = Orders.objects.filter(customer_id=user.customer_id).all()
    data = []
    for order in orders:
        data.append({
            "order_id": order.pk,
            "total_amount": order.total_amount,
            "created_on": order.created_on,
            "shipped_on": order.shipped_on,
            "name": user.username,
        })
    return Response(data=data, status=status.HTTP_200_OK)


@api_view(['GET'])
def test(request):
    context = {
        'order_id': 12334,
        'username': 'John Doe'
    }
    return render(request, 'notify_order.html', context)
