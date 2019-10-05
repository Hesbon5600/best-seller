import uuid

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import api_view, action
from rest_framework.response import Response
from rest_framework import status

from src.api import errors
from src.api.models import ShoppingCart, Product
from src.api.serializers import ShoppingcartSerializer, ProductSerializer, UpdateShoppingcartSerializer
from src.api.validators import validate_shopping_cart_input, validate_cart_ids, validate_field_required
import logging

logger = logging.getLogger(__name__)


@api_view(['GET'])
def generate_cart_id(request):
    """
    Generate the unique CART ID 
    """
    logger.debug("Generating cart ID")
    return Response({"cart_id": uuid.uuid4()})


@swagger_auto_schema(method='POST', request_body=openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'cart_id': openapi.Schema(type=openapi.TYPE_STRING, description='Cart ID.', required=['true']),
        'product_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Product ID.', required=['true']),
        'attributes': openapi.Schema(type=openapi.TYPE_STRING, description='Attributes of Product.', required=['true']),
        'quantity': openapi.Schema(type=openapi.TYPE_INTEGER, description='Quantity of Product.', required=['true']),
    }
))
@api_view(['POST'], )
def add_products(request):
    """
    Add a Product in the cart
    """
    error = validate_shopping_cart_input(request.data)
    if error:
        return error
    data = request.data
    serializer_class = ShoppingcartSerializer(data=data)
    serializer_class.is_valid(raise_exception=True)
    serializer_class.save()
    return Response(serializer_class.data, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_products(request, cart_id):
    """
    Get List of Products in Shopping Cart
    """
    error = validate_cart_ids(cart_id, 'cart_id')
    if error:
        return error
    data = ShoppingCart.objects.filter(cart_id=cart_id).all()
    serializer_class = ShoppingcartSerializer()
    return Response(serializer_class.shopping_cart_products(data=data), status=status.HTTP_200_OK)


@swagger_auto_schema(method='PUT', request_body=openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'quantity': openapi.Schema(type=openapi.TYPE_INTEGER, description='Item Quantity.', required=['true'])
    }
))
@api_view(['PUT'])
def update_quantity(request, item_id):
    """
    Update the cart by item
    """
    logger.debug("Updating quantity")
    error = None
    quantity = request.data.get('quantity', '')
    error = errors.handle(
        errors.Error(code="COM_10", message="Quantity must be a number not less than 1",
                     _status=400)) if not isinstance(quantity, int) or quantity < 1 else error
    invalid_qty = validate_field_required(request.data, 'quantity', 'COM_01')
    invalid_id = validate_cart_ids(item_id, 'item_id')
    error = invalid_qty if invalid_qty else error
    error = invalid_id if invalid_id else error
    if error:
        return error
    cart = ShoppingCart.objects.get(item_id=item_id)
    serializer_class = UpdateShoppingcartSerializer(
        cart,
        data=request.data,
        partial=True,
    )
    serializer_class.is_valid(raise_exception=True)
    serializer_class.update(cart, request.data)
    import pdb
    pdb.set_trace()
    return Response(serializer_class.data, status=status.HTTP_200_OK)


@api_view(['DELETE'])
def empty_cart(request, cart_id):
    """
    Empty cart
    """
    error = validate_cart_ids(cart_id, 'cart_id')
    if error:
        return error
    cart = ShoppingCart.objects.filter(cart_id=cart_id).all()
    for each in cart:
        each.delete()
    return Response(data=[], status=status.HTTP_200_OK)


@api_view(['DELETE'])
def remove_product(request, item_id):
    """
    Remove a product in the cart
    """
    error = validate_cart_ids(item_id, 'item_id')
    if error:
        return error
    item = ShoppingCart.objects.filter(item_id=item_id)
    item.delete()
    return Response(data={'message': 'Item deleted successfully'}, status=status.HTTP_200_OK)


@api_view(['GET'])
def move_to_cart(request, item_id):
    """
    Move a product to cart
    """
    # TODO: place the code here


@api_view(['GET'])
def total_amount(request, cart_id):
    """
    Return a total Amount from Cart
    """
    error = validate_cart_ids(cart_id, 'cart_id')
    if error:
        return error
    cart_items = ShoppingCart.objects.filter(cart_id=cart_id)

    total = 0
    for item in cart_items:
        product = Product.objects.get(product_id=item.product_id)
        total += product.price * item.quantity if \
            float(product.discounted_price) == 0 else \
            product.discounted_price * item.quantity
    return Response(data={'total': total}, status=status.HTTP_200_OK)


@api_view(['GET'])
def save_for_later(request, item_id):
    """
    Save a Product for latter
    """
    # TODO: place the code here


@api_view(['GET'])
def get_saved_products(request, cart_id):
    """
    Get saved Products 
    """
    # TODO: place the code here
