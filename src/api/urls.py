import logging

from django.urls import path, include
from rest_framework import routers

from src.api.viewsets.attribute import AttributeViewSet
#from src.api.viewsets.category import CategoryViewSet 
# TODO: Implement category
from src.api.viewsets.customers import create_customer, token_obtain, SocialLoginView, update_address, \
    update_credit_card, update_customer, get_customer
from src.api.viewsets.department import DepartmentViewSet
from src.api.viewsets.orders import create_order, order, orders, order_details
from src.api.viewsets.products import ProductViewSet
from src.api.viewsets.shipping_region import ShippingRegionViewSet
from src.api.viewsets.shoppingcart import generate_cart_id, add_products, get_products, update_quantity, empty_cart, \
    remove_product, move_to_cart, total_amount, save_for_later, get_saved_products
from src.api.viewsets.stripe import charge, webhooks
from src.api.viewsets.tax import TaxViewSet

logger = logging.getLogger(__name__)

router = routers.DefaultRouter()
router.register(r'departments', DepartmentViewSet)

router.register(r'attributes', AttributeViewSet)
router.register(r'products', ProductViewSet)
router.register(r'tax', TaxViewSet)
router.register(r'shipping/regions', ShippingRegionViewSet)

urlpatterns = [
    path('', include(router.urls)),
    # TODO: implement the category, shopping cart and orders

    path('attributes/values/<int:attribute_id>/', AttributeViewSet.as_view({"get": "get_values_from_attribute"})),
    path('attributes/inProduct/<int:product_id>/', AttributeViewSet.as_view({"get": "get_attributes_from_product"})),

    path('products/inCategory/<int:category_id>', ProductViewSet.as_view({"get": "get_products_by_category"})),
    path('products/inDepartment/<int:department_id>', ProductViewSet.as_view({"get": "get_products_by_department"})),

    path('customer/update', update_customer),

    path('customers', create_customer, name="Create a customer"),
    path('customer', get_customer, name="Get or updatee a customer"),
    path('customers/login', token_obtain, name="Login a customer"),
    path('customers/facebook', SocialLoginView.as_view()),
    path('customers/address', update_address),
    path('customers/creditCard', update_credit_card),

]
