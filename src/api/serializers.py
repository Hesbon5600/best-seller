from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate

# from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from src.api.models import Department, Category, Attribute, AttributeValue, Product, Customer, Shipping, Tax, ShoppingCart, \
    Orders, OrderDetail, ShippingRegion, Review

from src.turing_backend.authentication.token import generate_token


class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = '__all__'


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ('category_id', 'name', 'description', 'department_id')


class AttributeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attribute
        fields = '__all__'


class AttributeValueSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttributeValue
        fields = ('attribute_value_id', 'value')


class AttributeValueExtendedSerializer(serializers.ModelSerializer):
    attribute_name = serializers.ReadOnlyField(source='attribute.name')
    attribute_value = serializers.ReadOnlyField(source='value')

    class Meta:
        model = AttributeValue
        fields = ('attribute_name', 'attribute_value_id', 'attribute_value')


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ('product_id', 'name', 'description',
                  'price', 'discounted_price', 'thumbnail')


class OrdersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Orders
        fields = '__all__'


class OrdersDetailSerializer(serializers.ModelSerializer):
    total_amount = serializers.ReadOnlyField(source='order.total_amount')
    created_on = serializers.ReadOnlyField(source='order.created_on')
    shipped_on = serializers.ReadOnlyField(source='order.shipped_on')
    status = serializers.ReadOnlyField(source='order.status')
    name = serializers.ReadOnlyField(source='product_name')

    class Meta:
        model = OrderDetail
        fields = ('order_id', 'total_amount', 'created_on',
                  'shipped_on', 'status', 'name')


class OrdersSaveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Orders
        fields = ('tax_id', 'shipping_id')


class ShoppingcartSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShoppingCart
        fields = ('cart_id', 'attributes', 'product_id', 'quantity')


class TaxSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tax
        fields = '__all__'


class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ('product_id', 'review',
                  'customer_id', 'rating', 'created_on')


class ShippingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shipping
        fields = '__all__'


class ShippingRegionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShippingRegion
        fields = '__all__'


class CustomerSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = Customer
        fields = '__all__'


class CreateCustomerSerializer(serializers.ModelSerializer):
    """Serializers registration requests and creates a new user."""
    # Ensure email is provided and is unique
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    username = serializers.CharField(required=True)
    shipping_region_id = serializers.IntegerField(required=True)
    token = serializers.ListField(read_only=True)

    class Meta:
        model = Customer
        # List all of the fields that could possibly be included in a request
        # or response, including fields specified explicitly above.
        fields = '__all__'

    def create(self, validated_data):
        # Use the `create_user` method we wrote earlier to create a new user.
        return Customer.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.ListField(read_only=True)

    def validate(self, data):
        """ The `validate` method is where we make sure that the current
         instance of `LoginSerializer` has "valid". In the case of logging a
         user in, this means validating that they've provided an email
         and password and that this combination matches one of the users in
         our database. 
         """
        email = data.get('email', None)
        password = data.get('password', None)

        # The `authenticate` method is provided by Django and handles checking
        # for a user that matches this email/password combination. Notice how
        # we pass `email` as the `username` value. Remember that, in our User
        # model, we set `USERNAME_FIELD` as `email`.
        user = authenticate(username=email, password=password)

        # The `validate` method should return a dictionary of validated data.
        # This is the data that is passed to the `create` and `update` methods
        # that we will see later on.
        return {
            "customer_id": user.customer_id,
            'email': user.email,
            'username': user.username,
            "address_1": user.address_1,
            "address_2": user.address_2,
            "city": user.city,
            "region": user.region,
            "postal_code": user.postal_code,
            "shipping_region_id": user.shipping_region_id,
            "credit_card": user.credit_card,
            "day_phone": user.day_phone,
            "eve_phone": user.eve_phone,
            "mob_phone": user.mob_phone,
            'token': user.token,
        }


class UpdateCustomerSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        allow_blank=True, required=False, write_only=True)
    name = serializers.CharField(allow_blank=True, required=False)
    email = serializers.CharField(allow_blank=True, required=False)
    day_phone = serializers.CharField(allow_blank=True, required=False)
    eve_phone = serializers.CharField(allow_blank=True, required=False)
    mob_phone = serializers.CharField(allow_blank=True, required=False)

    class Meta:
        model = Customer
        fields = '__all__'


class SocialSerializer(serializers.Serializer):
    """
    Serializer which accepts an OAuth2 access token.
    """

    access_token = serializers.CharField(
        max_length=4096, required=True, trim_whitespace=True)

    class Meta:
        fields = 'access_token'


class CustomerAddressSerializer(serializers.Serializer):
    address_1 = serializers.CharField(max_length=256, required=True)
    address_2 = serializers.CharField(
        max_length=256, required=False, allow_null=True)
    city = serializers.CharField(max_length=256, required=True)
    region = serializers.CharField(max_length=256, required=True)
    postal_code = serializers.CharField(max_length=256, required=True)
    country = serializers.CharField(max_length=256, required=True)
    shipping_region_id = serializers.IntegerField(required=True)
    password = serializers.CharField(required=False, write_only=True)

    class Meta:
        fields = '__all__'


class CreditCardSerializer(serializers.Serializer):
    credit_card = serializers.CharField(max_length=256)

    class Meta:
        fields = 'credit_card'
