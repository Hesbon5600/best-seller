import re
from . import errors
from src.api.models import Customer, ShippingRegion, Product, ShoppingCart
from django.contrib.auth import authenticate


def does_not_exist(code, attribute, field):
    """Check if the field exists in the database

    Args:
        code (str): The error code
        attribute (str): Attribute being validated (Eg: Shipping Region ID)
        field (str): related field being validated (Eg: shipping_region)
    Returns:
        ValidationError: Raise the relevant validation error
    """
    error = errors.Error(code=f"{code}", message=f"The {attribute} doesn't exist",
                         _status=404, field=field)
    return errors.handle(error)


def invalid_(code, attribute, field):
    """Check if the field is valid

    Args:
        code (str): The error code
        attribute (str): Attribute being validated (Eg: Shipping Region ID)
        field (str): related field being validated (Eg: shipping_region)
    Returns:
        ValidationError: Raise the relevant validation error if the field is invalid
    """
    return errors.handle(errors.Error(code=f"{code}",
                                      message=f"This is an invalid {attribute}",
                                      _status=404, field=field))


def empty_field_value(code, field):
    """Check if the field is valid

    Args:
        code (str): The error code
        field (str): related field being validated (Eg: shipping_region)
    Returns:
        ValidationError: Raise the relevant validation error if the field is empty
    """
    return errors.handle(errors.Error(code=f"{code}",
                                      message=f"This field cannot be empty",
                                      _status=404, field=field))


def validate_field_required(data, field, code='USR_02'):
    """Check if the field exists in the requeest object

    Args:
        data (dict): request data
        field (str): related field being validated (Eg: email)
    Returns:
        ValidationError: Raise the relevant validation error if the field does not exist
    """
    if field not in data:
        return errors.handle(errors.Error(
            code=f"{code}",
            message="This field is required",
            _status=400,
            field=field))


def validate_email(email, action, request=None):
    """Validate the email address depending on the action 
    Args:
        email (str): email being validated
        action (str): the action baing done (Eg: signup, login, update)
        request (obj): the http request object
    Returns:
        ValidationError: Raise the relevant validation error if the email is invalid
        or already exists
    """
    email = email.strip()

    regex = r"[^@]+@[^@]+\.[^@]+"
    if email and not re.match(regex, email):
        return errors.handle(errors.USR_03)
    if action == 'signup' and Customer.objects.filter(email=email).exists():
        return errors.handle(errors.USR_04)
    if action == 'update' and email:
        if Customer.objects.filter(email=email) == request.user:
            return errors.handle(errors.USR_04)


def validate_password(password):
    """Validate the password
    Args:
        password (str): password to be validated
    Returns:
        ValidationError: Raise the relevant validation error if the password is invalid
    """
    password = password.strip()
    regex = r"^(?=.{8,}$)(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).*"
    if password and not re.match(regex, password):
        return errors.handle(errors.USR_11)


def valiate_email_password_combination(email, password):
    """Validate the shipping email and password combination
    Args:
        email (str): email
        password (str): password
    Returns:
        ValidationError: Raise a validation error 
        if the email and password combination is invalid
    """
    if not authenticate(username=email.strip(), password=password.strip()):
        return errors.handle(errors.USR_01)


def validate_phone_number(phone_no):
    """Validate the phone number
    Args:
        phone_no (str): phone number to be validated
    Returns:
        ValidationError: Raise the relevant validation error if the phone number is invalid
    """
    phone_no = phone_no.strip()
    if phone_no and '+' not in phone_no or len(phone_no) < 8:
        return invalid_('USR_06', 'phone number', 'phone')


def validate_address(address, address_type):
    """Validate the address
    Args:
        address (str): address to be validated
        address_type (str): address_type (Eg: address_1, address_2)
    Returns:
        ValidationError: Raise the relevant validation error if the address is invalid
    """
    address, address_type = address.strip(), address_type.strip()
    error = None
    if not address:
        error = empty_field_value('USR_17', address_type)
    if not isinstance(address, str):
        error = invalid_('USR_16', 'address', f'{address_type}')
    return error


def validate_extra_fields(field, field_value, code):
    """Validate the field for empty value and non string
    Args:
        field (str): field being validated
        field_value (str): field value to be validated
        code (str): error code
    Returns:
        ValidationError: Raise the relevant validation error if the
        field value is empty of invalid
    """
    error = None
    if not field_value.strip():
        error = empty_field_value('USR_17', field)
    if not isinstance(field_value.strip(), str):
        error = invalid_(f'{code}', f'{field}', f'{field}')
    return error


def validate_shipping_region_id(id_):
    """Validate the shipping region id
    Args:
        id_ (int): shipping region id to be validated
    Returns:
        ValidationError: Raise the relevant validation error 
        if the shipping region id is invalid or does not exis
    """
    if not isinstance(id_, int):
        return errors.handle(errors.USR_09)

    if not ShippingRegion.objects.filter(shipping_region_id=id_).exists():
        return does_not_exist('USR_09', 'Shipping Region ID ', 'shipping_region')


def validate_cart_ids(id_, attribute):
    """Validate the cart id or cart item id
    Args:
        id_ (int/str): cart id to be validated
        attribute (str): cart id to be validated
    Returns:
        ValidationError: Raise the relevant validation error 
        if the id does not exis in the db
    """
    error = None
    if attribute == 'cart_id' and \
        not ShoppingCart.objects.filter(cart_id=id_).exists():
        error = errors.handle(errors.SHP_01)
    if attribute == 'item_id' and \
        not ShoppingCart.objects.filter(item_id=id_).exists():
        error = errors.Error(code="COM_10", message="Don't exist shopping cart item with this item_id",
                         _status=400)
    return error


def validate_review_and_rating(data):
    """Validate the customer review and rating
    Args:
        data (dict): the request data
    Returns:
        ValidationError: Raise the relevant validation error 
        if the fields are missing or invalid
    """
    error = None
    review_none, rating_none = validate_field_required(
        data, 'review', 'COM_01'), validate_field_required(data, 'rating', 'COM_01')
    if review_none or rating_none:
        error = review_none or rating_none
    review = data.get('review', '')
    rating = data.get('rating', '')
    if not isinstance(review, str):
        error = errors.handle(
            errors.Error(code="COM_10", message="Review must be a string",
                         _status=400))
    if not isinstance(rating, int) or (rating < 0 or rating > 5):
        error = errors.handle(
            errors.Error(code="COM_10", message="Review must be a number between 0 and 5",
                         _status=400))
    return error


def validate_shopping_cart_input_types(data):
    """Validate the shopping cart input types
    Args:
        data (dict): the request data
    Returns:
        ValidationError: Raise the relevant validation error 
        if the fields are invalid
    """
    error = None
    cart_id = data.get('cart_id', '')
    product_id = data.get('product_id', '')
    attributes = data.get('attributes', '')
    quantity = data.get('quantity', '')
    if not isinstance(cart_id, str):
        error = errors.handle(
            errors.Error(code="COM_10", message="Cart ID must be a string",
                         _status=400))
    if not isinstance(attributes, str):
        error = errors.handle(
            errors.Error(code="COM_10", message="Attributes must be a string",
                         _status=400))
    if not isinstance(product_id, int):
        error = errors.handle(
            errors.Error(code="COM_10", message="Product ID must be a number",
                         _status=400))
    if not isinstance(quantity, int) or quantity < 1:
        error = errors.handle(
            errors.Error(code="COM_10", message="Quantity must be a number not less than 1",
                         _status=400))
    if not Product.objects.filter(product_id=product_id):
        error = errors.handle(errors.PRO_01)
    return error


def validate_shopping_cart_input(data):
    """Validate the shopping cart data
    Args:
        data (dict): the request data
    Returns:
        ValidationError: Raise the relevant validation error 
        if the fields are missing or invalid
    """
    error = None
    cart_id_err, product_id_err, attributes_err, quantity_err = validate_field_required(
        data, 'cart_id', 'COM_01'), validate_field_required(data, 'product_id', 'COM_01'),\
        validate_field_required(data, 'attributes', 'COM_01'),\
        validate_field_required(data, 'quantity', 'COM_01')
    if cart_id_err or product_id_err or attributes_err or quantity_err:
        error = cart_id_err or product_id_err or attributes_err or quantity_err
    invalid = validate_shopping_cart_input_types(data)
    if invalid:
        error = invalid
    return error
