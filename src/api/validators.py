import re
from . import errors
from src.api.models import Customer, ShippingRegion
from django.contrib.auth import authenticate


def does_not_exist(code, attribute, field):
    error = errors.Error(code=f"{code}", message=f"The {attribute} doesn't exist",
                         _status=404, field=field)
    return errors.handle(error)


def validate_field_required(data, field):
    if not data.get(field, ''):
        return errors.handle(errors.Error(
            code="USR_02",
            message="This field is required",
            _status=400,
            field=field))


def validate_email(email, action, request=None):
    regex = r"[^@]+@[^@]+\.[^@]+"
    if email and not re.match(regex, email):
        return errors.handle(errors.USR_03)
    if action == 'signup' and Customer.objects.filter(email=email).exists():
        return errors.handle(errors.USR_04)
    if action == 'update' and email:
        if Customer.objects.filter(email=email) == request.user:
            return errors.handle(errors.USR_04)


def validate_password(password):
    regex = r"^(?=.{8,}$)(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).*"
    if password and not re.match(regex, password):
        return errors.handle(errors.USR_11)


def validate_phone_number(phone_no):
    if phone_no and '+' not in phone_no or len(phone_no) < 8:
        return errors.handle(errors.USR_06)


def validate_shipping_region_id(id_):
    if not isinstance(id_, int):
        return errors.handle(errors.USR_09)

    if not ShippingRegion.objects.filter(shipping_region_id=id_).exists():
        return does_not_exist('USR_09', 'Shipping Region ID ', 'shipping_region')


def valiate_email_password_combination(email, password):
    if not authenticate(username=email, password=password):
        return errors.handle(errors.USR_01)
