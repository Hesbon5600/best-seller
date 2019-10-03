# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
import jwt

from datetime import datetime, timedelta

from django.db import models

from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)


class UserManager(BaseUserManager):
    """
    Django requires that custom users define their own Manager class. By
    inheriting from `BaseUserManager`, we get a lot of the same code used by
    Django to create a `User` for free. 

    All we have to do is override the `create_user` function which we will use
    to create `User` objects.
    """

    def create_user(self, username, email, shipping_region_id, password=None, **kwargs):
        """Create and return a `User` with an email, username and password."""
        if username is None:
            raise TypeError('Users must have a username.')

        if email is None:
            raise TypeError('Users must have an email address.')

        user = self.model(username=username, email=self.normalize_email(
            email), shipping_region_id=shipping_region_id)
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, username, email, password):
        """
        Create and return a `User` with superuser powers.

        Superuser powers means that this use is an admin that can do anything
        they want.
        """
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user


class Attribute(models.Model):
    attribute_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'attribute'


class AttributeValue(models.Model):
    attribute_value_id = models.AutoField(primary_key=True)
    attribute_id = models.IntegerField()
    value = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'attribute_value'


class Audit(models.Model):
    audit_id = models.AutoField(primary_key=True)
    order_id = models.IntegerField()
    created_on = models.DateTimeField()
    message = models.TextField()
    code = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'audit'


class Category(models.Model):
    category_id = models.AutoField(primary_key=True)
    department_id = models.IntegerField()
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=1000, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'category'


class Customer(AbstractBaseUser):
    """
    Customer model
    """
    customer_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50)
    email = models.CharField(unique=True, max_length=100)
    password = models.CharField(max_length=100)
    credit_card = models.TextField(blank=True, null=True)
    address_1 = models.CharField(max_length=100, blank=True, null=True)
    address_2 = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    shipping_region_id = models.IntegerField()
    day_phone = models.CharField(max_length=100, blank=True, null=True)
    eve_phone = models.CharField(max_length=100, blank=True, null=True)
    mob_phone = models.CharField(max_length=100, blank=True, null=True)

    # The `USERNAME_FIELD` property tells us which field we will use to log in.
    # In this case, we want that to be the email field.
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    # Tells Django that the UserManager class defined above should manage
    # objects of this type.
    objects = UserManager()

    def __str__(self):
        """
        Returns a string representation of this `Customer`.

        This string is used when a `Customer` is printed in the console.
        """
        return self.email

    @property
    def token(self):
        """
        This method generates and returns a string of the token generated.
        """
        from src.turing_backend.authentication.token import generate_token
        return generate_token(self.email)

    class Meta:
        managed = False
        db_table = 'customer'


class Department(models.Model):
    department_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=1000, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'department'


class OrderDetail(models.Model):
    item_id = models.AutoField(primary_key=True)
    order_id = models.IntegerField()
    product_id = models.IntegerField()
    attributes = models.CharField(max_length=1000)
    product_name = models.CharField(max_length=100)
    quantity = models.IntegerField()
    unit_cost = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        managed = False
        db_table = 'order_detail'


class Orders(models.Model):
    order_id = models.AutoField(primary_key=True)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_on = models.DateTimeField()
    shipped_on = models.DateTimeField(blank=True, null=True)
    status = models.IntegerField()
    comments = models.CharField(max_length=255, blank=True, null=True)
    customer_id = models.IntegerField(blank=True, null=True)
    auth_code = models.CharField(max_length=50, blank=True, null=True)
    reference = models.CharField(max_length=50, blank=True, null=True)
    shipping_id = models.IntegerField(blank=True, null=True)
    tax_id = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'orders'


class Product(models.Model):
    product_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=1000)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    discounted_price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.CharField(max_length=150, blank=True, null=True)
    image_2 = models.CharField(max_length=150, blank=True, null=True)
    thumbnail = models.CharField(max_length=150, blank=True, null=True)
    display = models.SmallIntegerField()

    class Meta:
        managed = False
        db_table = 'product'


class ProductAttribute(models.Model):
    product_id = models.IntegerField(primary_key=True)
    attribute_value_id = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'product_attribute'
        unique_together = (('product_id', 'attribute_value_id'),)


class ProductCategory(models.Model):
    product_id = models.IntegerField(primary_key=True)
    category_id = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'product_category'
        unique_together = (('product_id', 'category_id'),)


class Review(models.Model):
    review_id = models.AutoField(primary_key=True)
    customer_id = models.IntegerField()
    product_id = models.IntegerField()
    review = models.TextField()
    rating = models.SmallIntegerField()
    created_on = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'review'


class Shipping(models.Model):
    shipping_id = models.AutoField(primary_key=True)
    shipping_type = models.CharField(max_length=100)
    shipping_cost = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_region_id = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'shipping'


class ShippingRegion(models.Model):
    shipping_region_id = models.AutoField(primary_key=True)
    shipping_region = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'shipping_region'


class ShoppingCart(models.Model):
    item_id = models.AutoField(primary_key=True)
    cart_id = models.CharField(max_length=32)
    product_id = models.IntegerField()
    attributes = models.CharField(max_length=1000)
    quantity = models.IntegerField()
    buy_now = models.IntegerField()
    added_on = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'shopping_cart'


class Tax(models.Model):
    tax_id = models.AutoField(primary_key=True)
    tax_type = models.CharField(max_length=100)
    tax_percentage = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        managed = False
        db_table = 'tax'
