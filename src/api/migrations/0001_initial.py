# Generated by Django 2.2.2 on 2019-09-30 13:32

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Attribute',
            fields=[
                ('attribute_id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'attribute',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='AttributeValue',
            fields=[
                ('attribute_value_id', models.AutoField(primary_key=True, serialize=False)),
                ('attribute_id', models.IntegerField()),
                ('value', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'attribute_value',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Audit',
            fields=[
                ('audit_id', models.AutoField(primary_key=True, serialize=False)),
                ('order_id', models.IntegerField()),
                ('created_on', models.DateTimeField()),
                ('message', models.TextField()),
                ('code', models.IntegerField()),
            ],
            options={
                'db_table': 'audit',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Category',
            fields=[
                ('category_id', models.AutoField(primary_key=True, serialize=False)),
                ('department_id', models.IntegerField()),
                ('name', models.CharField(max_length=100)),
                ('description', models.CharField(blank=True, max_length=1000, null=True)),
            ],
            options={
                'db_table': 'category',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Customer',
            fields=[
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('customer_id', models.AutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=50)),
                ('email', models.CharField(max_length=100, unique=True)),
                ('password', models.CharField(max_length=100)),
                ('credit_card', models.TextField(blank=True, null=True)),
                ('address_1', models.CharField(blank=True, max_length=100, null=True)),
                ('address_2', models.CharField(blank=True, max_length=100, null=True)),
                ('city', models.CharField(blank=True, max_length=100, null=True)),
                ('region', models.CharField(blank=True, max_length=100, null=True)),
                ('postal_code', models.CharField(blank=True, max_length=100, null=True)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('shipping_region_id', models.IntegerField()),
                ('day_phone', models.CharField(blank=True, max_length=100, null=True)),
                ('eve_phone', models.CharField(blank=True, max_length=100, null=True)),
                ('mob_phone', models.CharField(blank=True, max_length=100, null=True)),
            ],
            options={
                'db_table': 'customer',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Department',
            fields=[
                ('department_id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('description', models.CharField(blank=True, max_length=1000, null=True)),
            ],
            options={
                'db_table': 'department',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='OrderDetail',
            fields=[
                ('item_id', models.AutoField(primary_key=True, serialize=False)),
                ('order_id', models.IntegerField()),
                ('product_id', models.IntegerField()),
                ('attributes', models.CharField(max_length=1000)),
                ('product_name', models.CharField(max_length=100)),
                ('quantity', models.IntegerField()),
                ('unit_cost', models.DecimalField(decimal_places=2, max_digits=10)),
            ],
            options={
                'db_table': 'order_detail',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Orders',
            fields=[
                ('order_id', models.AutoField(primary_key=True, serialize=False)),
                ('total_amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('created_on', models.DateTimeField()),
                ('shipped_on', models.DateTimeField(blank=True, null=True)),
                ('status', models.IntegerField()),
                ('comments', models.CharField(blank=True, max_length=255, null=True)),
                ('customer_id', models.IntegerField(blank=True, null=True)),
                ('auth_code', models.CharField(blank=True, max_length=50, null=True)),
                ('reference', models.CharField(blank=True, max_length=50, null=True)),
                ('shipping_id', models.IntegerField(blank=True, null=True)),
                ('tax_id', models.IntegerField(blank=True, null=True)),
            ],
            options={
                'db_table': 'orders',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Product',
            fields=[
                ('product_id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('description', models.CharField(max_length=1000)),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('discounted_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('image', models.CharField(blank=True, max_length=150, null=True)),
                ('image_2', models.CharField(blank=True, max_length=150, null=True)),
                ('thumbnail', models.CharField(blank=True, max_length=150, null=True)),
                ('display', models.SmallIntegerField()),
            ],
            options={
                'db_table': 'product',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='ProductAttribute',
            fields=[
                ('product_id', models.IntegerField(primary_key=True, serialize=False)),
                ('attribute_value_id', models.IntegerField()),
            ],
            options={
                'db_table': 'product_attribute',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='ProductCategory',
            fields=[
                ('product_id', models.IntegerField(primary_key=True, serialize=False)),
                ('category_id', models.IntegerField()),
            ],
            options={
                'db_table': 'product_category',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Review',
            fields=[
                ('review_id', models.AutoField(primary_key=True, serialize=False)),
                ('customer_id', models.IntegerField()),
                ('product_id', models.IntegerField()),
                ('review', models.TextField()),
                ('rating', models.SmallIntegerField()),
                ('created_on', models.DateTimeField()),
            ],
            options={
                'db_table': 'review',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Shipping',
            fields=[
                ('shipping_id', models.AutoField(primary_key=True, serialize=False)),
                ('shipping_type', models.CharField(max_length=100)),
                ('shipping_cost', models.DecimalField(decimal_places=2, max_digits=10)),
                ('shipping_region_id', models.IntegerField()),
            ],
            options={
                'db_table': 'shipping',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='ShippingRegion',
            fields=[
                ('shipping_region_id', models.AutoField(primary_key=True, serialize=False)),
                ('shipping_region', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'shipping_region',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='ShoppingCart',
            fields=[
                ('item_id', models.AutoField(primary_key=True, serialize=False)),
                ('cart_id', models.CharField(max_length=32)),
                ('product_id', models.IntegerField()),
                ('attributes', models.CharField(max_length=1000)),
                ('quantity', models.IntegerField()),
                ('buy_now', models.IntegerField()),
                ('added_on', models.DateTimeField()),
            ],
            options={
                'db_table': 'shopping_cart',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='Tax',
            fields=[
                ('tax_id', models.AutoField(primary_key=True, serialize=False)),
                ('tax_type', models.CharField(max_length=100)),
                ('tax_percentage', models.DecimalField(decimal_places=2, max_digits=10)),
            ],
            options={
                'db_table': 'tax',
                'managed': False,
            },
        ),
    ]
