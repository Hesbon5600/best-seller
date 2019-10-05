import logging
from django.utils import timezone
from django.contrib.auth.models import AnonymousUser
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework import status

from src.api import errors
from src.api.models import Category, Product, Review, ProductCategory, Department, Review
from src.api.serializers import ProductSerializer, ReviewSerializer, ReviewSerializer
from src.api.validators import validate_review_and_rating
logger = logging.getLogger(__name__)


class ProductSetPagination(PageNumberPagination):
    page_size = 20
    page_query_description = 'Inform the page. Starting with 1. Default: 1'
    page_size_query_param = 'limit'
    page_size_query_description = 'Limit per page, Default: 20.'
    max_page_size = 200

    def get_paginated_response(self, data):
        return Response(
            {
                "paginationMeta":   {
                    "currentPage": self.page.number,
                    "currentPageSize": len(data),
                    "totalPages": self.page.paginator.num_pages,
                    "totalRecords": self.page.paginator.count,
                },
                'rows': data
            }
        )


class ProductViewSet(viewsets.ReadOnlyModelViewSet):
    """
    list: Return a list of products
    retrieve: Return a product by ID.
    """
    queryset = Product.objects.all().order_by('product_id')
    serializer_class = ProductSerializer
    pagination_class = ProductSetPagination
    filter_backends = (SearchFilter,)
    search_fields = ('name', 'description')

    @action(methods=['GET'], detail=False, url_path='search', url_name='Search products')
    def search(self, request, *args, **kwargs):
        """        
        Search products
        """
        return super().list(request, *args, **kwargs)

    def get_products_by_category(self, request, category_id):
        """
        Get a list of Products by Categories
        """

        if not ProductCategory.objects.filter(category_id=category_id):
            return errors.handle(errors.CAT_01)
        product_ids = [cat.product_id for cat in ProductCategory.objects.filter(
            category_id=category_id).all()]
        data = self.serializer_class(Product.objects.filter(
            product_id__in=product_ids).all(), many=True).data
        return self.paginator.get_paginated_response(
            self.paginator.paginate_queryset(data, request))

    def get_products_by_department(self, request, department_id):
        """
        Get a list of Products of Departments
        """

        if not Category.objects.filter(department_id=department_id):
            return errors.handle(errors.DEP_02)
        product_ids = [ca.product_id for ca in ProductCategory.objects.filter
                       (category_id__in=[
                           category.category_id for category in Category.objects.filter(
                               department_id=department_id).all()]).all()]
        data = self.serializer_class(Product.objects.filter(
            product_id__in=product_ids).all().order_by('product_id'), many=True).data
        return self.paginator.get_paginated_response(
            self.paginator.paginate_queryset(data, request))

    @action(methods=['GET'], detail=True, url_path='details')
    def details(self, request, pk):
        """
        Get details of a Product
        """
        product = Product.objects.filter(product_id=pk)
        if not product:
            return errors.handle(errors.PRO_01)

        return Response(self.serializer_class(product).data, status=status.HTTP_200_OK)

    @action(methods=['GET'], detail=True, url_path='locations')
    def locations(self, request, pk):
        """
        Get locations of a Productr
        """
        product_category = ProductCategory.objects.get(product_id=pk)
        category = Category.objects.get(pk=product_category.category_id)

        department = Department.objects.filter(
            pk=category.department_id).all()
        data = []
        for each in department:
            data.append({
                'category_id': category.category_id,
                'category_name': category.name,
                'department_id': each.department_id,
                'department_name': each.name
            })
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['GET'], detail=True, url_path='reviews', url_name='List reviews')
    def reviews(self, request, pk):
        """Return a list of reviews
        Args:
            request (obj): request onject
            pk (int): product id
        Returns:
            list of the product's reviews
        """
        serializer_class = ReviewSerializer
        if not Product.objects.filter(product_id=pk):
            return errors.handle(errors.PRO_01)
        return Response(serializer_class(
            Review.objects.filter(product_id=pk).all(), many=True).data, status=status.HTTP_200_OK)

    @swagger_auto_schema(method='POST', request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'review': openapi.Schema(type=openapi.TYPE_STRING, description='Review Text of Product', required=['true']),
            'rating': openapi.Schema(type=openapi.TYPE_INTEGER, description='Rating of Product', required=['true']),
        }
    ))
    @action(methods=['POST'], detail=True, url_path='review', url_name='Create review')
    def review(self, request, pk):
        """ Create a new review
        Args:
            request (obj): request onject
            pk (int): product id
        Returns:
            The created product review
        """
        serializer_class = ReviewSerializer
        if isinstance(request.user, AnonymousUser):
            return errors.handle(errors.USR_10)
        if not Product.objects.filter(product_id=pk):
            return errors.handle(errors.PRO_01)
        data = request.data
        error = validate_review_and_rating(data)
        if error:
            return error
        data['product_id'] = pk
        data['created_on'] = timezone.now()
        data['customer_id'] = request.user.customer_id
        serializer = serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
