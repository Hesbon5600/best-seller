from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from src.api import errors
from src.api.models import (Attribute, AttributeValue,
                            Product, ProductAttribute, AttributeValue)
from src.api.serializers import (AttributeSerializer,
                                 AttributeValueSerializer,
                                 AttributeValueSerializer)
import logging

logger = logging.getLogger(__name__)


class AttributeViewSet(viewsets.ReadOnlyModelViewSet):
    """
    list: Return a list of attributes
    retrieve: Return a attribute by ID.
    """
    queryset = Attribute.objects.all()
    serializer_class = AttributeSerializer

    @action(detail=False, url_path='values/<int:attribute_id>')
    def get_values_from_attribute(self, request, *args, **kwargs):
        """
        Get Values Attribute from Attribute ID
        """
        serializer_class = AttributeValueSerializer
        attribute_id = kwargs.get('attribute_id', '')
        if not Attribute.objects.filter(attribute_id=attribute_id):
            return errors.handle(errors.ATT_01)
        attribute_value = AttributeValue.objects.filter(
            attribute_id=attribute_id).all()
        data = serializer_class(attribute_value, many=True).data
        return Response(data, status=200)

    @action(detail=False, url_path='inProduct/<int:product_id>')
    def get_attributes_from_product(self, request, *args, **kwargs):
        """
        Get all Attributes with Product ID
        """
        product_id = kwargs.get('product_id', '')
        if not Product.objects.filter(product_id=product_id):
            return errors.handle(errors.PRO_01)
        attribute_value_ids = [
            prod_attr_val.attribute_value_id for prod_attr_val in ProductAttribute.objects.filter(
                product_id=product_id).all()]
        attribute_ids = [
            prod_attr.attribute_id for prod_attr in AttributeValue.objects.filter(
                attribute_value_id__in=attribute_value_ids).all()]
        data = self.serializer_class(Attribute.objects.filter(
            attribute_id__in=attribute_ids).all(), many=True).data
        return Response(data, status=200)
