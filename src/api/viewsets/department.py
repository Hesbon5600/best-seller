from rest_framework import viewsets

from src.api.models import Department
from src.api.serializers import DepartmentSerializer
import logging

logger = logging.getLogger(__name__)


class DepartmentViewSet(viewsets.ReadOnlyModelViewSet):
    """
    list: Return a list of departments
    retrieve: Return a department by ID.
    """
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
