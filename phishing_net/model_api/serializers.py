from rest_framework.serializers import ModelSerializer
from .models import MSGS

class SMSSerializer(ModelSerializer):
    class Meta:
        model = MSGS
        fields = '__all__'