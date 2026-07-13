from rest_framework import serializers
from providers.models import Provider


class ProviderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Provider
        fields = [
            "id",
            "name",
            "aws_account_id",
            "inventory_role_name",
            "active",
            "connection_verified",
            "last_connection_test",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["connection_verified", "last_connection_test", "created_at", "updated_at"]

    def validate_aws_account_id(self, value):
        if not value or len(value) != 12 or not value.isdigit():
            raise serializers.ValidationError("aws_account_id must be exactly 12 digits")
        return value
