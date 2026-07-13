from django.urls import path

from api.routes.deep_scan import DeepScanDetailView, DeepScanListView

urlpatterns = [
    path("deep-scan/", DeepScanListView.as_view(), name="deep-scan-list"),
    path("deep-scan/<str:scan_id>/", DeepScanDetailView.as_view(), name="deep-scan-detail"),
]
