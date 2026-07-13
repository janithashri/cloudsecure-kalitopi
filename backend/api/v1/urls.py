from django.urls import path
from api.v1.views import (
    AttackEngineQueryCatalogView,
    AttackEngineRunAllView,
    AttackEngineSingleQueryView,
    CartographyGraphView,
    GraphDataView,
    InventorySummaryView,
    LoginView,
    LogoutView,
    MeView,
    RegisterView,
)

urlpatterns = [
    path("login/", LoginView.as_view(), name="auth-login"),
    path("register/", RegisterView.as_view(), name="auth-register"),
    path("logout/", LogoutView.as_view(), name="auth-logout"),
    path("me/", MeView.as_view(), name="auth-me"),
    path(
        "providers/<int:provider_id>/inventory-summary/",
        InventorySummaryView.as_view(),
        name="inventory-summary",
    ),
    path(
        "providers/<int:provider_id>/graph/",
        GraphDataView.as_view(),
        name="inventory-graph",
    ),
    path(
        "providers/<int:provider_id>/graph/cartography/",
        CartographyGraphView.as_view(),
        name="cartography-graph",
    ),
    path(
        "providers/<int:provider_id>/attack-engine/run/",
        AttackEngineRunAllView.as_view(),
        name="attack-engine-run",
    ),
    path(
        "providers/<int:provider_id>/attack-engine/query/<str:query_id>/",
        AttackEngineSingleQueryView.as_view(),
        name="attack-engine-single",
    ),
    path(
        "attack-engine/queries/",
        AttackEngineQueryCatalogView.as_view(),
        name="attack-engine-catalog",
    ),
]
