# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python import
from typing import Optional

from django.shortcuts import get_object_or_404

# Third party
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework import status

# Module import
from .base import BaseAPIView
from plane.db.models import APIToken
from plane.app.serializers import APITokenSerializer, APITokenReadSerializer
from plane.app.serializers.api import APITokenCreateSerializer


class ApiTokenEndpoint(BaseAPIView):
    def post(self, request: Request) -> Response:
        create = APITokenCreateSerializer(data=request.data)
        create.is_valid(raise_exception=True)
        api_token = create.save(user=request.user, user_type=1 if request.user.is_bot else 0)

        serializer = APITokenSerializer(api_token)
        # Token will be only visible while creating
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request: Request, pk: Optional[str] = None) -> Response:
        if pk is None:
            api_tokens = APIToken.objects.filter(user=request.user)
            serializer = APITokenReadSerializer(api_tokens, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            api_tokens = get_object_or_404(APIToken, user=request.user, pk=pk)
            serializer = APITokenReadSerializer(api_tokens)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request: Request, pk: str) -> Response:
        api_token = get_object_or_404(APIToken, user=request.user, pk=pk)
        api_token.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def patch(self, request: Request, pk: str) -> Response:
        api_token = get_object_or_404(APIToken, user=request.user, pk=pk)
        serializer = APITokenSerializer(api_token, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(APITokenReadSerializer(api_token).data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
