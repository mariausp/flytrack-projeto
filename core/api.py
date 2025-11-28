from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializers import (
    FlightSearchSerializer,
    FlightSearchResponseSerializer,
)

@api_view(['GET','POST'])
@permission_classes([IsAuthenticated])
def busca_voos(request):
    raw_data = request.data if request.method == 'POST' else request.query_params
    search_serializer = FlightSearchSerializer(data=raw_data)
    search_serializer.is_valid(raise_exception=True)
    params = search_serializer.validated_data

    origem = (params.get('origem') or '').strip()
    destino = (params.get('destino') or '').strip()
    viagem_data = params.get('data')
    pax = params.get('pax', 1)

    base = 4970
    origem_lower = origem.lower()
    destino_lower = destino.lower()
    if 'são paulo' in origem_lower or 'sao paulo' in origem_lower:
        base += 100
    if 'new' in destino_lower or 'nova' in destino_lower:
        base += 250

    fimsemana = viagem_data.weekday() >= 4 if viagem_data else False
    if fimsemana:
        base += 180

    total = base * pax
    mais_barato = max(base - 200, 3900)

    response_payload = {
        'ok': True,
        'recomendado': {
            'preco': total,
            'preco_fmt': f"R$ {total:,.0f}".replace(',', '.'),
            'descricao': 'Tarifa recomendada com 1 mala despachada',
        },
        'mais_barato': {
            'preco': mais_barato,
            'preco_fmt': f"R$ {mais_barato:,.0f}".replace(',', '.'),
            'descricao': 'Tarifa sem bagagem despachada',
        },
        'parametros': {
            'origem': origem,
            'destino': destino,
            'data': viagem_data.isoformat() if viagem_data else '',
            'pax': pax,
        }
    }

    response_serializer = FlightSearchResponseSerializer(data=response_payload)
    response_serializer.is_valid(raise_exception=True)
    return Response(response_serializer.data, status=status.HTTP_200_OK)
