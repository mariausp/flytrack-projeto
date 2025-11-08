from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from datetime import datetime

@api_view(['GET','POST'])
@permission_classes([IsAuthenticated])
def busca_voos(request):
    if request.method == 'POST':
        origem  = request.data.get('origem','')
        destino = request.data.get('destino','')
        data    = request.data.get('data','')
        pax     = int(request.data.get('pax', 1))
    else:
        origem  = request.GET.get('origem','')
        destino = request.GET.get('destino','')
        data    = request.GET.get('data','')
        pax     = int(request.GET.get('pax', 1))

    base = 4970
    if 'São Paulo' in origem: base += 100
    if 'New' in destino or 'Nova' in destino: base += 250
    try:
        dt = datetime.fromisoformat(data); fimsemana = dt.weekday() >= 4
    except Exception:
        fimsemana = False
    if fimsemana: base += 180
    total = base * max(pax,1)

    return Response({
        'ok': True,
        'recomendado': {
            'preco': total,
            'preco_fmt': f"R$ {total:,.0f}".replace(',', '.'),
            'descricao': 'Tarifa recomendada com 1 mala despachada',
        },
        'mais_barato': {
            'preco': max(base-200, 3900),
            'preco_fmt': f"R$ {max(base-200, 3900):,.0f}".replace(',', '.'),
        },
        'parametros': {'origem': origem, 'destino': destino, 'data': data, 'pax': pax}
    })
